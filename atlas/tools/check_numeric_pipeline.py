"""D40 B 1.11 numeric audit; original CPU routines, never a camera emulator.

The tone builder is executed without hooks. Inputs are synthetic RAM; explicitly
labelled fault-injection cases overlay correction DATA, never executable code.
Matrix output ranges below are mathematical predictions under stated Q9/Q8
assumptions, not measured ASIC behavior.
"""
import hashlib
import itertools
import json
import math
import random
import struct
import sys
from collections import Counter
from pathlib import Path
from fr_color_machine import ColorMachine, EXPECTED, signed
from color_tables import matrices

CTX, OUT, MAIN, ALT, CORR, STRIDE = (0x20000000, 0x83EB586C, 0x83E89310,
                                  0x83E882CC, 0x33692E, 0x83CE8344)


def words(blob, address, n):
    return list(struct.unpack_from('>'+str(n)+'H', blob, address-0x40000))


def clamp(v):
    return min(4095, max(0, v))


def interpolate(samples):
    result = []
    for a, b in zip(samples, samples[1:]):
        result += [a, (a+b)//2]
    return result + [samples[-1], samples[-1]]


def packed_tone(blob, index):
    if 0 <= index < 21:
        start, s0, s1 = 0x34BC56, 0x34BC41, 0x34BC2C
        k = index
    elif 47 <= index < 54:
        start, s0, s1 = 0x348433, 0x34842C, 0x348425
        k = index-47
    else:
        raise ValueError('Only records delimited by the observed seed arrays')
    out = [blob[s0+k-0x40000], blob[s1+k-0x40000]]
    for byte in blob[start+2047*k-0x40000:start+2047*(k+1)-0x40000]:
        for nibble in (byte>>4, byte&15):
            out.append((2*out[-1]-out[-2]+nibble-8) & 65535)
    assert len(out) == 4096
    return out


def new_machine(blob, samples, alternate=False, headers=(1,1), correction=None):
    m = ColorMachine(blob)
    m.map(CTX, bytes(0x1800))
    m.map(OUT-16, bytes([0xA5])*(8192+32))
    m.map(STRIDE, bytes([9]))
    m.map(ALT, bytes(0x1044))
    m.map(MAIN, bytes(0x1044))
    m.store(CTX+0x466, 0x17, 1)
    m.store(CTX+0x5A, 0 if alternate else 0x40, 1)
    m.store(CTX+0x2D, 0x18 if alternate else 0, 1)
    m.store(CTX+0x6AE, 4, 1)
    ptr = ALT if alternate else MAIN
    m.store(ptr, headers[0], 1); m.store(ptr+1, headers[1], 1)
    for i, value in enumerate(samples):
        m.store(ptr+0x44+2*i, value, 2)
    if correction is not None:
        assert len(correction) == 4096
        data = bytearray(4096*9)
        for i, value in enumerate(correction): data[9*i+4] = value & 255
        m.map(CORR, data)
    return m


def describe(values):
    return {'minimum':min(values), 'maximum':max(values),
            'first_8':values[:8], 'last_8':values[-8:],
            'zero_count':values.count(0), 'white_4095_count':values.count(4095),
            'first_4095_index':next((i for i,v in enumerate(values) if v==4095), None),
            'descending_steps':sum(b<a for a,b in zip(values, values[1:]))}


def check_tones(blob):
    assert blob[CORR-0x40000:CORR-0x40000+36864] == bytes(36864)
    samples = {
        'default_rom': words(blob,0xDC294,2048),
        'ascending_12bit': [2*i for i in range(2048)],
        'descending_12bit': [4095-2*i for i in range(2048)],
        'alternating_0_4095': [0,4095]*1024,
        'constant_white': [4095]*2048,
        'constant_zero': [0]*2048,
        'malformed_u16': ([0,1,4094,4095,4096,8191,32768,65535]*256),
    }
    records=[]
    for alternate in (False,True):
        for name, curve in samples.items():
            m = new_machine(blob,curve,alternate)
            steps=m.run(0x323C22,CTX,budget=350000)
            expected=[clamp(v) for v in interpolate(curve)]
            actual=[m.load(OUT+2*i,2) for i in range(4096)]
            assert actual==expected, (alternate,name)
            assert m.regs[4]==OUT and m.regs[15]==0x10001000
            assert m.load(OUT-8,8)==m.load(OUT+8192,8)==0xA5A5A5A5A5A5A5A5
            records.append({'path':'alternate' if alternate else 'main','case':name,
                            'instructions':steps,'output':describe(actual)})
    for alternate in (False,True):
        for headers in ((0,0),(1,0),(0,1)):
            m=new_machine(blob,[65535]*2048,alternate,headers)
            steps=m.run(0x323C22,CTX,budget=350000)
            expected=interpolate(words(blob,0xDB250 if alternate else 0xDC294,2048))
            assert [m.load(OUT+2*i,2) for i in range(4096)]==[clamp(v) for v in expected]
            records.append({'path':'alternate' if alternate else 'main','case':'fallback',
                            'headers':headers,'instructions':steps})
    # Deliberate data fault injection to execute both clamp edges, including
    # averaging BEFORE correction/clamp. Original correction table is all zero.
    corr=([-128,-1,0,1,127,0,1,-1]*512)
    for alternate in (False,True):
        curve=samples['malformed_u16']
        m=new_machine(blob,curve,alternate,correction=corr)
        steps=m.run(0x323C22,CTX,budget=350000)
        expected=[clamp(v+c) for v,c in zip(interpolate(curve),corr)]
        assert [m.load(OUT+2*i,2) for i in range(4096)]==expected
        records.append({'path':'alternate' if alternate else 'main',
                        'case':'synthetic_signed_correction_DATA_overlay',
                        'instructions':steps,'output':describe(expected)})
    stock=[]
    for index in list(range(21))+list(range(47,54)):
        m=new_machine(blob,[0]*2048)
        m.store(CTX+0x466,index,1)
        steps=m.run(0x323C22,CTX,budget=400000)
        raw=packed_tone(blob,index)
        expected=[clamp(v) for v in raw]
        assert [m.load(OUT+2*i,2) for i in range(4096)]==expected,index
        assert m.regs[4]==OUT and m.regs[15]==0x10001000
        assert m.load(OUT-8,8)==m.load(OUT+8192,8)==0xA5A5A5A5A5A5A5A5
        stock.append({'selector':index,'instructions':steps,'output':describe(expected),
                      'decoded_outside_12bit':sum(v>4095 for v in raw)})
    return {'custom_and_fallback_cases':records, 'stock_records':stock,
            'stock_index_scope':'21+7 records from seed spacing; runtime reachability not proved',
            'direct_byte_curve_ctx_1d_bit_20_path_tested':False,
            'original_cpu_executions':len(records)+len(stock),
            'full_output_entries_compared':4096*(len(records)+len(stock))}


def check_static(blob):
    sqrt=words(blob,0xC860C,4096); square=words(blob,0xC660C,4096)
    scale=words(blob,0xCA60C,256)
    # Entire verification uses exact integer arithmetic, including sqrt ties.
    root=[]
    for i in range(4096):
        n=4096*i; k=math.isqrt(n)
        root.append(min(4095,k+(4*n >= (2*k+1)**2)))
    assert sqrt==root
    assert square==[(i*i+2048)//4096 for i in range(4096)]
    assert scale==[(2*i*4095+255)//510 for i in range(256)]
    compositions={}
    for name, vals in [('square_of_sqrt',[square[sqrt[i]] for i in range(4096)]),
                       ('sqrt_of_square',[sqrt[square[i]] for i in range(4096)])]:
        errors=[v-i for i,v in enumerate(vals)]
        compositions[name]={'minimum_error':min(errors),'maximum_error':max(errors),
                            'exact_count':errors.count(0),'error_histogram':dict(sorted(Counter(errors).items()))}
    return {'entries_checked':8448,
            'sqrt':describe(sqrt),'square':describe(square),'rescale':describe(scale),
            'square_half_tie_indices':[i for i in range(4096) if i*i%4096==2048],
            'hypothetical_direct_compositions_NOT_actual_pixel_path':compositions}


def matrix_audit(blob):
    result={}
    for name,rom,count,scale,sign in [('M1',0x332888,18,512,1024),('M2',0x33270E,21,256,512)]:
        mats=matrices(blob,rom,count)
        bounds=[]
        for index,mat in enumerate(mats):
            row_bounds=[]
            for row in range(3):
                values=mat[3*row:3*row+3]
                lo=4095*sum(v for v in values if v<0)
                hi=4095*sum(v for v in values if v>0)
                row_bounds.append({'accumulator_min':lo,'accumulator_max':hi,
                                   'after_ASSUMED_divisor_min':lo/scale,
                                   'after_ASSUMED_divisor_max':hi/scale})
            bounds.append({'profile':index,'rows':row_bounds})
        result[name]={'coefficient_min':min(v for mat in mats for v in mat),
                      'coefficient_max':max(v for mat in mats for v in mat),
                      'row_sums':sorted(set(tuple(sum(mat[3*i:3*i+3]) for i in range(3)) for mat in mats)),
                      'inferred_fixed_point_divisor_NOT_verified':scale,
                      'serialization_sign_bit':hex(sign),
                      'mathematical_input_cube_0_4095_bounds_NOT_ASIC_measurement':bounds}
    # Out-of-range values expose that the CPU serializer does not saturate
    # coefficients to the inferred sign/magnitude payload width.
    records=[]
    for a,b in [(1023,511),(1024,512),(-1023,-511),(-1024,-512),(65536,65536),(-65536,-65536)]:
        m=ColorMachine(blob);m.map(0x83EB3000,bytes(0x6000));m.map(CTX,bytes(0x800))
        m.store(0x83EB5864,CTX,4)
        for i in range(9):m.store(0x83EB3BE0+4*i,a,4);m.store(0x83EB3BBC+4*i,b,4)
        m.regs[8]=0x83EB5864;m.regs[14]=0x10001000;m.regs[15]=0x10000FF0
        m.run(0x323562,stop=0x3235E4)
        ea=(a if a>=0 else (abs(a)&65535)|1024)&65535
        eb=(b if b>=0 else (abs(b)&65535)|512)&65535
        assert all(m.load(CTX+0x3A4+2*i,2)==ea for i in range(9))
        assert all(m.load(CTX+0x3B6+2*i,2)==eb for i in range(9))
        records.append({'M1_input':a,'M1_packed':hex(ea),'M2_input':b,'M2_packed':hex(eb)})
    result['serializer_boundary_executions']=records
    result['ASIC_rounding_clipping_and_accumulator_width']='unknown'
    return result


def check_new_instructions(blob):
    m=ColorMachine(blob);code=0x21000000;data=0x21000100
    m.map(code,bytes(4));m.map(data,bytes(1));m.regs[3]=data
    cases=0
    for mask,byte,en,ez in [(2,0x20,False,False),(2,0,False,True),(8,0x80,True,False),(1,0x80,False,True)]:
        for v,c in itertools.product((False,True),repeat=2):
            m.store(code,0x8903+(mask<<4),2);m.store(code+2,0x9720,2);m.store(data,byte,1)
            m.n,m.z,m.v,m.c=True,False,v,c
            m.run(code)
            assert (m.n,m.z,m.v,m.c)==(en,ez,v,c)
            cases+=1
    for shift, value, expected, carry in [(0,0x80000000,0x80000000,False),
        (1,3,1,True),(31,0x80000000,1,False),(32,0xFFFFFFFF,0xFFFFFFFF,False),
        (33,0xFFFFFFFF,0x7FFFFFFF,True)]:
        m.store(code,0xB212,2);m.store(code+2,0x9720,2)
        m.regs[1],m.regs[2]=shift,value;m.v=True
        m.run(code)
        assert m.regs[2]==expected and m.c==carry and m.v
        assert m.n==bool(expected&0x80000000) and m.z==(expected==0)
        cases+=1
    return cases


def check_float_truncation(blob):
    # Original firmware helper, no host arithmetic hooks. Host float32 packing
    # only constructs IEEE input words; the expected integer uses Python int.
    rng=random.Random(2383)
    vals=[0.0,-0.0,0.5,-0.5,1.5,-1.5,1.9,-1.9,511.99,-511.99,
          512.5,-512.5,1023.99,-1023.99,2147483520.0,-2147483648.0,
          2147483648.0,-4294967296.0]
    vals += [rng.uniform(-2048,2048) for _ in range(2048)]
    m=ColorMachine(blob); examples=[]
    for i,v in enumerate(vals):
        encoded=struct.pack('>f',v)
        fv=struct.unpack('>f',encoded)[0]
        expected=min(2147483647,max(-2147483648,int(fv)))
        m.run(0xBE8DE,int.from_bytes(encoded,'big'),budget=100)
        actual=signed(m.regs[4]);assert actual==expected,(fv,actual,expected)
        if i<18:examples.append({'float32':fv,'integer':actual})
    return {'original_routine':'0xBE8DE','finite_cases':len(vals),
            'observed_rule':'truncate toward zero, saturate signed32 on finite overflow',
            'examples':examples,'NaN_and_infinity_tested':False,
            'ASIC_pixel_rounding_inferred_from_this':False}


if __name__=='__main__':
    blob=Path(sys.argv[1]).read_bytes()
    assert hashlib.sha256(blob).hexdigest()==EXPECTED
    result={'firmware_sha256':EXPECTED,'result':'PASS','camera_connected':False,
            'firmware_modified':False,'ASIC_pixel_arithmetic_emulated':False,
            'new_instruction_checks':check_new_instructions(blob),
            'float_to_integer':check_float_truncation(blob),
            'static_luts':check_static(blob),'tone_builder':check_tones(blob),
            'matrices':matrix_audit(blob)}
    Path(sys.argv[2]).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'result':result['result'],
                      'tone_executions':result['tone_builder']['original_cpu_executions'],
                      'tone_entries':result['tone_builder']['full_output_entries_compared'],
                      'static_lut_entries':result['static_luts']['entries_checked']}))
