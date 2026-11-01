"""Read-only D40 B 1.11 hardware-table analysis and bounded CPU checks.

No pixel engine, DMA, sensor, interrupts, or camera are emulated. The MMIO
addresses below are ordinary synthetic memory during the CPU checks.
Usage: python extract_v4.py BD400111.bin OUTPUT [upstream_jstdhuff.c]
"""
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path
from atlas import require_b
from extract_v2 import save_json, save_csv
from fr_decode import listing
from fr_color_machine import ColorMachine


STATIC = [
    ('rescale_8_to_12', 0xca60c, 256, [0x40010200],
     'floor(i*4095/255+0.5)', lambda i: (2*i*4095+255)//510),
    ('square_root', 0xc860c, 4096, [0x40010400],
     'min(4095,floor(sqrt(4096*i)+0.5))',
     lambda i: min(4095, math.floor(math.sqrt(4096*i)+0.5))),
    ('square', 0xc660c, 4096, [0x40012400, 0x40014400, 0x40016400],
     'floor(i*i/4096+0.5)', lambda i: (i*i+2048)//4096),
]
SMALL = [
    # name, function, output RAM, hardware, packed ROM, y0, y1, bytes, bits, context
    ('E600',0x324020,0x83eb7ffc,0x4001e600,0x3472fc,0x3472f2,0x3472e8,127,4,0x467),
    ('E800',0x3240a2,0x83eb7df8,0x4001e800,0x346a37,0x346a2d,0x346a23,127,4,0x469),
    ('EA00',0x324062,0x83eb7efa,0x4001ea00,0x34650f,0x346505,0x3464fb,64,2,0x468),
    ('FC00',0x3240e4,0x83eb7cf6,0x4001fc00,0x3467a3,0x346799,0x34678f,64,2,0x46a),
]
GEOMETRY = [0xc656c] + list(range(0xc657c,0xc660c,16))
RANGES = [
    ('B_pixel_frame_driver',0x4b260,0x4b41c),
    ('B_pixel_complete_configuration',0x4b41c,0x4b6a0),
    ('B_pixel_static_luts',0x4be82,0x4bf06),
    ('B_pixel_completion_interrupt',0x47874,0x478aa),
    ('B_pixel_process_callers',0x4ae0e,0x4af0c),
    ('B_pixel_resize_callers_and_jpeg_handoff',0x485ec,0x48900),
    ('B_pixel_scaler_setup',0x494f2,0x4966c),
    ('B_pixel_jpeg_setup',0x49a7c,0x49bc0),
    ('B_pixel_jpeg_huffman_setup',0x49f74,0x4a066),
    ('B_pixel_small_lut_expanders',0x324020,0x324124),
    ('B_pixel_sharpening_lut_selectors',0x3229ca,0x322d34),
    ('B_pixel_scene_inputs',0x31b6d2,0x31b77c),
    ('B_pixel_sharpening_setting_decode',0x31ef16,0x31ef26),
    ('B_pixel_signed_division_helper',0xbe78c,0xbe7da),
]


def digest(b):
    return hashlib.sha256(b).hexdigest()


def words(blob, address, count):
    return list(struct.unpack_from('>'+str(count)+'H',blob,address-0x40000))


def expand_small(blob, spec, index):
    _,_,_,_,rom,y0,y1,length,bits,_ = spec
    result = [blob[y0-0x40000+index],blob[y1-0x40000+index]]
    offset = rom-0x40000+length*index
    for byte in blob[offset:offset+length]:
        for shift in range(8-bits,-1,-bits):
            delta = ((byte>>shift)&((1<<bits)-1))-(1<<(bits-1))
            result.append((2*result[-1]-result[-2]+delta)&255)
    return result


def machine(blob):
    m = ColorMachine(blob)
    m.map(0x83eb3000,bytes(0x6000))
    m.map(0x40010000,bytes([0xa5])*0x10000)
    return m


def compare_huffman(blob, source):
    text = re.sub(r'/\*.*?\*/','',source.read_text(),flags=re.S)
    results=[]
    for rom,suffix in [(0xc642e,'luminance'),(0xc6360,'chrominance')]:
        values=[]
        for prefix in ['bits_dc_','val_dc_','bits_ac_','val_ac_']:
            match=re.search(prefix+suffix+r'\s*\[.*?\]\s*=\s*\{(.*?)\}',text,re.S)
            if not match: raise ValueError('Expected upstream C array absent')
            array=[int(s,0) for s in re.findall(r'0x[0-9a-fA-F]+|\d+',match[1])]
            values.extend(array[1:] if prefix.startswith('bits') else array)
        assert len(values)==206
        actual=blob[rom-0x40000:rom-0x40000+206]
        assert actual==bytes(values), suffix
        results.append(dict(component=suffix,rom=hex(rom),bytes=206,
                            sha256=digest(actual),match=True))
    return dict(source_url='https://raw.githubusercontent.com/libjpeg-turbo/libjpeg-turbo/main/src/jstdhuff.c',
                source_sha256=digest(source.read_bytes()),tables=results)


def extract(path, out, huffman_source=None):
    blob=require_b(path)
    data,evidence=out/'data',out/'evidence'
    data.mkdir(parents=True,exist_ok=True); evidence.mkdir(parents=True,exist_ok=True)
    checks=dict(firmware_sha256=digest(blob),camera_connected=False,firmware_modified=False,
                hardware_emulated=False,date='2026-10-28')
    static_rows, static_stats=[],[]
    for name,rom,n,banks,formula,fn in STATIC:
        values=words(blob,rom,n)
        assert values==[fn(i) for i in range(n)],name
        static_rows.extend(dict(table=name,index=i,value=v) for i,v in enumerate(values))
        static_stats.append(dict(name=name,rom=hex(rom),entries=n,
                                 hardware=[hex(a) for a in banks],formula=formula,
                                 all_entries_match=True,sha256=digest(struct.pack('>'+str(n)+'H',*values))))
    save_csv(data/'hardware_static_luts.csv',static_rows)
    save_json(data/'hardware_static_lut_formulas.json',static_stats)
    checks['formula_entries_checked']=sum(s[2] for s in STATIC)
    m=machine(blob)
    steps=m.run(0x4be82,budget=200000)
    for _,rom,n,banks,_,_ in STATIC:
        for bank in banks:
            assert [m.load(bank+2*i,2) for i in range(n)]==words(blob,rom,n)
    assert m.regs[15]==0x10001000
    assert m.load(0x400101fe,2)==m.load(0x40018400,2)==0xa5a5
    checks['original_static_initializer']={'executions':1,'instructions':steps,
                                         'halfword_copies_checked':256+4*4096}
    small_rows,small_stats=[],[]
    for spec in SMALL:
        name,pc,ram,hw,rom,y0,y1,length,bits,ctx=spec
        for index in range(10):
            expected=expand_small(blob,spec,index)
            m=machine(blob)
            m.store(ram-8,0xa5a5a5a5a5a5a5a5,8)
            m.store(ram+len(expected),0xa5a5a5a5a5a5a5a5,8)
            m.run(pc,index)
            actual=[m.load(ram+i,1) for i in range(len(expected))]
            assert actual==expected,(name,index)
            assert m.regs[4]==ram and m.regs[15]==0x10001000
            assert m.load(ram-8,8)==m.load(ram+len(expected),8)==0xa5a5a5a5a5a5a5a5
            # Execute the original byte-to-halfword upload helper too.
            m.regs[5],m.regs[6]=hw,256
            m.run(0x4bee6,ram)
            assert [m.load(hw+2*i,2) for i in range(256)]==expected[:256]
            assert m.load(hw+512,2)==0xa5a5
            small_rows.extend(dict(bank=name,profile=index,index=i,value=v,hardware_copied=i<256)
                              for i,v in enumerate(expected))
            small_stats.append(dict(bank=name,profile=index,hardware=hex(hw),context_offset=hex(ctx),
                                    generated=len(expected),hardware_copied=256,
                                    minimum=min(expected[:256]),maximum=max(expected[:256]),
                                    decreasing_steps=sum(a>b for a,b in zip(expected[:255],expected[1:256])),
                                    sha256=digest(bytes(expected))))
    save_csv(data/'hardware_small_luts.csv',small_rows)
    save_json(data/'hardware_small_lut_stats.json',small_stats)
    checks['small_original_expander_executions']=40
    checks['small_original_upload_executions']=40
    aux=words(blob,0x331e0e,18*64)
    assert aux==([256]*16+[0]*32+[256]*16)*18
    checks['auxiliary_18_profiles_all_identity_pattern']=True
    geometries=[]
    for rom in GEOMETRY:
        vals=struct.unpack_from('>I6H',blob,rom-0x40000)
        record=dict(rom=hex(rom),source_offset=hex(vals[0]),field_04=vals[1],field_06=vals[2],
                    field_08=vals[3],field_0a=vals[4],field_0c=hex(vals[5]),field_0e=vals[6])
        geometries.append(record)
        # Middle fragment only: table already selected; CPU setup, not DMA.
        m=machine(blob); ctx,desc=0x20000000,0x20001000
        m.map(ctx,bytes(0x800));m.map(desc,bytes(0x80))
        m.store(ctx+0x14,0x81000000,4)
        m.regs[5],m.regs[8],m.regs[9]=desc,0x40010000,rom
        m.run(0x4b32a,ctx,stop=0x4b372)
        for addr,value,size in [(0x4001ff08,0x81000000+vals[0],4),
                                (0x4001ff04,vals[1],2),(0x4001ff06,vals[2],2),
                                (0x40010002,vals[3],2),(0x40010004,vals[4],2),
                                (desc+0x1a,vals[3],2),(desc+0x1c,vals[4],2)]:
            assert m.load(addr,size)==value,(record,hex(addr))
        # Start configuration fragment; stop before waiting on an OS event.
        m.run(0x4b3aa,stop=0x4b3d6)
        assert m.load(0x4001ff18,2)==0x100 and m.load(0x4001ff00,2)==0x4000
        assert m.load(0x40010000,2)==((vals[5]&~0x300)|0x100)
    save_csv(data/'hardware_geometry_records.csv',geometries)
    checks['geometry_write_fragments']=len(GEOMETRY)
    checks['start_write_fragments_no_OS_or_hardware']=len(GEOMETRY)
    # Three plane pointers before the first bit-test instruction.
    m=machine(blob);desc=0x20001000;m.map(desc,bytes(0x80));m.store(desc+12,0x82000000,4)
    m.regs[5]=desc;m.run(0x4b260,0x20000000,stop=0x4b2a0)
    for addr,offset in [(0x4001ff0c,0x2f90),(0x4001ff10,0x5cf590),(0x4001ff14,0x8b5890)]:
        assert m.load(addr,4)==0x82000000+offset
    checks['plane_address_fragment']=1
    # JPEG register handoff: synthetic caller frame, prologue not executed.
    m=machine(blob);m.map(0x40030000,bytes(0x1000));fp=0x10001000
    m.regs[14],m.regs[8],m.regs[10],m.regs[9]=fp,0x40030000,3008,2000
    for delta,value in [(24,3040),(28,0x82002f90),(32,0x825cf590),(36,0x828b5890),(40,0x83000000)]:
        m.store(fp+delta,value,4)
    m.run(0x49ad4,stop=0x49b12)
    for addr,value,size in [(0x40030f02,3040,2),(0x40030f08,1520,2),
                            (0x40030f04,3008,2),(0x40030f06,2000,2),
                            (0x40030f10,0x82002f90,4),(0x40030f14,0x825cf590,4),
                            (0x40030f18,0x828b5890,4),(0x40030f28,0x83000000,4)]:
        assert m.load(addr,size)==value
    checks['jpeg_register_handoff_fragment']=1
    if huffman_source:
        save_json(data/'jpeg_huffman_identification.json',compare_huffman(blob,huffman_source))
        checks['external_standard_huffman_bytes_compared']=412
    else:
        checks['external_standard_huffman_bytes_compared']='NOT RUN: supply upstream jstdhuff.c'
    records=[]
    for name,start,end in RANGES:
        lines=list(listing(blob,start-0x40000,end-0x40000))
        if any('TRUNCATED' in line for line in lines): raise ValueError('Adjust end boundary: '+name)
        (evidence/(name+'.asm.txt')).write_text(
            'Bounded static listing; not a complete CFG or ASIC model.\n'
            'Firmware SHA256: '+digest(blob)+'\n'
            'FILE     CPU_PC   BYTES        MNEMONIC  OPERANDS\n'+'\n'.join(lines)+'\n')
        records.append(dict(name=name,cpu_start=hex(start),cpu_end_exclusive=hex(end),
                            file_start=hex(start-0x40000),file_end_exclusive=hex(end-0x40000),
                            sha256=digest(blob[start-0x40000:end-0x40000])))
    save_json(data/'v4_evidence_ranges.json',records)
    checks['evidence_ranges']=len(records)
    save_json(data/'pixel_pipeline.json',{
        'firmware_sha256':digest(blob),
        'cpu_to_file_offset':'ROM CPU address - 0x40000',
        'scope':'Selected processing and JPEG/resize paths, not all modes or NEF writing',
        'driver_cpu':'0x4b260','configuration_cpu':'0x4b41c',
        'engine_mmio':'0x40010000','completion_event':{'group':4,'mask':'0x00400000'},
        'interrupt_handler_cpu':'0x47874',
        'dataflow':[
            {'from':'context input buffer','to':'0x40010000','evidence':'address and geometry writes'},
            {'from':'0x40010000','to':'three memory planes','evidence':'producer writes and downstream consumers'},
            {'from':'three memory planes','to':'0x40030000 JPEG','evidence':'same addresses; 412-byte Huffman identification'},
            {'from':'three memory planes','to':'0x40020000 resize','evidence':'same addresses and ratio setup'}],
        'input_format':{'hypothesis':'packed 12-bit samples','confidence':'geometry inference only'},
        'output_format':{'hypothesis':'8-bit planar YCbCr 4:2:2','confidence':'strong converging static evidence',
                         'unresolved':['Cb/Cr order','range','chroma siting']},
        'plane_offsets_from_descriptor_base':['0x2f90','0x5cf590','0x8b5890'],
        'static_lut_definitions':static_stats,
        'small_luts':[dict(name=s[0],function_cpu=hex(s[1]),output_ram=hex(s[2]),hardware=hex(s[3]),
                           packed_rom=hex(s[4]),seed0_rom=hex(s[5]),seed1_rom=hex(s[6]),
                           compressed_bytes_per_profile=s[7],delta_bits=s[8],context_offset=hex(s[9]),
                           records_by_layout=10,hardware_entries=256,
                           role='sharpening-setting-linked; signal axis unknown' if s[0]!='E600' else 'signal axis and role unknown')
                      for s in SMALL],
        'auxiliary_4x16':{'rom':'0x331e0e','all_18_profiles_identical':True,
                          'values_per_block':[256,0,0,256],
                          'interpretation':'possible 16 identity 2x2 transforms at scale 256; unproved'},
        'selector_inputs':{'x':'u8(context+0x6d)',
                           'q':'clamp(128 + ((3 * trunc(sum(s16(context+0x104+2*i),i=0..14)/15)) >> 5),0,255)',
                           'physical_units':'unresolved','evidence_cpu':'0x31b6d2'},
        'internal_pixel_stage_order':'UNRESOLVED; CPU upload sequence is not ASIC topology',
        'camera_tested':False})
    checks['result']='PASS'
    checks['limitations']=[
        'No actual pixels produced; synthetic MMIO is plain RAM',
        'Geometry record selector, interrupt handlers, OS waits and JPEG codec not executed',
        'Internal ASIC stage order, rounding and LUT input axes unresolved',
        'Ten small-LUT records identified from seed-table spacing; reachability of all indices not proved',
        'V1-v3 validation reports preserved as historical results, not all rerun']
    save_json(data/'pixel_execution_checks.json',checks)
    save_json(out/'VALIDATION_v4.json',checks)
    print(json.dumps(checks,indent=2))


if __name__=='__main__':
    extract(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]) if len(sys.argv)>3 else None)
