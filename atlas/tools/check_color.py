"""Execute original color fragments in synthetic memory; never touch a camera."""
import hashlib
import json
import random
import struct
import sys
from pathlib import Path
from fr_color_machine import ColorMachine, signed
from color_tables import matrices, expand_profile, saturation_pair, selected_profile, hue_model, f32


def new_machine(blob):
    m = ColorMachine(blob)
    m.map(0x83eb3000, bytes(0x6000))
    m.map(0x68000ae4, bytes(8))
    for address,value in {0x83eb8717:6,0x83eb8718:7,
                          0x83eb870c:6,0x83eb870d:6,0x83eb870e:6,0x83eb870f:6}.items():
        m.store(address,value,1)
    return m


def check_profiles(blob):
    for index in list(range(48))+list(range(1000,1005)):
        m = new_machine(blob)
        m.store(0x83eb78f4-8,0xa5a5a5a5a5a5a5a5,8)
        m.store(0x83eb78f4+1026,0xa5a5a5a5a5a5a5a5,8)
        expected = expand_profile(blob,index)
        m.run(0x324124,index)
        actual = [m.load(0x83eb78f4+i,1) for i in range(len(expected))]
        assert actual == expected, index
        assert m.regs[4] == 0x83eb78f4
        assert m.regs[15] == 0x10001000
        assert m.load(0x83eb78f4-8,8) == 0xa5a5a5a5a5a5a5a5
        assert m.load(0x83eb78f4+1026,8) == 0xa5a5a5a5a5a5a5a5
    return 53


def check_selector(blob):
    # Stop before the 1024-iteration delay loop; verify all table-address cases.
    count = 0
    for sat in range(4):
        for family in range(3):
            for x in (60,61,65,66,70,71,72,84,96,108,119,120,200):
                for q in (0,142,143,180,218,219,255):
                    m = new_machine(blob)
                    for address,value in ((0x83eb3d44,sat),(0x83eb3cd4,family),
                                          (0x83eb5858,x),(0x83eb5868,q)):
                        m.store(address,value,4)
                    m.run(0x3232d8,stop=0x3233e8)
                    a,b,k,clipped_x = saturation_pair(blob,sat,family,x,q)
                    assert (m.regs[4],m.regs[5],m.regs[6],m.regs[8]) == (a,b,k,clipped_x)
                    count += 1
    # Run the whole selector, including its original remainder dispatch.
    full = 0
    for sat in range(4):
        for family in range(3):
            for x in list(range(60,73))+[119,120,200]:
                m = new_machine(blob)
                for address,value in ((0x83eb3d44,sat),(0x83eb3cd4,family),
                                      (0x83eb5858,x),(0x83eb5868,180)):
                    m.store(address,value,4)
                m.run(0x3232d8)
                assert m.load(0x83eb786c,2) == selected_profile(blob,sat,family,x,180)
                assert m.regs[15] == 0x10001000
                full += 1
    return count, full


def check_matrix_transport(blob):
    rng = random.Random(2383)
    m1 = matrices(blob,0x332888,18)
    m2 = matrices(blob,0x33270e,21)
    cases = [(a,b) for a in m1 for b in m2]
    cases += [([-1023,1023,0,-1,1,512,-512,511,-511],[-511,511,0,-1,1,256,-256,255,-255])]
    cases += [([rng.randrange(-1023,1024) for _ in range(9)],
               [rng.randrange(-511,512) for _ in range(9)]) for _ in range(20)]
    for a,b in cases:
        m = new_machine(blob)
        ctx = 0x20000000
        m.map(ctx,bytes([0xa5])*0x800)
        m.map(0x40010000,bytes([0xa5])*0x60)
        m.store(0x83eb5864,ctx,4)
        for address,values in ((0x83eb3be0,a),(0x83eb3bbc,b)):
            for i,v in enumerate(values): m.store(address+4*i,v,4)
        m.regs[8] = 0x83eb5864
        m.regs[14] = 0x10001000
        m.regs[15] = 0x10000ff0
        m.run(0x323562,stop=0x3235e4)
        expected_a = [v if v>=0 else abs(v)|0x400 for v in a]
        expected_b = [v if v>=0 else abs(v)|0x200 for v in b]
        assert [m.load(ctx+0x3a4+2*i,2) for i in range(18)] == expected_a+expected_b
        assert m.load(ctx+0x3a2,2) == m.load(ctx+0x3c8,2) == 0xa5a5
        m.regs[8],m.regs[9] = 0x40010000,ctx+0x26c
        m.run(0x4b4ca,stop=0x4b4f2)
        assert [m.load(0x40010022+2*i,2) for i in range(18)] == expected_a+expected_b
        assert m.load(0x40010020,2) == m.load(0x40010046,2) == 0xa5a5
    return len(cases)


def check_hue_with_fp_hooks(blob):
    def asfloat(v): return struct.unpack('>f',struct.pack('>I',v))[0]
    def asbits(v): return struct.unpack('>I',struct.pack('>f',v))[0]
    def conversion(m): m.regs[4] = asbits(signed(m.regs[4]))
    def truncation(m): m.regs[4] = int(asfloat(m.regs[4])) & 0xffffffff
    def compare(m):
        a,b = asfloat(m.regs[4]),asfloat(m.regs[5])
        m.z,m.n,m.v,m.c = a==b,a<b,False,a<b
    def binary(op):
        def invoke(m): m.regs[4] = asbits(op(asfloat(m.regs[4]),asfloat(m.regs[5])))
        return invoke
    hooks = {0xbe968:conversion,0xbe8de:truncation,0xbe474:compare,
             0xbe6ea:binary(lambda a,b:a/b),0xbeb22:binary(lambda a,b:a*b),
             0xbe352:binary(lambda a,b:a+b)}
    cases = matrices(blob,0x33270e,21)+[[76,151,29,511,-511,500,-511,511,500]]
    count = 0
    for family,mode in enumerate((3,1,4)):
        for hue in range(7):
            for mat in cases:
                m = new_machine(blob)
                m.store(0x83eb3d48,mode,4); m.store(0x83eb3d34,hue,4)
                for i,v in enumerate(mat): m.store(0x83eb3bbc+4*i,v,4)
                m.run(0x322606,hooks=hooks)
                actual = [signed(m.load(0x83eb3bbc+4*i,4)) for i in range(9)]
                assert actual == hue_model(blob,mat,hue,family), (family,hue,mat,actual)
                assert [signed(m.load(0x83eb3a88+4*i,4)) for i in range(9)] == mat
                assert m.regs[15] == 0x10001000
                count += 1
    return count


if __name__ == '__main__':
    blob = Path(sys.argv[1]).read_bytes()
    profiles = check_profiles(blob)
    pair,full = check_selector(blob)
    transport = check_matrix_transport(blob)
    hue = check_hue_with_fp_hooks(blob)
    print(json.dumps(dict(result='PASS',firmware_sha256=hashlib.sha256(blob).hexdigest(),
                         profile_expansions_original_code=profiles,
                         saturation_selector_prefix_executions=pair,
                         saturation_selector_full_executions=full,
                         matrix_transport_cases_two_fragments_each=transport,
                         hue_executions_with_host_float32_hooks=hue,
                         camera_connected=False,firmware_modified=False,
                         limitations=['Synthetic memory only; no sensor/JPEG/hardware tests',
                                      'Hue floating point runtime replaced with host operations; not a bit-exact FP validation',
                                      'Matrix selection across all shooting and white-balance modes is not executed']),indent=2))
