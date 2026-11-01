"""Bounded checks for separated fixed Cinema preset and original Custom.
Physical flash, LCD/OS synchronization and actual power cycling are not tested.
"""
import argparse,binascii,hashlib,json,random,struct,sys
from pathlib import Path
from atlas import require_b,BASE
from build_independent_profile import assemble,FLAG,ARENA,ARENA_END
from check_menu_integration import make,hooks,syscall
from menu_shortcut_prototype import MENU,CURRENT,PARENT,CUSTOM,SAVED_MODE,WORK_MODE,WORK_TONE
from fr_color_machine import ColorMachine
from check_updater import probe_image,flash_commands

ROOT=Path(__file__).resolve().parents[1]


def raw(m,a,n):return bytes(m.load(a+i,1) for i in range(n))
def put(m,a,data):
    for i,x in enumerate(data):m.store(a+i,x,1)


def color_machine(original,image,seed=0):
    m=ColorMachine(original);m.blob=image
    m.map(0x20000000,bytes(0x1800));m.map(0x83EB3000,bytes(0x6000))
    m.store(0x83EB5864,0x20000000,4)
    return m


def main(original_path,exp_path,candidate_path,output):
    original=require_b(original_path);exp=Path(exp_path).read_bytes();candidate=json.loads(Path(candidate_path).read_text())
    image,manifest=assemble(original,exp,candidate)
    result={'result':'RUNNING','sha256':manifest['sha256'],'manifest':manifest,'camera_tested':False}
    assert image[0x9C294:0x9D294]==original[0x9C294:0x9D294]
    assert image[0xBF06:0xBFAC]==original[0xBF06:0xBFAC]
    # The only base-table literal is in the curve builder. No new state is placed
    # in unclassified padding: arena is reclaimed from the proven zero lookup.
    hits=[o for o in range(len(original)-3) if original[o:o+4]==ARENA.to_bytes(4,'big')]
    assert hits==[0x2E3C36],hits
    menu_cases=0
    for row in range(8):
        for old in range(256):
            m=make(original,image,row=row,scroll=1 if row==7 else 0,saved=0x59,tone=old,work=(old&0xC3)|0x14)
            before=raw(m,WORK_TONE,8)
            m.regs[5]=0x10001800;m.run(0x132286,arg=0x8000,hooks=hooks(),syscall=syscall)
            if row==7:
                assert m.load(FLAG,1)==1 and raw(m,WORK_TONE,8)==before
                assert m.load(SAVED_MODE,1)>>4==5
            elif row==6:
                assert m.load(CURRENT,4)==CUSTOM and raw(m,WORK_TONE,8)==before
            else:
                assert m.load(FLAG,1)==0
                # Only the mode bits in byte 1 are allowed to change.
                after=raw(m,WORK_TONE,8)
                assert after[0]==before[0] and after[2:]==before[2:] and (after[1]&0xC3)==(before[1]&0xC3)
            menu_cases+=1
    result['menu_cases']=menu_cases

    done_cases=0
    for old in range(256):
        m=make(original,image,saved=old,tone=old,work=old^0x55)
        m.store(FLAG,1,1);m.store(CURRENT,CUSTOM,4)
        m.store(CUSTOM+12,0,2);m.store(CUSTOM+14,0,2)
        m.run(0x144302,hooks=hooks())
        assert m.load(FLAG,1)==0 and m.load(CURRENT,4)==PARENT
        assert m.load(SAVED_MODE,1)==((old&15)|0x50)
        assert m.load(WORK_TONE,1)==old and m.load(WORK_MODE,1)==(((old^0x55)&0xC3)|0x14)
        done_cases+=1
    result['custom_done_cases']=done_cases

    capture_cases=0
    for flag in (0,1):
        for old in range(256):
            m=make(original,image,saved=0x59,tone=old,work=0x94)
            m.map(0x20000000,bytes(0x1000));m.store(FLAG,flag,1)
            payload=bytes((old,(old*37+13)&255,old^0x55,9,8,7,6,5));put(m,WORK_TONE,payload)
            m.run(0x4793A,arg=0x2000002C,stop=0x47956)
            expected=bytes.fromhex('3d5400')+payload[3:] if flag else payload
            assert raw(m,0x2000002C,8)==expected and raw(m,WORK_TONE,8)==payload
            # Process the already captured frame after flipping the menu flag.
            m.store(FLAG,1-flag,1)
            assert raw(m,0x2000002C,8)==expected
            capture_cases+=1
    result['capture_snapshot_cases']=capture_cases

    decoder_cases=0
    for tonebyte in range(256):
        m=color_machine(original,image);m.store(0x2000002C,tonebyte,1)
        m.run(0x31ED1A,stop=0x31ED3C)
        tone=(tonebyte>>2)&7
        assert m.load(0x83EB3D50,4)==(6 if tone==7 else tone)
        assert m.load(0x2000002C,1)==tonebyte
        decoder_cases+=1
    result['decoder_cases']=decoder_cases

    # Full existing parameter serialization with valid stock inputs. Custom
    # must reproduce the original, including the existing uploaded-curve selector.
    packed_values=[]
    for field,sign in (('M1_candidate_Q9',0x400),('M2_candidate_Q8',0x200)):
        for row in candidate[field]:
            packed_values += [x if x>=0 else -x|sign for x in row]
    packing_cases=0
    for rawtone in range(8):
        for mode in (0,5,6):
            for flags in (0,0x20):
                for mono in (0,1):
                    machines=[]
                    for blob in (original,image):
                        m=color_machine(original,blob)
                        rng=random.Random(40+packing_cases)
                        data=next(d for a,d in m.regions if a==0x83EB3000)
                        data[0xABC:0xC04]=rng.randbytes(82*4)
                        m.store(0x83EB5864,0x20000000,4)
                        m.store(0x2000002C,(rawtone<<2)|1,1);m.store(0x2000002D,(mode<<2)|0x40,1)
                        m.store(0x2000001D,flags,1);m.store(0x83EB3D1C,mono,4)
                        m.store(0x83EB3CC0,23,4);m.store(0x83EB3CBC,23,4)
                        m.store(0x83EB3D50,6 if rawtone==7 else rawtone,4)
                        try:m.run(0x3234BE,stop=0x3236DA if mono else None)
                        except Exception as e:raise RuntimeError(('serializer case',rawtone,mode,flags,mono,'original' if blob is original else 'patched',str(e))) from e
                        machines.append(m)
                    a,b=machines
                    expected=bytearray(raw(a,0x20000000,0x1800))
                    if rawtone==7:
                        expected[0x2C]=(expected[0x2C]&0xE3)|(6<<2)
                        if mode==5 and flags==0 and mono==0:
                            expected[0x466]=24
                            expected[0x3A4:0x3C8]=struct.pack('>18H',*packed_values)
                    assert raw(b,0x20000000,0x1800)==bytes(expected),('packing',rawtone,mode,flags,mono)
                    for reg in ((8,14,15) if mono else (8,9,10,11,14,15)):assert a.regs[reg]==b.regs[reg]
                    packing_cases+=1
    result['packing_cases']=packing_cases
    result['packing_scope']='48 full color executions and 48 monochrome prefixes ending before original division tail'

    # Main curve: all legal stock selectors, fallback/uploaded headers and
    # correction columns; the original zero correction table is replaced by 0.
    curve_cases=0
    def curve_machine(blob,selector,header,column):
        m=color_machine(original,blob)
        for address in (0x83E89310,0x83E882CC):
            m.map(address,bytes(0x1044));m.store(address,header,1);m.store(address+1,header,1)
            for i in range(2048):m.store(address+0x44+2*i,(i*2+17)%4096,2)
        m.map(0x83CE8344,bytes([9]));m.store(0x20000466,selector,1);m.store(0x200006AE,column,1)
        return m
    for selector in (0,1,7,14,21,22,23):
        for header in (0,1):
            for column in (0,4,8):
                a=curve_machine(original,selector,header,column);b=curve_machine(image,selector,header,column)
                a.run(0x323C22,arg=0x20000000,budget=350000);b.run(0x323C22,arg=0x20000000,budget=350000)
                assert a.regs[4]==b.regs[4]==0x83EB586C
                assert raw(a,0x83EB586C,8192)==raw(b,0x83EB586C,8192),('stock curve',selector,header,column)
                curve_cases+=1
    for header in (0,1):
        for column in (0,4,8):
            m=curve_machine(image,24,header,column);m.run(0x323C22,arg=0x20000000,budget=100000)
            assert [m.load(0x83EB586C+2*i,2) for i in range(4096)]==candidate['curve_4096']
            assert m.regs[4]==0x83EB586C, 'curve ABI return pointer'
            curve_cases+=1
    result['curve_cases']=curve_cases

    # Save only encodes tag 7 in the record handed to the journal. Runtime
    # settings remain mode 5; physical journal writes are explicitly modeled.
    persistence=0
    for mode,flag in [(mode,flag) for mode in range(7) for flag in (0,1)]:
        for low in range(16):
            active=int(flag==1 and mode==5)
            value=(mode<<4)|low
            m=make(original,image,saved=value,tone=0xA5,work=(mode<<2)|0x40);m.store(FLAG,flag,1)
            custom=raw(m,WORK_TONE,8);records=[]
            def journal(c):records.append(raw(c,0x83CED21A,18))
            hs=hooks();hs[0x6B708]=journal;hs[0x6CCD8]=lambda c:None
            m.run(0x403FA,hooks=hs)
            assert len(records)==1 and records[0][4]==((0x70|low) if active else value)
            assert m.load(SAVED_MODE,1)==value and m.load(0x83CED21E,1)==value
            assert raw(m,WORK_TONE,8)==custom
            n=make(original,image);put(n,0x83CED21A,records[0]);n.regs[9]=0x83CED21A
            n.run(0x40520,stop=0x40530)
            assert n.load(FLAG,1)==active and n.load(SAVED_MODE,1)==value
            assert raw(n,WORK_TONE,8)==custom
            n.run(0x143EF6)
            assert n.load(MENU+12,2)+n.load(MENU+14,2)==(7 if active else (6 if mode==5 else 5 if mode==6 else mode))
            persistence+=1
    result['save_load_cases']=persistence
    probe=probe_image(original,image)
    assert probe['accepted'] and probe['kind_flag']==1
    schedule=flash_commands(original,(1,),None)
    programs=[(int(x['address'],16),int(x['length'],16)) for x in schedule['commands'] if x['op']=='program']
    changed=[off for off,(a,b) in enumerate(zip(original,image)) if a!=b]
    assert all(any(start<=off+BASE<start+size for start,size in programs) for off in changed)
    assert binascii.crc_hqx(image,0)==0
    result['update_precheck']=probe
    result['changed_bytes']=len(changed)
    result['all_changed_bytes_in_modeled_update_ranges']=True
    result['physical_flash_tested']=False
    result['result']='PASS_WITH_MODELED_JOURNAL_LCD_OS_SYNC'
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k.endswith('_cases') or k=='result'},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('original_B');p.add_argument('EXP01');p.add_argument('candidate_json');p.add_argument('--output',type=Path,default=ROOT/'data/independent_profile_validation.json')
    a=p.parse_args();main(a.original_B,a.EXP01,a.candidate_json,a.output)
