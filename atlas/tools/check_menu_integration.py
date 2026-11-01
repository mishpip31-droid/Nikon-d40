"""Integration harness for ROM menu rows on EXP01. Physical LCD/OS are models."""
import argparse
import binascii
import hashlib
import json
import struct
import random
from pathlib import Path
from atlas import require_b, DATA_START, COPY_END, DELTA, BASE
from fr_decode import listing
from fr_menu_runtime_machine import MenuRuntimeMachine
from menu_shortcut_prototype import MENU, CURRENT, PARENT, CUSTOM, WORK_TONE, WORK_MODE, SAVED_MODE
from build_menu_experiment import assemble, TEXT_ID

ROOT=Path(__file__).resolve().parents[1]


class Checked(MenuRuntimeMachine):
    def __init__(self,original,image):
        super().__init__(original)
        self.blob=image
        self.writes=[];self.events=[];self.spans=[]

    def store(self,address,value,size):
        # Firmware address writes are deliberately unmapped and must fail.
        if BASE <= address < BASE+len(self.blob):
            raise AssertionError(('write to ROM descriptor/code',hex(address),size,hex(getattr(self,'pc',0))))
        super().store(address,value,size)
        self.writes.append((address,size))


def make(original,image,row=0,scroll=0,saved=0x09,tone=0,work=0):
    m=Checked(original,image);m.map(0x83CD0000,bytes(0x20000))
    a,data=m.regions[1];off=DATA_START+DELTA-a
    data[off:off+COPY_END-DATA_START]=image[DATA_START:COPY_END]
    m.regs[14]=0x10001800
    m.store(CURRENT,MENU,4);m.store(0x83CED108,PARENT,4)
    m.store(MENU+0xC,row-scroll,2);m.store(MENU+0xE,scroll,2)
    m.store(SAVED_MODE,saved,1);m.store(WORK_TONE,tone,1);m.store(WORK_MODE,work,1)
    m.writes.clear()
    return m


def noop(m): pass
def zero(m): m.regs[4]=0
def one(m): m.regs[4]=1


def sync(m):
    m.events.append({'kind':'sync_model','arg':m.regs[4]})


def syscall(m):
    code=m.regs[12]&0xffffffff
    m.events.append({'kind':'syscall_model','code':hex(code),'r4':m.regs[4],'r5':m.regs[5]})
    # Only menu event set and delay paths are allowed here, never a wildcard OS stub.
    assert code in (0xFFFFFFD0,0xFFFFFFDB),hex(code)
    m.regs[12]=0


def divide(m):
    x=m.regs[4];x=x-(1<<32) if x>>31 else x
    y=m.regs[5];y=y-(1<<32) if y>>31 else y
    assert y==2
    m.regs[4]=(abs(x)//abs(y)*(-1 if (x<0) != (y<0) else 1))&0xffffffff


def menu_divide(m):
    x=m.regs[4];x=x-(1<<32) if x>>31 else x
    y=m.regs[5];y=y-(1<<32) if y>>31 else y
    assert -4096<=x<=4096 and 0<y<=8,(x,y)
    m.regs[4]=(abs(x)//y*(-1 if x<0 else 1))&0xffffffff


def draw_model(m):
    start=m.load(m.regs[15]+0x10,4);end=m.load(m.regs[15]+0x14,4)
    assert BASE<=start<=end<=BASE+len(m.blob),(hex(start),hex(end))
    raw=m.blob[start-BASE:end-BASE]
    m.spans.append({'start':hex(start),'end':hex(end),'hex':raw.hex(),
                    'text':raw.decode('ascii',errors='backslashreplace')})
    # LCD glyph painting is replaced, while original callers and span hooks run.
    m.store(m.regs[4],0,2);m.store(m.regs[4]+2,40,2)


def icon_model(m):
    # Hardware-assisted bitmap painting receives an icon ID, not a descriptor.
    m.store(m.regs[4],20,2);m.store(m.regs[4]+2,20,2)


def hooks():
    return {0x4C1C2:zero,0x1477BA:zero,0x7D72A:noop,0x7CDE2:draw_model,0x7BD04:icon_model,0x7C904:icon_model,
            0xBE982:divide,0xBE78C:menu_divide,0x149DD8:noop,0x6A636:noop,0x1468AE:sync}


def main(original_path,exp_path,output):
    original=require_b(original_path);exp=Path(exp_path).read_bytes();image,manifest=assemble(original,exp)
    result={'result':'RUNNING','image_sha256':manifest['sha256'],'layout':manifest['layout'],
            'physical_camera_test':False,'read_only_rows':True,'models':['LCD rectangle/glyph painting','divide-by-two helper','palette and a menu visual-state query','event-set/delay OS calls','settings synchronization 0x1468ae']}
    primitive=0
    values=(0,1,0x7FFF,0x8000,0xFFFF,0x10000,0x80000000,0xFFFFFFFF)
    for opcode,unsigned in ((0xBB10,True),(0xBF10,False)):
        for x in values:
            for y in values:
                m=MenuRuntimeMachine(original);m.map(0x21000000,struct.pack('>HH',opcode,0x9720))
                m.regs[0]=x;m.regs[1]=y;m.c=m.v=True
                m.run(0x21000000)
                a=x&65535;b=y&65535
                if not unsigned:
                    a=a-65536 if a&32768 else a;b=b-65536 if b&32768 else b
                expected=(a*b)&0xffffffff
                assert m.mdl==expected and m.n==bool(expected&0x80000000) and m.z==(expected==0) and m.c and m.v
                primitive+=1
    rng=random.Random(120)
    for x in (*values,*(rng.getrandbits(32) for _ in range(16))):
        for amount in range(64):
            m=MenuRuntimeMachine(original);m.map(0x21000000,bytes.fromhex('b6109720'))
            m.regs[0]=x;m.regs[1]=amount;m.v=True
            m.run(0x21000000)
            expected=(x*(2**(amount%32)))%(2**32)
            carry=bool((x>>(32-amount%32))&1) if amount%32 else False
            assert m.regs[0]==expected and m.c==carry and m.v and m.z==(expected==0) and m.n==bool(expected&0x80000000)
            primitive+=1
    result['new_instruction_cases']=primitive
    # Every original type-0 text ID in every language: both argument prefixes.
    langs=json.loads((ROOT/'data/language_tables.json').read_text())
    span_cases=0
    for lang in langs:
        table=int(lang['table_rom'],16)
        for index in range(602):
            for entry,stop in ((0x7C222,0x7C23A),(0x7CB78,0x7CBB0)):
                m=make(original,image);m.store(0x83CE3FEC,table,4)
                m.regs[7]=index;m.regs[8]=index;m.regs[9]=0x83CE3FE8
                m.run(entry,stop=stop)
                if entry==0x7C222:start,end=m.regs[6],m.regs[7]
                else:start,end=m.load(m.regs[15]+0x10,4),m.load(m.regs[15]+0x14,4)
                if index==TEXT_ID:
                    assert image[start-BASE:end-BASE]==b'Cinema2383'
                else:
                    assert (start,end)==struct.unpack_from('>II',original,table-BASE+4*index)
                span_cases+=1
    result['all_language_span_cases']=span_cases

    # Execute original language selection and complete original font measurement.
    geometry=[]
    for lang_index in range(15):
        m=make(original,image);m.run(0x9B14E,arg=lang_index)
        table=m.load(0x83CE3FEC,4)
        m.regs[5]=TEXT_ID;m.regs[6]=0
        m.run(0x7BBDA,arg=0x10001800)
        width,height=m.load(0x10001800,2),m.load(0x10001802,2)
        assert 0<width<222 and 0<height<=40
        geometry.append({'language_selector':lang_index,'table':hex(table),'width_in_original_wrapper_units':width,'height':height})
    result['actual_font_measurements']=geometry

    # Actual original row list compositor; drawing emits spans instead of pixels.
    rendered=[]
    for viewport in (0,1):
        m=make(original,image,row=min(7,viewport+3),scroll=viewport)
        m.run(0x147B68,hooks=hooks(),budget=300000)
        rendered.append({'viewport':viewport,'spans':m.spans})
    assert any(s['text']=='Cinema2383' for r in rendered for s in r['spans'])
    result['original_compositor_runs']=rendered

    # Real menu event dispatcher, with explicit UI/OS/synchronization boundary models.
    dispatch=[]
    for row in range(8):
        m=make(original,image,row=row,scroll=min(row,1),saved=0x29,tone=0xA5,work=0x4A)
        m.regs[5]=0x10001800
        m.run(0x132286,arg=0x8000,hooks=hooks(),syscall=syscall,budget=300000)
        record={'row':row,'menu':hex(m.load(CURRENT,4)),'saved':m.load(SAVED_MODE,1),'work':m.load(WORK_MODE,1),'tone':m.load(WORK_TONE,1),'events':m.events}
        if row==6: assert m.load(CURRENT,4)==CUSTOM
        else:
            assert m.load(CURRENT,4)==PARENT
            assert any(e['kind']=='sync_model' and e['arg']==2 for e in m.events)
        if row==7:
            assert m.load(SAVED_MODE,1)>>4==5
            assert (m.load(WORK_TONE,1)>>2)&7==6
        dispatch.append(record)
    result['event_dispatch_cases']=dispatch

    movement=[]
    for direction,key in ((1,0x1000),(-1,0x2000)):
        for initial in range(8):
            m=make(original,image,row=initial,scroll=1 if initial==7 else 0,saved=0x59,tone=0xA5,work=0x54)
            for step in range(16):
                m.regs[5]=0x10001800
                m.run(0x132286,arg=key,hooks=hooks(),syscall=syscall,budget=100000)
                within,scroll=m.load(MENU+0xC,2),m.load(MENU+0xE,2)
                assert within+scroll==(initial+direction*(step+1))%8
                assert 0<=scroll<=1 and 0<=within<=6
                assert m.load(CURRENT,4)==MENU
                assert (m.load(SAVED_MODE,1),m.load(WORK_TONE,1),m.load(WORK_MODE,1))==(0x59,0xA5,0x54)
            movement.append({'event':hex(key),'start_row':initial,'steps':16})
    result['navigation_sequences']=movement
    result['navigation_steps']=len(movement)*16

    # Exit to parent without applying and the original pre-save/reload copies.
    exits=0;save_restore=0
    for initial in range(8):
        m=make(original,image,row=initial,scroll=1 if initial==7 else 0,saved=0x59,tone=0xA5,work=0x54)
        m.regs[5]=0x10001800
        m.run(0x132286,arg=0x4000,hooks=hooks(),syscall=syscall)
        assert m.load(CURRENT,4)==PARENT
        assert (m.load(SAVED_MODE,1),m.load(WORK_TONE,1),m.load(WORK_MODE,1))==(0x59,0xA5,0x54)
        assert not any(e['kind']=='sync_model' for e in m.events)
        exits+=1
    for old in range(256):
        m=make(original,image,row=7,scroll=1,saved=old,tone=old,work=old)
        m.run(0x143FA4,hooks=hooks())
        m.run(0x403FA,stop=0x6B708)
        stored=bytes(m.load(0x83CED21A+i,1) for i in range(32))
        assert stored[4]>>4==5 and ((stored[10]>>2)&7)==6
        # Model a journal read restoring exactly this block, then run real reload copy.
        n=make(original,image)
        for i,value in enumerate(stored):n.store(0x83CED21A+i,value,1)
        n.regs[9]=0x83CED21A
        n.run(0x40520,stop=0x40530)
        n.run(0x143EF6)
        assert n.load(SAVED_MODE,1)>>4==5
        assert n.load(MENU+0xC,2)+n.load(MENU+0xE,2)==7
        save_restore+=1
    result['exit_without_apply_cases']=exits
    result['pre_save_reload_prefix_cases']=save_restore
    result['journal_write_and_real_power_cycle_executed']=False

    result['result']='PASS_WITH_MODELED_LCD_OS_AND_SYNC'
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    for name,start,end in [('EXP02_initializer',0x143EF6,0x143F40),('EXP02_measure_hook',0x143F40,0x143F72),
                            ('EXP02_action',0x143FA4,0x14403E),('EXP02_draw_hook',0x14403E,0x14408E)]:
        (ROOT/'evidence'/(name+'_v12.asm.txt')).write_text('\n'.join(listing(image,start-BASE,end-BASE))+'\n')
    print(json.dumps({'result':result['result'],'all_language_span_cases':span_cases,'font_measurements':len(geometry),'compositor_runs':len(rendered),'dispatcher_runs':len(dispatch),'navigation_steps':result['navigation_steps'],'save_reload_prefix_cases':save_restore},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('original_B');p.add_argument('EXP01');p.add_argument('--output',type=Path,default=ROOT/'data/menu_integration_validation.json')
    a=p.parse_args();main(a.original_B,a.EXP01,a.output)
