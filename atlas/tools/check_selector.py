"""Read-only, bounded execution of the D40 B 1.11 optimize-menu selector.
Only the observed instruction subset is implemented. System side effects are
stubbed and recorded; this is not a camera emulator or a flashability check.
"""
from pathlib import Path
import random,sys,hashlib
firmware_path=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).with_name('BD400111.bin')
BLOB=firmware_path.read_bytes()
EXPECTED_SHA256='b9df48d461e875dce4ba84da88164af170dfc48ad9f7674859623bad0401032e'
if hashlib.sha256(BLOB).hexdigest()!=EXPECTED_SHA256:
    raise SystemExit('Unsupported firmware: this analysis applies only to the original D40 B 1.11 file with the documented SHA-256.')
def run(selected,old_saved,old_work):
    regs=[0]*16;regs[15]=0x10001000
    memory={};pc=0x143fa4;rp=0xdead0000;pending=None;z=False;calls=[]
    def load(a,n):
        if 0x40000<=a and a+n<=0x40000+len(BLOB):return int.from_bytes(BLOB[a-0x40000:a-0x40000+n],'big')
        return int.from_bytes(bytes(memory.get(a+i,0) for i in range(n)),'big')
    def store(a,v,n):
        for i,x in enumerate((v&((1<<(8*n))-1)).to_bytes(n,'big')):memory[a+i]=x
    store(0x83cee49c,0x83ce58ac,4)
    store(0x83ce58ac+0x0c,0,2);store(0x83ce58ac+0x0e,selected,2)
    store(0x83ce58ac+0x1c,0x83ce58cc,4);store(0x83ce58ac+0x14,0x83ce53cc,4)
    store(0x83ce957f,old_saved,1);store(0x83ced225,old_work,1)
    for steps in range(500):
        if pc==0xdead0000:return load(0x83ce957f,1),load(0x83ced225,1),load(0x83cee49c,4),calls
        if pc==0x1468ae:
            calls.append(regs[4]);pc=rp;continue
        w=load(pc,2);i=w&15;j=(w>>4)&15;x=(w>>4)&255;nextpc=pc+2;scheduled=None
        if w&0xfff0==0x9f80:regs[i]=load(pc+2,4);nextpc=pc+6
        elif w&0xf000==0xc000:regs[i]=x
        elif w&0xff00==0x8b00:regs[i]=regs[j]
        elif w&0xff00==0x0400:regs[i]=load(regs[j],4)
        elif w&0xff00==0x0600:regs[i]=load(regs[j],1)
        elif w&0xff00==0x0000:regs[i]=load((regs[13]+regs[j])&0xffffffff,4)
        elif w&0xff00==0x0100:regs[i]=load((regs[13]+regs[j])&0xffffffff,2)
        elif w&0xff00==0x1400:store(regs[j],regs[i],4)
        elif w&0xff00==0x1600:store(regs[j],regs[i],1)
        elif w&0xfff0==0x1700:regs[15]-=4;store(regs[15],regs[i],4)
        elif w==0x1781:regs[15]-=4;store(regs[15],rp,4)
        elif w&0xfff0==0x0700:regs[i]=load(regs[15],4);regs[15]+=4
        elif w==0x0781:rp=load(regs[15],4);regs[15]+=4
        elif w&0xff00==0xa400:regs[i]=(regs[i]+j)&0xffffffff
        elif w&0xff00==0xa600:regs[i]=(regs[i]+regs[j])&0xffffffff
        elif w&0xff00==0xaa00:z=regs[i]==regs[j]
        elif w&0xff00==0x8200:regs[i]&=regs[j]
        elif w&0xff00==0x9200:regs[i]|=regs[j]
        elif w&0xff00==0xb400:regs[i]=(regs[i]<<j)&0xffffffff
        elif w&0xfff0==0x9780:regs[i]=((regs[i]&255)-(256 if regs[i]&128 else 0))&0xffffffff
        elif w&0xfff0==0x97a0:regs[i]=((regs[i]&65535)-(65536 if regs[i]&32768 else 0))&0xffffffff
        elif w&0xff00==0xe300:
            if not z:nextpc=pc+2+((w&255)-(256 if w&128 else 0))*2
        elif w&0xff00==0xf000:scheduled=pc+2+((w&255)-(256 if w&128 else 0))*2
        elif w&0xfff0==0x9700:nextpc=regs[i]
        elif w&0xfff0==0x9f00:scheduled=regs[i]
        elif w&0xfff0==0x9f10:rp=pc+4;scheduled=regs[i]
        elif w==0x9f20:scheduled=rp
        elif w&0xff00 in (0x8000,0x8100):
            a=regs[i];old=load(a,1);mask=j if w&0xff00==0x8000 else j<<4
            preserve=0xf0 if w&0xff00==0x8000 else 0x0f;store(a,old&(preserve|mask),1)
        else:raise RuntimeError(f'unhandled instruction {w:04x} at {pc:08x}')
        pc=pending if pending is not None else nextpc
        pending=scheduled
    raise RuntimeError('instruction budget exceeded')
if __name__=='__main__':
    rng=random.Random(40);count=0
    for choice,mode in enumerate([0,1,2,3,4,6,None]):
        for _ in range(64):
            saved,work=rng.randrange(256),rng.randrange(256)
            out_saved,out_work,menu,calls=run(choice,saved,work)
            if mode is None:
                assert (out_saved,out_work,menu,calls)==(saved,work,0x83ce593c,[])
            else:
                assert out_saved==(saved&15)|(mode<<4)
                assert out_work==(work&0xc3)|(mode<<2)
                assert menu==0x83ce53cc and calls==[2]
            count+=1
    print(f'PASS: {count} bounded executions of original selector; all seven entries and preserved bits checked.')
    print('Firmware bytes unchanged. Persistence, JPEG output, hardware execution and update acceptance are not tested.')
