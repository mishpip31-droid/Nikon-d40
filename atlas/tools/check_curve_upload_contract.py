"""Reproduce EXP03's wrong return pointer and test EXP04's real upload caller.
FR instructions execute; MMIO is ordinary mapped memory, with no ASIC pixels.
No replacement of the tone builder or of the three hardware copy loops.
"""
import argparse,hashlib,json,random,struct
from pathlib import Path
from atlas import require_b
from fr_color_machine import ColorMachine
CTX=0x20000000
CURVE=0x83EB586C
BANKS=(0x40018400,0x4001A400,0x4001C400)
BAD_SHA='3a48b641ecda06afbbfe38e2fa245b249958fd0134b9fa9203932f72617c80e2'

class Trace(ColorMachine):
    def __init__(self,original,image):
        super().__init__(original);self.blob=image;self.writes=[]
    def store(self,address,value,size):
        super().store(address,value,size)
        if 0x40010000<=address<0x40020000:
            self.writes.append((address,size,value&((1<<(8*size))-1)))

def setup(original,image,selector,seed,uploaded=False):
    m=Trace(original,image)
    m.map(CTX,random.Random(seed).randbytes(0x3000))
    m.map(0x83EB3000,bytes(0x6000));m.map(0x40010000,bytes(0x10000))
    m.map(0x83CE8344,bytes([9]))
    for source in (0x83E89310,0x83E882CC):
        m.map(source,bytes(0x1044))
        if uploaded:
            m.store(source,1,1);m.store(source+1,1,1)
            for i in range(2048):m.store(source+0x44+2*i,(2*i+seed)%4096,2)
    # Legal known-path inputs; other context bytes vary to expose wrong-source reads.
    m.store(CTX+0x1D,0,1);m.store(CTX+0x73C,0,1)
    m.store(CTX+0x466,selector,1);m.store(CTX+0x6AE,0,1)
    return m

def bank_data(m):return [[m.load(bank+2*i,2) for i in range(4096)] for bank in BANKS]

def check(original_path,bad_path,fixed_path,candidate_path,output):
    original=require_b(original_path);bad=Path(bad_path).read_bytes();fixed=Path(fixed_path).read_bytes()
    assert hashlib.sha256(bad).hexdigest()==BAD_SHA
    candidate=json.loads(Path(candidate_path).read_text())['curve_4096']
    # Regression must fail on the exact binary delivered as EXP03, not a fabricated bug.
    m=setup(original,bad,24,40);m.run(0x323C22,CTX)
    assert [m.load(CURVE+2*i,2) for i in range(4096)]==candidate
    assert m.regs[4]==CTX and m.regs[4]!=CURVE
    n=setup(original,bad,24,40)
    wrong=[n.load(CTX+2*i,2) for i in range(4096)]
    n.run(0x4B41C,CTX,budget=350000,stop=0x4B5F8)
    assert bank_data(n)==[wrong]*3
    reproduction={'binary_sha256':BAD_SHA,'computed_curve_correct':True,'return_pointer_actual':hex(m.regs[4]),'return_pointer_required':hex(CURVE),'all_three_banks_copy_context':True,'mismatches_per_bank':sum(x!=y for x,y in zip(wrong,candidate)),'entries_above_4095_per_bank':sum(x>4095 for x in wrong)}
    cases=0;mmio_elements=0
    for seed in range(8):
        for uploaded in (False,True):
            # The exact builder must satisfy the pointer and callee-save contract.
            m=setup(original,fixed,24,seed,uploaded)
            initial={i:m.regs[i] for i in (8,9,10,11,14,15)}
            m.run(0x323C22,CTX)
            assert m.regs[4]==CURVE
            assert all(m.regs[i]==v for i,v in initial.items())
            assert [m.load(CURVE+2*i,2) for i in range(4096)]==candidate
            # Execute original caller -> patched builder -> original upload loops.
            m=setup(original,fixed,24,seed,uploaded)
            m.run(0x4B41C,CTX,budget=350000,stop=0x4B5F8)
            assert bank_data(m)==[candidate]*3
            events=[(a,n,v) for a,n,v in m.writes if any(bank<=a<bank+8192 for bank in BANKS)]
            assert events==[(bank+2*i,2,v) for bank in BANKS for i,v in enumerate(candidate)]
            mmio_elements+=len(events);cases+=1
            # Original Custom also reaches MMIO unchanged (fallback and uploaded curve).
            a=setup(original,original,23,seed,uploaded);b=setup(original,fixed,23,seed,uploaded)
            a.run(0x4B41C,CTX,budget=350000,stop=0x4B5F8)
            b.run(0x4B41C,CTX,budget=350000,stop=0x4B5F8)
            assert a.writes==b.writes
            assert bank_data(a)==bank_data(b)
            cases+=1
    report={'result':'PASS_CPU_CALLER_BUILDER_MMIO_COPY','EXP03_regression':reproduction,'fixed_sha256':hashlib.sha256(fixed).hexdigest(),'upload_path_cases':cases,'Cinema_MMIO_u16_writes_checked':mmio_elements,'tone_builder_hooked':False,'upload_loops_hooked':False,'scope_end_cpu':'0x4b5f8','scope':'through all three tone-bank copies; later configuration not executed','physical_camera_tested':False,'ASIC_pixels_emulated':False}
    output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('original_B');p.add_argument('bad_EXP03');p.add_argument('fixed_EXP04');p.add_argument('candidate_json');p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();check(a.original_B,a.bad_EXP03,a.fixed_EXP04,a.candidate_json,a.output)
