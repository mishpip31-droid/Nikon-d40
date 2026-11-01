#!/usr/bin/env python3
"""Read-only execution of original D40 B flash/update routines.
All flash responses, OS events and MMIO effects are explicit computer models.
No camera is connected; no input firmware is modified.
"""
import argparse, hashlib, itertools, json, struct
from pathlib import Path
from fr_update_machine import UpdateMachine, EXPECTED
from check_updater import write_bytes

RAMBASE=0x83CD0000
TYPE=0x83CEA3E8
LOCK=0x83CEA3D0
TARGET=0x180000
SOURCE=0x81000000
UNLOCK_A=(0x400AAA,0x4AAAA)
UNLOCK_B=(0x400554,0x45554)

class ProbeMachine(UpdateMachine):
    def __init__(self,blob):
        super().__init__(blob)
        self.map(RAMBASE,bytes(0x40000))
        write_bytes(self,0x83CDFFB0,blob[0x1144C4:0x11D52A])
        self.map(0x50000000,bytes(0x200))
        self.map(0x40040000,bytes(0x400))
        self.map(0x40060000,bytes(0x20))
        self.writes=[];self.read_sequences={};self.read_counts={}
        self.program_model=False;self.armed=False;self.corrupt_offset=None
        self.syscalls=[];self.identity=None;self.id_mode=False
        self.store(LOCK,1,4)
        self.store(0x83CEA3D8,0x7fffffff,4)
        self.writes=[]

    def load(self,address,size):
        if address in self.read_sequences:
            seq=self.read_sequences[address]
            index=self.read_counts.get(address,0);self.read_counts[address]=index+1
            return seq[min(index,len(seq)-1)]
        if address==0x40000 and size==4 and self.id_mode and self.identity is not None:
            return self.identity
        return super().load(address,size)

    def store(self,address,value,size):
        if hasattr(self,'writes') and 0x40000<=address<0x410000:
            assert size==2
            self.writes.append({'pc':hex(getattr(self,'pc',0)),'address':hex(address),'value':hex(value&65535)})
            if self.armed:
                self.armed=False
                if self.program_model:
                    if self.corrupt_offset is not None and address==TARGET+self.corrupt_offset:value^=1
                    super().store(address,value,2)
            elif address in UNLOCK_A and value==0xA0:self.armed=True
            elif address in UNLOCK_A and value==0x90:self.id_mode=True
            elif address in UNLOCK_A and value==0xF0:self.id_mode=False
            return
        if hasattr(self,'writes') and 0x40000000<=address<0x60000000:
            self.writes.append({'pc':hex(getattr(self,'pc',0)),'address':hex(address),'value':hex(value),'size':size})
        super().store(address,value,size)

    def syscall(self,m):
        self.syscalls.append({'pc':hex(self.pc),'code':hex(self.regs[12]),'args':self.regs[4:8]})
        self.regs[12]=0

def machine(blob,kind=0):
    m=ProbeMachine(blob);m.store(TYPE,kind,1);return m

def execute(m,pc,arg=0,budget=100000,hooks=None,syscall=None,stop=None):
    entry_sp=m.regs[15]
    steps=m.run(pc,arg,budget=budget,hooks=hooks,syscall=syscall or m.syscall,stop=stop)
    if stop is None:assert m.regs[15]==entry_sp, "Unbalanced stack"
    return {'return':m.regs[4],'instructions':steps}

def poll(m,expected,sequence,budget=1000):
    m.regs[5]=expected;m.read_sequences[TARGET]=sequence
    try:res=execute(m,0x83CE8C7A,TARGET,budget)
    except RuntimeError as e:
        if str(e)!='Instruction budget exceeded':raise
        res={'return':None,'bounded_run_exhausted':True,'last_pc':hex(m.pc)}
    res['reads']=m.read_counts[TARGET];return res

def test_poll(blob):
    cases=0
    for kind,expected,first in itertools.product((0,1),(0,0x80),range(256)):
        m=machine(blob,kind)
        # A ready second read distinguishes hardware-error detection from retry.
        res=poll(m,expected,[first,expected])
        assert res['return']==1
        assert res['reads']==(1 if first&0x80==expected else 2)
        cases+=1
    errors=[]
    for expected in (0,0x80):
        bad=(expected^0x80)|0x20
        m=machine(blob,0);r=poll(m,expected,[bad,bad]);assert r['return']==0 and r['reads']==2;errors.append(r)
    stalls=[]
    for kind,expected in itertools.product((0,1),(0,0x80)):
        bad=expected^0x80
        if kind:bad|=0x20
        m=machine(blob,kind);r=poll(m,expected,[bad],5000)
        assert r.get('bounded_run_exhausted')
        stalls.append({'kind':kind,'expected_bit7':expected,**r})
    return {'ready_or_transition_cases':cases,'confirmed_error_cases':errors,'persistent_busy_cases':stalls,'scope':'No local counter, clock read or watchdog service occurs in this loop; external watchdog/reset not modeled'}

def test_identity(blob):
    rows=[]
    for locked,identity in itertools.product((0,1),(0x00BF235B,0x00BF0000,0x000122F9,0xFFFFFFFF)):
        m=machine(blob);m.store(LOCK,locked,4);m.identity=identity
        res=execute(m,0x83CE8658)
        assert m.load(TYPE,1)==int(identity>>16==0xBF)
        assert m.load(0x83CEA3CC,4)==identity
        assert [int(w['value'],16) for w in m.writes]==[0xAA,0x55,0x90,0xF0]
        assert len(m.syscalls)==(0 if locked else 2)
        rows.append({'identity':hex(identity),'already_locked':locked,'selected_kind':m.load(TYPE,1),'commands':m.writes,'syscalls':m.syscalls,**res})
    return rows

def test_program(blob):
    rows=[]
    words=(0,0x80,0x7F,0x1234,0xA55A,0xFFFF)
    for kind,word,locked in itertools.product((0,1),words,(0,1)):
        m=machine(blob,kind);m.store(LOCK,locked,4)
        m.map(TARGET,b'\xff'*16);m.program_model=True;m.regs[5]=word
        res=execute(m,0x83CE8BE8,TARGET)
        assert res['return']==1
        expected_commands=[] if word==0xFFFF else [(UNLOCK_A[kind],0xAA),(UNLOCK_B[kind],0x55),(UNLOCK_A[kind],0xA0),(TARGET,word)]
        assert [(int(x['address'],16),int(x['value'],16)) for x in m.writes]==expected_commands
        assert len(m.syscalls)==(2 if not locked and word!=0xFFFF else 0)
        rows.append({'kind':kind,'word':hex(word),'locked':locked,'commands':m.writes,**res})
    m=machine(blob,0);m.regs[5]=0x1234;m.read_sequences[TARGET]=[0xA0]
    failed=execute(m,0x83CE8BE8,TARGET)
    assert failed['return']==0 and int(m.writes[-1]['value'],16)==0xF0
    return {'successful_cases':len(rows),'cases':rows,'DQ5_failure':{'commands':m.writes,**failed}}

def test_program_range(blob):
    result=[]
    data=bytes.fromhex('1234ffff008000007f7fa55a')
    for kind,n in itertools.product((0,1),range(len(data)+1)):
        m=machine(blob,kind);m.map(TARGET,b'\xff'*32);m.map(SOURCE,data+b'\0\0')
        m.program_model=True;m.regs[5]=SOURCE;m.regs[6]=n
        res=execute(m,0x83CE89E0,TARGET)
        assert res['return']==1
        compared=(n+1)//2*2
        actual=bytes(m.load(TARGET+i,1) for i in range(compared))
        assert actual==data[:compared]
        result.append({'kind':kind,'length_arg':n,'bytes_programmed_or_compared':compared,**res})
    corrupt=[]
    for offset in (0,4,6,8,10):
        m=machine(blob);m.map(TARGET,b'\xff'*32);m.map(SOURCE,data)
        m.program_model=True;m.corrupt_offset=offset;m.regs[5]=SOURCE;m.regs[6]=len(data)
        res=execute(m,0x83CE89E0,TARGET);assert res['return']==0
        assert int(m.writes[-1]['value'],16)==0xF0
        corrupt.append({'corrupted_halfword_offset':offset,'bit_flip':0,'poll_bit7_unchanged':True,**res})
    return {'cases':result,'readback_rejects_corruption_after_successful_bit7_poll':corrupt,
            'note':'Odd lengths round up to a full halfword; actual updater ranges are even. Host model instantly commits non-FFFF words; no electrical simulation.'}

def test_blank(blob):
    result=[]
    for n in (0,1,2,3,16,64):
        for bad in (None,0,(n+1)//2-1):
            if n==0 and bad is not None:continue
            m=machine(blob);data=bytearray(b'\xff'*66)
            if bad is not None:data[bad*2]^=1
            m.map(TARGET,data);m.regs[5]=n
            res=execute(m,0x83CE8A9E,TARGET)
            assert res['return']==int(bad is None)
            result.append({'length_arg':n,'bad_halfword':bad,**res})
    return result

def test_erase_commands(blob):
    rows=[]
    for kind,length in itertools.product((0,1),(0x2000,0x10000)):
        m=machine(blob,kind);m.regs[5]=length;m.read_sequences[TARGET]=[0xFFFF]
        # Every addressed 4 KiB sub-sector gets a ready response.
        for off in range(0,length,0x1000):m.read_sequences[TARGET+off]=[0xFFFF]
        res=execute(m,0x83CE8B02,TARGET)
        assert res['return']==1
        count=1 if kind==0 else length//0x1000
        assert len(m.writes)==count*6
        for i in range(count):
            expected=[(UNLOCK_A[kind],0xAA),(UNLOCK_B[kind],0x55),(UNLOCK_A[kind],0x80),(UNLOCK_A[kind],0xAA),(UNLOCK_B[kind],0x55),(TARGET+(i*0x1000 if kind else 0),0x30)]
            assert [(int(x['address'],16),int(x['value'],16)) for x in m.writes[i*6:(i+1)*6]]==expected
        rows.append({'kind':kind,'length':length,'erase_commands':count,**res})
    m=machine(blob,0);m.regs[5]=0x10000;m.read_sequences[TARGET]=[0x20]
    res=execute(m,0x83CE8B02,TARGET)
    assert res['return']==0 and int(m.writes[-1]['value'],16)==0xF0
    return {'cases':rows,'failure_resets_read_mode':res}

def test_erase_outer(blob):
    rows=[]
    for address,length in ((0x180123,0x100),(0x180000,0x20000),(0x3F0123,0x2000),(0x3EE000,0x14000),(0x400000,0x10000)):
        m=machine(blob);calls=[]
        def init(m):pass
        def erase(m):calls.append(('erase',m.regs[4],m.regs[5]));m.regs[4]=1
        def blank(m):calls.append(('blank',m.regs[4],m.regs[5]));m.regs[4]=1
        m.regs[5]=length
        res=execute(m,0x83CE8954,address,hooks={0x83CE8658:init,0x83CE8B02:erase,0x83CE8A9E:blank})
        expected=[];a=address&~0xFFFF
        if address&0x3F0000==0x3F0000:a=address&~0x1FFF
        while a<address+length:
            size=0x2000 if a&0x3F0000==0x3F0000 else 0x10000
            expected.extend([('erase',a,size),('blank',a,size)]);a+=size
        assert calls==expected and res['return']==1
        rows.append({'address':hex(address),'length':hex(length),'calls':calls,**res})
    failures=[]
    for failure in ('erase','blank'):
        m=machine(blob);m.regs[5]=0x20000;calls=[]
        def erase(m):calls.append('erase');m.regs[4]=int(failure!='erase')
        def blank(m):calls.append('blank');m.regs[4]=int(failure!='blank')
        res=execute(m,0x83CE8954,TARGET,hooks={0x83CE8658:lambda m:None,0x83CE8B02:erase,0x83CE8A9E:blank})
        assert res['return']==0 and calls==(['erase'] if failure=='erase' else ['erase','blank'])
        failures.append({'failure':failure,'calls':calls,**res})
    return {'geometry_cases':rows,'failure_cases':failures,'scope':'Geometry and failure propagation real CPU; inner erase and blank verification separately tested, replaced here by recording hooks'}

def test_admission(blob):
    rows=[]
    for a,b,c,hw,flag,ready,osok in itertools.product((0,1),repeat=7):
        m=machine(blob)
        for addr,value in zip((0x83CE905E,0x83CE905A,0x83CE9054),(a,b,c)):m.store(addr,value,2)
        m.store(0x50000107,0x20 if hw else 0,1);m.store(0x83CE971E,0x40 if flag else 0,1);m.store(0x83CEB168,ready,1)
        def os(m):
            assert m.regs[12]==0xFFFFFF96
            m.syscalls.append({'code':hex(m.regs[12]),'args':m.regs[5:8]})
            m.regs[12]=0 if osok else 0xFFFFFFFF;m.regs[13]=0x20000000 if osok else 0
        res=execute(m,0xAB646,syscall=os)
        expected=not(a or b or c or hw or flag) and ready and osok
        assert bool(res['return'])==bool(expected)
        rows.append({'input_bits':[a,b,c,hw,flag,ready,osok],'accepted':bool(res['return'])})
    return {'input_order':['RAM905E_nonzero','RAM905A_nonzero','RAM9054_nonzero','MMIO107_bit5','RAM971E_bit6','RAMB168_nonzero','OS_poll_success'],'cases':rows,'scope':'Original AB646 and 40DDA executed. MMIO values and OS poll result supplied; physical meanings not all established.'}

def test_handshake(blob):
    rows=[]
    for ack,step,start in ((0,50,1000),(1,50,1000),(3,50,1000),(None,100,1000),(5,100,1000),(2,249,1000),(2,250,1000),(1,100,0xFFFFFFF0),(None,100,0xFFFFFFF0)):
        m=machine(blob);waits=0;commands=[];timeouts=[]
        m.read_sequences[0x68000114]=[(start+i*step)&0xFFFFFFFF for i in range(20)]
        def command(m):
            commands.append(m.regs[4])
            if ack==0:m.store(0x83CE9508,0x80,1)
        def os(m):
            nonlocal waits
            code=m.regs[12]
            if code==0xFFFFFF56:
                timeouts.append(m.regs[13]);waits+=1
                if waits==ack:m.store(0x83CE9508,0x80,1)
                m.regs[13]=0x4000
            else:assert code==0xFFFFFFD1
            m.regs[12]=0
        res=execute(m,0xAB9F8,hooks={0xA9A50:command},syscall=os)
        assert commands==[13]
        expected=ack is not None and ack*step<500
        assert bool(res['return'])==expected
        assert m.load(0x83CE950B,1)&0x80
        rows.append({'ack_after_wait':ack,'clock_step':step,'clock_start':hex(start),'waits':waits,'timeout_arguments':timeouts,'request_byte':hex(m.load(0x83CE950B,1)),**res})
    return {'cases':rows,'scope':'Original request/ack/time-budget logic and C13F2 clock accessor; external command consumer, OS waits and MMIO clock values modeled. Time unit not established.'}

def test_tail(blob):
    rows=[]
    for success,display in itertools.product((0,1),(0,1)):
        m=machine(blob);m.regs[8]=3 if success else 0;m.regs[10]=0x40040000;m.regs[11]=0x80048000
        m.store(0x83CEA3C4,0x20 if display else 0,1)
        m.map(0x83EB3A44,(0x82000000).to_bytes(4,'big'));m.map(0x82000000,bytes(0x200))
        for i in range(8):m.store(0x8200014C+i*2,i+1,2)
        delays=[]
        def delay(m):delays.append(m.regs[4])
        m.writes=[]
        res=execute(m,0x83CE8892,stop=0x83CE88DE,hooks={0x83CE8F8A:delay})
        assert m.load(0x50000106,1)&0x10
        assert bool(delays)==bool(success)
        serial=[w for w in m.writes if int(w['address'],16)==0x5000010B and int(w['value'],16)&1]
        if success:assert len(serial)==16
        else:assert not serial
        rows.append({'success':bool(success),'display_flag':display,'delay_arguments':delays,'serial_clock_high_count':len(serial),'terminal_pc':hex(m.pc),'MMIO_writes':m.writes,**res})
    return {'cases':rows,'scope':'Original success/failure tail including serial MMIO writes executed; delays are hooks, peripheral effects not modeled. Both reach terminal self-loop; no direct jump to B reset in this fragment.'}

def test_ack_consumer(blob):
    class TaskExit(Exception):pass
    rows=[]
    for request,ack in itertools.product((0,1),repeat=2):
        m=machine(blob);m.store(0x83CE950B,0x80 if request else 0,1);m.store(0x83CE9508,0x80 if ack else 0,1)
        m.store(0x50000106,0xFF,1);codes=[];exited=False
        def os(m):
            code=m.regs[12];codes.append(hex(code))
            if code==0xFFFFFFEB:raise TaskExit()
            assert code==0xFFFFFFD0
            m.regs[12]=0
        try:execute(m,0xAA1EC,syscall=os)
        except TaskExit:exited=True
        assert exited==bool(request and ack)
        assert m.load(0x50000106,1)==(0xEF if request and ack else 0xFF)
        rows.append({'request':request,'ack':ack,'OS_task_exit_called':exited,'MMIO106':hex(m.load(0x50000106,1)),'syscall_codes':codes})
    return {'cases':rows,'scope':'Original receive-side callback, OS event and task-exit modeled; receipt and transport of acknowledgement are not emulated'}

def test_recovery_evidence(blob):
    start,end=0xB0000,0xE0000
    assert set(blob[start:end])=={255}
    assert int.from_bytes(blob[0xAFFFC:0xB0000],'big')==0xC0F90
    assert int.from_bytes(blob[0xBFBC0:0xBFBC4],'big')==0xFFFFFFFF
    assert int.from_bytes(blob[0xBFFFC:0xC0000],'big')==0xFFFFFFFF
    return {'omitted_image_region':{'file_start':hex(start),'file_end_exclusive':hex(end),'bytes':end-start,'all_FF':True},
            'B_entry_vector':{'CPU':hex(0xEFFFC),'value':hex(0xC0F90)},
            'loader_metadata_reference':{'CPU':hex(0xFFBC0),'image_value':'0xffffffff','reader_CPU':'0xab6c8'},
            'scope':'Update-file padding does not establish physical flash contents. Separate writer covers CPU 0xf0000..0x120000, but invocation and recovery semantics are unresolved.'}

def verify(blob):
    assert hashlib.sha256(blob).hexdigest()==EXPECTED
    result={'base_sha256':EXPECTED,'camera_tested':False,'physical_flash_tested':False,'recovery_proven':False}
    for name,fn in [('identity',test_identity),('polling',test_poll),('program_word',test_program),('program_range',test_program_range),('blank_check',test_blank),('erase_commands',test_erase_commands),('erase_geometry',test_erase_outer),('admission',test_admission),('handshake',test_handshake),('tail',test_tail),('ack_consumer',test_ack_consumer),('recovery_evidence',test_recovery_evidence)]:
        result[name]=fn(blob);print(name+': PASS',flush=True)
    result['result']='PASS';return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('original_B');p.add_argument('--output',required=True);a=p.parse_args()
    report=verify(Path(a.original_B).read_bytes());Path(a.output).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if isinstance(v,(bool,str))},indent=2))

