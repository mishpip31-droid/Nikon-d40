"""D40 A 1.12 task 5, startup data and task activation research.
Original CPU code, explicit serial-transfer / OS / delay / remainder models.
No camera access. Usage: python check_a_memory.py AD400112.bin result.json
"""
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

from fr_task_machine import TaskMachine

SHA = '0cc92921d6b2ad5d5cfa070abeebdd9aaca224d326e42a26339e3ac384270394'


def machine(blob):
    assert hashlib.sha256(blob).hexdigest() == SHA
    m = TaskMachine(blob)
    m.map(0x30000, bytes(0x10000))
    m.map(0, bytes(0x2000))
    return m


def put(m, address, data):
    for i, v in enumerate(data):
        m.store(address+i, v, 1)


class MemoryTask:
    """One task-5 iteration. Serial calls return synchronously by explicit model.

    Memory is an abstract 15-bit address window, NOT a chip capacity assertion.
    No EEPROM electrical timing, persistence, write endurance or DMA simulation.
    """
    def __init__(self, blob, status=None, backing=None, clobber=False):
        self.m = machine(blob)
        self.memory = bytearray(backing if backing is not None else bytes(0x8000))
        self.status = iter(status or [])
        self.trace = []
        self.command = None
        self.pending_write_address = None
        self.status_reads = 0
        self.delays = []
        self.events = []
        self.model_remainder_calls = 0
        self.clobber = clobber

    def clobber_scratch(self, m):
        if self.clobber:
            for i in list(range(8)) + [12, 13]:
                m.regs[i] = (0xA5310000 + i * 0x1111) & 0xFFFFFFFF
            m.n = m.z = m.v = m.c = True

    def tx(self, m):
        p, n = m.regs[4:6]
        data = bytes(m.load(p+i, 1) for i in range(n))
        self.trace.append(dict(kind='tx', hex=data.hex(), n=n))
        if self.pending_write_address is not None:
            address = self.pending_write_address
            assert (address & 31) + n <= 32
            for i, b in enumerate(data):
                self.memory[(address+i) & 0x7FFF] = b
            self.trace[-1]['address'] = address
            self.pending_write_address = None
        else:
            assert data
            self.command = data[0]
            if self.command in (2, 3):
                assert n == 3
                self.address = int.from_bytes(data[1:3], 'big')
                if self.command == 2:
                    self.pending_write_address = self.address
        self.clobber_scratch(m)

    def rx(self, m):
        p, n = m.regs[4:6]
        if self.command == 5:
            assert n == 1
            data = bytes([next(self.status, 0)])
            self.status_reads += 1
        elif self.command == 3:
            data = bytes(self.memory[(self.address+i) & 0x7FFF] for i in range(n))
        else:
            raise AssertionError(('Unexpected receive command', self.command))
        put(m, p, data)
        self.trace.append(dict(kind='rx', n=n, command=self.command,
                              hex=data.hex() if n < 17 else None))
        self.clobber_scratch(m)

    def delay(self, m):
        self.delays.append(m.regs[4])  # abstract units, no elapsed time asserted
        self.clobber_scratch(m)

    def remainder(self, m):
        a, b = m.regs[4:6]
        assert 0 <= a <= 65535 and b == 32
        # Original F22B4 is DIV0S + 32 DIV1 + DIV2/3/4S, returning MDH.
        # This arithmetic helper is modeled, NOT instruction-executed.
        m.regs[4] = a % b
        self.model_remainder_calls += 1

    def syscall(self, m):
        code = m.regs[12] & 255
        if code == 0xC3:
            assert m.regs[5] == 1
            m.regs[13] = 0x3C600
        elif code == 0xD2:
            assert m.regs[5:8] == [2, 0x4000, 2]
            m.regs[13] = 0x4000
        elif code == 0xD1:
            assert m.regs[4:6] == [2, 0xFFFFBFFF]
        elif code == 0xD0:
            self.events.append((m.regs[4], m.regs[5]))
        else:
            raise AssertionError(('Unexpected syscall', hex(m.pc), hex(code)))
        m.regs[12] = 0

    def run(self, address, length, read=False, buffer=0x3C800, complete=0x2000, payload=None):
        m = self.m
        if payload is not None:
            put(m, buffer, payload)
        req = struct.pack('>IIHHHH', 0, 0, (address & 0x7FFF) | (0x8000 if read else 0),
                          buffer & 0xFFFF, length, complete)
        put(m, 0x3C600, req)
        hooks = {0xD4938:self.tx, 0xD49F4:self.rx, 0xD4B0C:self.rx,
                 0xD4842:self.delay, 0xF22B4:self.remainder}
        self.steps = m.run(0xD4622, stop=0xD46C4, hooks=hooks, syscall=self.syscall)
        assert self.events == [(2, 0x4000), (3, complete)]
        assert m.load(0x3CC40, 4) == 0
        return bytes(m.load(buffer+i, 1) for i in range(length))


def startup_data(blob, backing, initial_flags=0):
    """CPU caller C1164+C11A4+C1214 with serialized mailbox/event model.
    Model transfers one request through a separate task-5 CPU instance, then
    copies its read result into the caller. This is not concurrent scheduling.
    """
    m = machine(blob)
    m.store(0x3CC9B, initial_flags, 1)
    requests = []
    worker = None

    def syscall(cpu):
        nonlocal worker
        code = cpu.regs[12] & 255
        if code == 0xD1:
            assert cpu.regs[4:6] == [3, 0xFFFFDFFF]
        elif code == 0xC1:
            assert cpu.regs[4] == 1
            p = cpu.regs[5]
            raw = bytes(cpu.load(p+i, 1) for i in range(16))
            requests.append(raw.hex())
            _, _, address, dest, length, completion = struct.unpack('>IIHHHH', raw)
            assert (address, dest, length, completion) == (0x8000, 0xC000, 0x400, 0x2000)
            worker = MemoryTask(blob, backing=backing)
            data = worker.run(address, length, read=True, buffer=dest | 0x30000, complete=completion)
            put(cpu, dest | 0x30000, data)
        elif code == 0xD2:
            assert cpu.regs[5:8] == [3, 0x2000, 2]
            assert worker is not None
            cpu.regs[13] = 0x2000
        else:
            raise AssertionError(hex(code))
        cpu.regs[12] = 0

    oldsp = m.regs[15]
    steps = m.run(0xC1164, syscall=syscall)
    assert m.regs[15] == oldsp
    assert m.load(0x3C000, 1024).to_bytes(1024, 'big') == backing[:1024]
    part = backing[:0x380]
    expected = initial_flags & ~0x30
    if not any(part): expected |= 0x20
    if all(v == 255 for v in part): expected |= 0x10
    if (expected & 0x30) or sum(part) % 256: expected |= 0x40
    assert m.load(0x3CC9B, 1) == expected
    return dict(flags=expected, sum_mod256=sum(part) % 256, steps=steps, request=requests[0])


def main():
    blob = Path(sys.argv[1]).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    report = dict(version=10, firmware_sha256=SHA, result='PASS', hardware_tests=0,
        models=['serial send and receive/DMA replacement', 'instant abstract memory writes',
                'explicit status bytes', 'immediate OS mailbox/event success',
                'delay logging with no time unit', 'nonnegative remainder-by-32 helper'],
        limits=['No physical chip identification, EEPROM capacity or hardware persistence proof',
                'No A/B protocol or complete task scheduler reconstructed'])
    write_cases = 0
    example = None
    for offset in range(32):
        for length in (0, 1, 2, 31, 32, 33, 63, 64, 65, 257):
            address = 0x100 + offset
            payload = bytes((i * 17 + 5) & 255 for i in range(length))
            t = MemoryTask(blob)
            t.run(address, length, payload=payload)
            assert t.memory[address:address+length] == payload
            chunks = [(x['address'], x['n']) for x in t.trace if 'address' in x]
            left, addr, expected = length, address, []
            while left:
                size = min(left, 32 - (addr & 31))
                expected.append((addr, size)); addr += size; left -= size
            assert chunks == expected
            if length:
                assert t.trace[-1]['kind'] == 'tx' and 'address' in t.trace[-1]
            assert not (t.m.load(0x3E24D,1) & 0x40)
            write_cases += 1
            if offset == 31 and length == 65:
                example = dict(address=address, length=length, chunks=chunks, trace=t.trace, events=t.events)
    report['write_boundary_cases'] = write_cases
    report['write_example'] = example
    backing = bytes((i * 23 + 19) & 255 for i in range(0x8000))
    read_cases = 0
    for address in (0, 31, 255, 1023):
        for n in (1, 32, 33, 1024):
            t = MemoryTask(blob, backing=backing)
            assert t.run(address, n, read=True) == backing[address:address+n]
            read_cases += 1
    report['read_cases'] = read_cases
    # Ensure transfer models do not succeed only because they preserve scratch registers.
    for read in (False, True):
        for address in (0,31,32):
            for n in (1,33,65,257):
                t=MemoryTask(blob,backing=backing,clobber=True)
                payload=bytes((i+7)&255 for i in range(n))
                got=t.run(address,n,read=read,payload=payload)
                if read: assert got==backing[address:address+n]
                else: assert t.memory[address:address+n]==payload
    report['scratch_clobber_cases']=24
    report['busy_boundary'] = []
    for busy_count in range(7):
        t = MemoryTask(blob, status=[1]*busy_count + [0])
        t.run(0, 1, read=True)
        error = bool(t.m.load(0x3E24D,1) & 0x40)
        assert error == (busy_count >= 5)
        assert t.status_reads == min(busy_count+1, 6)
        assert len(t.delays) == min(busy_count, 6)
        report['busy_boundary'].append(dict(busy_samples=busy_count, samples=t.status_reads,
                  delays=t.delays, error=error, completion_events=t.events))
    # Decode all possible one-byte status responses in the original D47CA.
    for status in range(256):
        t = MemoryTask(blob, status=[status])
        t.m.run(0xD47CA, hooks={0xD4938:t.tx,0xD49F4:t.rx})
        value = t.m.load(0x3E24D, 1)
        assert value & 0xA0 == (0x80 if status & 1 else 0) | (0x20 if status & 0x8C else 0)
    report['status_decode_cases'] = 256
    # Follow original task-1 startup data path with valid, damaged and blank data.
    rng = random.Random(33010)
    block = bytearray(rng.randrange(256) for _ in range(0x8000))
    block[0x37F] = -sum(block[:0x37F]) & 255
    report['startup_examples'] = {'valid':startup_data(blob, block),
        'all_zero':startup_data(blob, bytes(0x8000)),
        'all_ff':startup_data(blob, b'\xff'*0x8000),
        'valid_with_existing_error':startup_data(blob, block, 0x40)}
    checksum_cases = 4
    for index in list(range(0, 0x380, 17)) + [0x37F, 0x380, 0x3FF]:
        damaged = bytearray(block); damaged[index] ^= 1
        x = startup_data(blob, damaged)
        assert bool(x['flags'] & 0x40) == (index < 0x380)
        checksum_cases += 1
    report['startup_checksum_cases'] = checksum_cases
    # Task 1 helper executes directly; C371=0 keeps unrelated conditional branch inactive.
    activation = []
    for flag in (0,8):
        m = machine(blob); m.store(0x3CC9A,flag,1); starts=[]
        def sys_start(cpu):
            assert cpu.regs[12] & 255 == 0xE9
            starts.append(cpu.regs[4:6]); cpu.regs[12]=0
        sp = m.regs[15]
        m.run(0xC137C, syscall=sys_start)
        assert m.regs[15] == sp
        assert starts == [[10,0],[9,0x101],[4,0xFFFFFF01]] + ([[2,0]] if flag else [])
        activation.append(dict(initial_3cc9a=flag, starts=starts))
    report['task1_activation_cases'] = activation
    m=machine(blob);gate_calls=[]
    def gate_syscall(cpu):
        code=cpu.regs[12]&255
        assert code in (0xD0,0xD1)
        gate_calls.append([code,cpu.regs[4],cpu.regs[5]])
        cpu.regs[12]=0
    m.run(0xC0F1E,stop=0xC0F6E,syscall=gate_syscall)
    assert gate_calls==[[0xD1,4,0xFFFFDFFF],[0xD1,9,0xFFFFFE1F],
                        [0xD0,2,0x4000],[0xD0,6,0x1000],[0xD0,9,0x10]]
    report['task1_startup_gate']=gate_calls
    # Resolve the actually selected INT40 dispatch entries in A 1.12.
    assert int.from_bytes(blob[0x3FEFC:0x3FF00],'big')==0xFEECC
    targets={0xC1:0xFF9D0,0xC3:0xFFA22,0xD0:0xFF836,0xD1:0xFF8C6,
             0xD2:0xFF8EE,0xD9:0xFF486,0xDA:0xFF44E,0xE9:0xFF544}
    report['syscall_dispatch']={}
    for code,target in targets.items():
        address=0xFEEC4+2*(code-256)
        actual=0xFEEC4+struct.unpack_from('>h',blob,address-0xC0000)[0]
        assert actual==target
        report['syscall_dispatch'][hex(code)]=dict(table_cpu=address,handler_cpu=actual)
    # Standalone original byte-transfer callback: external byte-completion
    # events are injected by this loop, not delivered by an interrupt controller.
    callback_cases=0
    for receive in (False,True):
        for n in (1,2,31,32,33,255,1024):
            m=machine(blob);buf=0x3C800
            payload=bytes((i*29+3)&255 for i in range(n))
            put(m,buf,bytes(n) if receive else payload)
            m.store(0x3D514,buf,4);m.store(0x3D518,n,2)
            m.store(0x3E24D,8 if receive else 0,1)
            wake=[];transmitted=[payload[0]]
            def wakeup(cpu):
                assert cpu.regs[12]&255==0xD9 and cpu.regs[4]==5
                wake.append(5);cpu.regs[12]=0
            sp=m.regs[15]
            for i in range(n):
                m.store(0xBB,payload[i] if receive else 0,1)
                m.run(0xD4A5E,syscall=wakeup)
                assert m.regs[15]==sp
                assert m.load(0x3D518,2)==n-i-1
                assert len(wake)==int(i==n-1)
                if not receive and i<n-1:transmitted.append(m.load(0xBB,1))
            assert m.load(0x3D514,4)==buf+n-1
            if receive:assert m.load(buf,n).to_bytes(n,'big')==payload
            else:assert bytes(transmitted)==payload
            callback_cases+=1
    report['byte_callback_cases']=callback_cases
    # Hardware transfer setup is executed, but transfer/sleep completion is not.
    for n in (0,1,32,33,1024):
        m=machine(blob);m.regs[5]=n;sleeps=[]
        def sleep(cpu):
            assert cpu.regs[12]&255==0xDA
            sleeps.append(cpu.pc);cpu.regs[12]=0
        sp=m.regs[15];m.run(0xD4B0C,arg=0x3C800,syscall=sleep)
        assert m.regs[15]==sp and sleeps==[0xD4BA0]
        assert m.load(0x218,4)==0x92010000+n
        assert m.load(0x210,4)==0x95010000+n
        assert m.load(0x1018,4)==0xBB and m.load(0x101C,4)==0x3C800
        assert m.load(0x3CC58,4)==0xD4BA8
    report['hardware_transfer_setup_cases']=5
    # BTSTL flags are independently checked for every byte and all V/C pairs.
    for byte in range(256):
        for flags in range(4):
            m = machine(blob);m.store(0x3CC9A,byte,1);m.regs[8]=0x3CC9A
            m.n=True;m.z=False;m.v=bool(flags&1);m.c=bool(flags&2)
            m.run(0xC13A8,stop=0xC13AA)
            assert (m.n,m.z,m.v,m.c)==(False,not bool(byte&8),bool(flags&1),bool(flags&2))
            assert m.load(0x3CC9A,1)==byte
    report['btstl_cases']=1024
    out=Path(sys.argv[2]);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k.endswith('_cases') and isinstance(v,int)}))


if __name__=='__main__':
    main()
