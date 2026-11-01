"""Bounded execution of original D40 B 1.11 instructions, in host memory only.

Exercises the journal scanner and two curve expansion routines. The interpreter
implements only their observed instruction subset, rejects unmapped access and
unknown instructions, and does not emulate flash hardware, the OS or a camera.
"""
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

EXPECTED = 'b9df48d461e875dce4ba84da88164af170dfc48ad9f7674859623bad0401032e'


def signed(x, bits=32):
    x &= (1 << bits) - 1
    return x - (1 << bits) if x >> (bits - 1) else x


class Machine:
    def __init__(self, blob):
        if hashlib.sha256(blob).hexdigest() != EXPECTED:
            raise ValueError('Unsupported firmware')
        self.blob = blob
        self.regs = [0] * 16
        self.regs[15] = 0x10001000
        self.regions = []
        self.map(0x10000000, bytes(0x2000))
        self.z = self.n = self.v = self.c = False
        self.mdl = 0

    def map(self, address, data):
        if any(address < a + len(b) and a < address + len(data) for a, b in self.regions):
            raise ValueError('Overlapping test memory')
        self.regions.append((address, bytearray(data)))

    def load(self, address, size):
        for a, b in self.regions:
            if a <= address and address + size <= a + len(b):
                return int.from_bytes(b[address-a:address-a+size], 'big')
        if 0x40000 <= address and address + size <= 0x40000 + len(self.blob):
            return int.from_bytes(self.blob[address-0x40000:address-0x40000+size], 'big')
        raise RuntimeError(f'Unmapped read {address:#x}/{size}')

    def store(self, address, value, size):
        for a, b in self.regions:
            if a <= address and address + size <= a + len(b):
                b[address-a:address-a+size] = (value & ((1 << (8*size))-1)).to_bytes(size, 'big')
                return
        raise RuntimeError(f'Unmapped write {address:#x}/{size}')

    def nz(self, value):
        self.z = (value & 0xffffffff) == 0
        self.n = bool(value & 0x80000000)
        return value & 0xffffffff

    def add(self, a, b):
        b &= 0xffffffff
        value = (a + b) & 0xffffffff
        self.c = a + b > 0xffffffff
        self.v = bool((~(a ^ b) & (a ^ value)) & 0x80000000)
        return self.nz(value)

    def sub(self, a, b):
        value = (a - b) & 0xffffffff
        self.c = a < b
        self.v = bool(((a ^ b) & (a ^ value)) & 0x80000000)
        return self.nz(value)

    def run(self, pc, arg, budget=100000):
        self.regs[4] = arg
        rp = 0xdead0000
        pending = None
        r = self.regs
        for steps in range(budget):
            if pc == rp:
                return steps
            w = self.load(pc, 2)
            i, j, x = w & 15, (w >> 4) & 15, (w >> 4) & 255
            high = w & 0xff00
            nextpc, scheduled = pc + 2, None
            if w & 0xfff0 == 0x9f80:
                r[i] = self.load(pc+2, 4); nextpc = pc + 6
            elif high == 0x9b00:
                r[i] = (j << 16) | self.load(pc+2, 2); nextpc = pc + 4
            elif w & 0xf000 == 0xc000: r[i] = x
            elif high == 0x8b00: r[i] = r[j]
            elif high in (0x0400, 0x0500, 0x0600):
                r[i] = self.load(r[j], {0x0400:4, 0x0500:2, 0x0600:1}[high])
            elif high in (0x0000, 0x0100, 0x0200):
                r[i] = self.load((r[13]+r[j]) & 0xffffffff, {0x0000:4, 0x0100:2, 0x0200:1}[high])
            elif high in (0x1400, 0x1500, 0x1600):
                self.store(r[j], r[i], {0x1400:4, 0x1500:2, 0x1600:1}[high])
            elif high in (0x1000, 0x1100, 0x1200):
                self.store((r[13]+r[j]) & 0xffffffff, r[i], {0x1000:4, 0x1100:2, 0x1200:1}[high])
            elif w & 0xfff0 == 0x1700:
                r[15] -= 4; self.store(r[15], r[i], 4)
            elif w & 0xfff0 == 0x0700:
                r[i] = self.load(r[15], 4); r[15] += 4
            elif high == 0xa400: r[i] = self.add(r[i], j)
            elif high == 0xa500: r[i] = self.add(r[i], j - 16)
            elif high == 0xa600: r[i] = self.add(r[i], r[j])
            elif high == 0xac00: r[i] = self.sub(r[i], r[j])
            elif high == 0xaa00: self.sub(r[i], r[j])
            elif high == 0xa800: self.sub(r[i], j)
            elif high == 0x8200: r[i] = self.nz(r[i] & r[j])
            elif high == 0xb400: r[i] = self.nz(r[i] << j)
            elif high == 0xb800: r[i] = self.nz(signed(r[i]) >> j)
            elif high == 0xaf00:
                self.mdl = (signed(r[i]) * signed(r[j])) & 0xffffffff
            elif w & 0xfff0 == 0xb750: r[i] = self.mdl
            elif w & 0xfff0 == 0x9780: r[i] = signed(r[i], 8) & 0xffffffff
            elif w & 0xfff0 == 0x97b0: r[i] &= 65535
            elif w & 0xf000 in (0xe000, 0xf000):
                cond = (w >> 8) & 15
                conditions = {0:True, 2:self.z, 3:not self.z,
                              4:self.c, 5:not self.c,
                              10:self.n != self.v, 11:self.n == self.v,
                              12:self.z or self.n != self.v,
                              13:not self.z and self.n == self.v,
                              14:self.c or self.z, 15:not self.c and not self.z}
                if cond not in conditions: raise RuntimeError(f'Unknown branch {w:04x}')
                target = pc + 2 + signed(w, 8)*2
                if w & 0xf000 == 0xf000:
                    scheduled = target if conditions[cond] else pc + 4
                elif conditions[cond]: nextpc = target
            elif w == 0x9f20: scheduled = rp
            elif w == 0x9720: nextpc = rp
            else: raise RuntimeError(f'Unsupported instruction {w:04x} at {pc:08x}')
            pc = pending if pending is not None else nextpc
            pending = scheduled
        raise RuntimeError('Instruction budget exceeded')


def expand_reference(samples):
    result = []
    for a, b in zip(samples, samples[1:]):
        result += [a, (a+b)//2]
    return result + [samples[-1]]*2


def check_curves(blob):
    rng = random.Random(2383)
    fallback = list(struct.unpack_from('>2048H', blob, 0x9c294))
    cases = [[0]*2048, [4095]*2048, [2*i for i in range(2048)],
             [0, 4095]*1024, [rng.randrange(4096) for _ in range(2048)],
             [rng.randrange(65536) for _ in range(2048)]]
    count = 0
    for entry in (0x4bf06, 0x4bf58):
        for flags in ((0, 0), (1, 0), (0, 1), (1, 1)):
            for samples in cases:
                m = Machine(blob)
                data = bytes(flags) + bytes(0x42) + struct.pack('>2048H', *samples)
                m.map(0x83e89310, data)
                m.map(0x20000000, bytes([0xa5])*(0x2000+32))
                original = bytes(m.regions[1][1])
                m.run(entry, 0x20000010)
                expected = expand_reference(samples if all(flags) else fallback)
                actual = [m.load(0x20000010+2*i, 2) for i in range(4096)]
                assert actual == expected
                assert m.load(0x20000000, 16) == int.from_bytes(bytes([0xa5])*16, 'big')
                assert m.load(0x20002010, 16) == int.from_bytes(bytes([0xa5])*16, 'big')
                assert bytes(m.regions[1][1]) == original
                count += 1
    return count


def check_journal(blob):
    lengths = [struct.unpack_from('>H', blob, 0x95368+8*i)[0] for i in range(12)]
    def record(slot, payload):
        return struct.pack('>HH', slot, len(payload)) + payload + bytes(len(payload) % 2)
    def mark(seq): return struct.pack('>HH', 0xaa55, seq)
    initial = record(2, bytes([0x21])*lengths[2])
    update = record(2, bytes([0x42])*lengths[2])
    # Values expected at each slot refer to the last committed checkpoint only.
    cases = [
        ('erased', b'', {}, None),
        ('uncommitted', initial, {}, None),
        ('one_commit', initial+mark(10), {2:4}, 10),
        ('uncommitted_tail', initial+mark(10)+update, {2:4}, 10),
        ('two_commits', initial+mark(10)+update+mark(11), {2:len(initial)+8}, 11),
        ('wrong_length', initial+mark(10)+record(2,b'bad')+mark(11), {2:4}, 11),
        ('invalid_id', initial+mark(10)+record(12,b'')+mark(11), {2:4}, 10),
        ('sequence_ffff', initial+mark(0xffff), {2:4}, 0xffff),
        ('empty_commit', mark(0), {}, 0),
    ]
    all_records, pointers = b'', {}
    for i, n in enumerate(lengths):
        pointers[i] = len(all_records) + 4
        all_records += record(i, bytes([i])*n)
    cases.append(('all_12_slots', all_records+mark(17), pointers, 17))
    count = 0
    for index, base in enumerate((0x180000, 0x190000)):
        for name, data, expected, seq in cases:
            m = Machine(blob)
            m.map(base, data + bytes([0xff])*(0x10000-len(data)))
            m.map(0x83cea3ec, bytes(0xc0))
            m.regs[10] = 0x12345678
            m.run(0x6b654, index)
            assert m.regs[10] == 0x12345678, name
            assert m.regs[15] == 0x10001000, name
            for slot in range(12):
                actual = m.load(0x83cea424+index*0x30+slot*4, 4)
                want = base+expected[slot] if slot in expected else 0
                assert actual == want, (name, slot, hex(actual), hex(want))
            assert m.load(0x83cea4a0+index, 1) == int(seq is not None), name
            if seq is not None:
                assert m.load(0x83cea484+index*2, 2) == seq, name
            count += 1
    return count


if __name__ == '__main__':
    blob = Path(sys.argv[1]).read_bytes()
    result = {'curve_original_code_executions':check_curves(blob),
              'journal_scanner_original_code_executions':check_journal(blob),
              'result':'PASS', 'camera_connected':False, 'firmware_modified':False,
              'scope':'Synthetic host memory; no flash erase/program, image sensor, JPEG or power-loss hardware tests'}
    print(json.dumps(result, indent=2))
