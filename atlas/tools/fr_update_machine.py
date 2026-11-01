"""Bounded interpreter for D40 update research, derived from v7 ColorMachine.
New: ADDSP, byte BAND/BOR, explicit INT 0x40 models and current-PC tracing.
Not a full FR/REALOS or electrical flash emulator; see FLASH_LOWLEVEL_RU.md.
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


class UpdateMachine:
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

    def run(self, pc, arg=0, budget=150000, stop=None, hooks=None, syscall=None):
        self.regs[4] = arg
        rp = 0xdead0000
        pending = None
        r = self.regs
        for steps in range(budget):
            self.pc = pc
            if pc == 0xdead0000 or pc == stop:
                return steps
            if hooks and pc in hooks:
                hooks[pc](self)
                pc = rp
                continue
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
            elif high == 0x0f00:
                oldsp = r[15]; self.store(oldsp-4, r[14], 4)
                r[14] = oldsp-4; r[15] = oldsp - (w & 255)*4
            elif w == 0x9f90:
                r[15] = r[14]+4; r[14] = self.load(r[14], 4)
            elif high in (0x8e00, 0x8f00):
                base = 0 if high == 0x8e00 else 8
                for bit in range(8):
                    if w & (1 << bit):
                        r[15] -= 4; self.store(r[15], r[base+7-bit], 4)
            elif high in (0x8c00, 0x8d00):
                base = 0 if high == 0x8c00 else 8
                for bit in range(8):
                    if w & (1 << bit):
                        r[base+bit] = self.load(r[15],4); r[15] += 4
            elif w == 0x1781:
                r[15] -= 4; self.store(r[15], rp, 4)
            elif w == 0x0781:
                rp = self.load(r[15], 4); r[15] += 4
            elif w & 0xfff0 in (0x9700, 0x9f00, 0x9710, 0x9f10):
                target = r[i]
                if w & 0xfff0 in (0x9710, 0x9f10): rp = pc + (4 if w & 0x0800 else 2)
                if w & 0x0800: scheduled = target
                else: nextpc = target
            elif w & 0xf000 == 0xd000:
                target = pc + 2 + signed(w & 2047, 11)*2
                rp = pc + (4 if w & 0x0800 else 2)
                if w & 0x0800: scheduled = target
                else: nextpc = target
            elif high in (0x0300, 0x1300):
                addr = r[15]+j*4
                if high == 0x0300: r[i] = self.load(addr,4)
                else: self.store(addr,r[i],4)
            elif w & 0xf000 in (0x2000,0x3000,0x4000,0x5000,0x6000,0x7000):
                kind = w >> 12; size = {2:4,3:4,4:2,5:2,6:1,7:1}[kind]
                addr = (r[14]+signed(x,8)*size) & 0xffffffff
                if kind % 2 == 0: r[i] = self.load(addr,size)
                else: self.store(addr,r[i],size)
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
            elif high == 0xa300: r[15] = (r[15] + signed(w & 255,8)*4) & 0xffffffff
            elif high == 0xa400: r[i] = self.add(r[i], j)
            elif high == 0xa500: r[i] = self.add(r[i], j - 16)
            elif high == 0xa600: r[i] = self.add(r[i], r[j])
            elif high == 0xac00: r[i] = self.sub(r[i], r[j])
            elif high == 0xaa00: self.sub(r[i], r[j])
            elif high == 0xa800: self.sub(r[i], j)
            elif high == 0x8200: r[i] = self.nz(r[i] & r[j])
            elif high == 0x9200: r[i] = self.nz(r[i] | r[j])
            elif high == 0x9a00: r[i] = self.nz(r[i] ^ r[j])
            elif high in (0x8000,0x8100,0x9000,0x9100):
                value = self.load(r[i],1)
                if high == 0x8000: value &= 0xf0 | j
                elif high == 0x8100: value &= 0x0f | (j<<4)
                elif high == 0x9000: value |= j
                else: value |= j<<4
                self.store(r[i],value,1)  # NZVC are unchanged.
            elif w == 0x1f40:
                if syscall is None: raise RuntimeError('INT 0x40 requires explicit system-call model')
                syscall(self)
            elif high == 0x8900:
                # FR manual CM71-00101-5E, 7.33: BTSTH. V/C unchanged.
                value = self.load(r[i], 1) & (j << 4)
                self.n, self.z = bool(value & 0x80), value == 0
            elif high in (0xb000,0xb100): r[i] = self.nz(r[i] >> (j + (16 if high == 0xb100 else 0)))
            elif high == 0xb200:
                # FR manual 7.47: register count uses its lower five bits.
                shift = r[j] & 31
                self.c = bool((r[i] >> (shift-1)) & 1) if shift else False
                r[i] = self.nz(r[i] >> shift)
            elif high == 0xb500: r[i] = self.nz(r[i] << (j+16))
            elif high == 0xb900: r[i] = self.nz(signed(r[i]) >> (j+16))
            elif high == 0xb400: r[i] = self.nz(r[i] << j)
            elif high == 0xb800: r[i] = self.nz(signed(r[i]) >> j)
            elif high in (0xaf00,0xab00):
                self.mdl = (signed(r[i]) * signed(r[j])) & 0xffffffff
            elif w & 0xfff0 == 0xb750: r[i] = self.mdl
            elif w & 0xfff0 == 0x9780: r[i] = signed(r[i], 8) & 0xffffffff
            elif w & 0xfff0 == 0x97b0: r[i] &= 65535
            elif w & 0xfff0 == 0x97a0: r[i] = signed(r[i],16) & 0xffffffff
            elif w & 0xfff0 == 0x9790: r[i] &= 255
            elif w == 0x9fa0: pass
            elif w & 0xf000 in (0xe000, 0xf000):
                cond = (w >> 8) & 15
                conditions = {0:True, 2:self.z, 3:not self.z,
                              4:self.c, 5:not self.c,
                              6:self.n, 7:not self.n,
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

