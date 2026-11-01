"""Fujitsu FR (big endian) instruction decoder with control-flow metadata.

Opcode descriptions: fr_opcodes.json, derived from Kevin Schoedel's DFR
(see THIRD_PARTY.txt). The decoder itself is independent code.
"""
import json
from pathlib import Path

_OPS = [op for op in json.loads((Path(__file__).parent / 'fr_opcodes.json').read_text())
        if op[2] != 'W']
LUT = [None] * 65536
for _op in reversed(_OPS):
    _val, _mask = _op[0], _op[1]
    free = (~_mask) & 0xFFFF
    # enumerate all words matching value/mask
    sub = free
    while True:
        LUT[_val | sub] = _op
        if sub == 0:
            break
        sub = (sub - 1) & free

SPECIAL = ['TBR', 'RP', 'SSP', 'USP', 'MDH', 'MDL']
COND_BR = {'BC', 'BNC', 'BEQ', 'BNE', 'BN', 'BP', 'BV', 'BNV', 'BLT', 'BGE',
           'BLE', 'BGT', 'BLS', 'BHI'}
# mnemonics whose last register operand is a source, not a destination
NO_DEST = {'ST', 'STB', 'STH', 'CMP', 'CMP2', 'BTSTH', 'BTSTL', 'AND', 'OR', 'EOR',
           'ANDB', 'ORB', 'EORB', 'ANDH', 'ORH', 'EORH', 'BANDH', 'BANDL', 'BORH',
           'BORL', 'BEORH', 'BEORL', 'PUSH', 'STM0', 'STM1', 'DMOV', 'DMOVB',
           'DMOVH', 'COPST', 'COPSV', 'JMP', 'JMP:D', 'CALL', 'CALL:D', 'DIV0S',
           'DIV0U', 'DIV1', 'DIV2', 'MUL', 'MULU', 'MULH', 'MULUH', 'STRES'}


def signed(v, bits):
    return v - (1 << bits) if bits and v & (1 << (bits - 1)) else v


class Insn:
    __slots__ = ('addr', 'size', 'name', 'ops', 'flow', 'target', 'delay',
                 'imm', 'reg_i', 'reg_j', 'dest', 'word', 'direct')

    def __repr__(self):
        return f'{self.addr:08x} {self.name} {self.ops}'


def decode(read, addr):
    """read(addr, n) -> bytes or None. Returns Insn or None if invalid/unmapped."""
    b = read(addr, 2)
    if b is None or len(b) < 2:
        return None
    w = int.from_bytes(b, 'big')
    op = LUT[w]
    if op is None:
        return None
    _, _, typ, name, fmt = op
    i, j, x, bits, n, c = w & 15, (w >> 4) & 15, 0, 0, 2, 0
    if typ == 'B':
        x, bits = (w >> 4) & 255, 8
    elif typ == 'C':
        x, bits = j, 4
    elif typ == 'D':
        x, bits = w & 255, 8
    elif typ == 'F':
        x, bits = w & 2047, 11
    if name in ('LSL2', 'LSR2', 'ASR2'):
        name = name[:-1]
        x += 16
        bits += 1
    ins = Insn()
    ins.addr, ins.word = addr, w
    ins.target = ins.imm = ins.dest = ins.direct = None
    out = []
    for ch in fmt.split(';')[0]:
        if ch == 'X':
            e = read(addr + n, 2)
            if e is None or len(e) < 2:
                return None
            x = (x << 16) | int.from_bytes(e, 'big')
            bits += 16
            n += 2
        elif ch == 'Y':
            e = read(addr + n, 2)
            if e is None or len(e) < 2:
                return None
            v = int.from_bytes(e, 'big')
            n += 2
            x, bits, c, j, i = i, 4, v >> 8, (v >> 4) & 15, v & 15
        elif ch in '24':
            sh = 1 if ch == '2' else 2
            x <<= sh
            bits += sh
        elif ch == 'b':
            x += 16
            bits += 1
        elif ch == 'r':
            x = (addr + 2 + signed(x, bits)) & 0xFFFFFFFF
            bits = 32
            ins.target = x
        elif ch == 'u':
            out.append(hex(x))
            ins.imm = x
        elif ch == 'd':
            out.append(str(x))
            ins.imm = x
        elif ch == 's':
            out.append(str(signed(x, bits)))
            ins.imm = signed(x, bits)
        elif ch == 'n':
            out.append(str(x - (1 << bits)))
            ins.imm = x - (1 << bits)
        elif ch == 'q':
            h = bits // 2
            m = (1 << h) - 1
            out.append(f'{(x >> h) & m}/{x & m}')
        elif ch == 'i':
            out.append(f'r{i}')
        elif ch == 'j':
            out.append(f'r{j}')
        elif ch == 'g':
            out.append(SPECIAL[i] if i < 6 else f'special{i}')
        elif ch == 'h':
            out.append(SPECIAL[j] if j < 6 else f'special{j}')
        elif ch == 'k':
            out.append(f'cr{i}')
        elif ch == 'l':
            out.append(f'cr{j}')
        elif ch == 'c':
            out.append(hex(c))
        elif ch in 'AFPSCM':
            out.append({'A': 'r13', 'F': 'r14', 'P': 'PS', 'S': 'r15', 'C': 'CCR',
                        'M': 'ILM'}[ch])
        elif ch == '&':
            out.append('+')
        elif ch == 'x':
            x |= 0x100
        elif ch in 'yz':
            start = 8 if ch == 'y' else 0
            regs = [start + (7 - k if x & 0x100 else k) for k in range(8) if x & (1 << k)]
            out.append('(' + ','.join(f'r{k}' for k in regs) + ')')
        else:
            out.append(ch)
    ins.size = n
    ins.name = name
    ins.ops = ''.join(out)
    ins.reg_i, ins.reg_j = i, j
    ins.delay = name.endswith(':D')
    base = name[:-2] if ins.delay else name
    if base == 'BRA':
        ins.flow = 'jump'
    elif base in COND_BR:
        ins.flow = 'cjump'
    elif base == 'BNO':
        ins.flow = 'seq'
        ins.target = None
    elif base == 'JMP':
        ins.flow = 'ijump'
    elif base == 'CALL':
        ins.flow = 'call' if ins.target is not None else 'icall'
    elif base in ('RET', 'RETI'):
        ins.flow = 'ret'
    elif base == 'INT':
        ins.flow = 'int'
    else:
        ins.flow = 'seq'
    # destination register (general register written by plain register ops)
    if ins.flow == 'seq' and base not in NO_DEST:
        last = ins.ops.rsplit(',', 1)[-1] if ins.ops else ''
        if last.startswith('r') and last[1:].isdigit():
            ins.dest = int(last[1:])
        elif base in ('LDM0', 'LDM1', 'POP'):
            ins.dest = -1  # multiple / unknown
    # direct (I/O-space) address operands for D-type direct addressing
    if typ == 'D' and base in ('DMOV', 'DMOVH', 'DMOVB', 'LD', 'LDUH', 'LDUB', 'ST',
                               'STUH', 'STUB') and '@' in ins.ops:
        ins.direct = ins.imm
    return ins
