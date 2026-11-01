"""Small FR big-endian listing helper; not an emulator or code/data classifier.
Opcode descriptions derive from Kevin Schoedel's DFR; see THIRD_PARTY.txt.
"""
import json
from pathlib import Path

OPS = json.loads((Path(__file__).parent / 'fr_opcodes.json').read_text())
LUT = [None] * 65536
for op in reversed(OPS):
    for w in range(op[0], op[0] + ((~op[1]) & 65535) + 1):
        if w & op[1] == op[0]:
            LUT[w] = op

def signed(v, bits):
    return v - (1 << bits) if bits and v & (1 << (bits - 1)) else v

def decode(b, off, base=0x40000):
    w = int.from_bytes(b[off:off+2], 'big')
    op = LUT[w]
    if op is None:
        return 2, '.hword', f'0x{w:04x}'
    _, _, typ, name, fmt = op
    i, j, x, bits, n, c = w & 15, (w >> 4) & 15, 0, 0, 2, 0
    if typ == 'B': x, bits = (w >> 4) & 255, 8
    elif typ == 'C': x, bits = j, 4
    elif typ == 'D': x, bits = w & 255, 8
    elif typ == 'F': x, bits = w & 2047, 11
    elif typ == 'W': x, bits = w, 16
    if name in ('LSL2','LSR2','ASR2'):
        name = name[:-1]; x += 16; bits += 1
    out = ''
    special = ['TBR', 'RP', 'SSP', 'USP', 'MDH', 'MDL']
    for ch in fmt.split(';')[0]:
        if ch == 'X':
            x = (x << 16) | int.from_bytes(b[off+n:off+n+2], 'big'); bits += 16; n += 2
        elif ch == 'Y':
            v = int.from_bytes(b[off+n:off+n+2], 'big'); n += 2
            x, bits, c, j, i = i, 4, v >> 8, (v >> 4) & 15, v & 15
        elif ch in '24':
            shift = 1 if ch == '2' else 2; x <<= shift; bits += shift
        elif ch == 'b': x += 16; bits += 1
        elif ch == 'r': x = (base + off + 2 + signed(x, bits)) & 0xffffffff; bits = 32
        elif ch == 'u': out += hex(x)
        elif ch == 'd': out += str(x)
        elif ch == 's': out += str(signed(x, bits))
        elif ch == 'n': out += str(x - (1 << bits))
        elif ch == 'q':
            half=bits//2; mask=(1 << half)-1
            out += f'{(x>>half)&mask}/{x&mask}'
        elif ch == 'i': out += f'r{i}'
        elif ch == 'j': out += f'r{j}'
        elif ch == 'g': out += special[i] if i < len(special) else f'special{i}'
        elif ch == 'h': out += special[j] if j < len(special) else f'special{j}'
        elif ch == 'k': out += f'cr{i}'
        elif ch == 'l': out += f'cr{j}'
        elif ch == 'c': out += hex(c)
        elif ch in 'AFPSCM': out += {'A':'r13','F':'r14','P':'PS','S':'r15','C':'CCR','M':'ILM'}[ch]
        elif ch == '&': out += '+'
        elif ch == 'x': x |= 0x100
        elif ch in 'yz':
            start = 8 if ch == 'y' else 0
            regs = [start + (7-k if x & 0x100 else k) for k in range(8) if x & (1 << k)]
            out += '(' + ','.join(f'r{k}' for k in regs) + ')'
        else: out += ch
    return n, name, out

def listing(b, start, end, base=0x40000):
    if start % 2 or not 0 <= start < end <= len(b):
        raise ValueError('Invalid aligned file range')
    off = start
    while off < end:
        n, name, operands = decode(b, off, base)
        if off+n > end:
            yield f'{off:08x} {base+off:08x} TRUNCATED'; break
        yield f'{off:08x} {base+off:08x} {b[off:off+n].hex():12s} {name:9s} {operands}'
        off += n
