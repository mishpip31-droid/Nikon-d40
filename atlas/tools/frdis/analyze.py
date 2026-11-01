"""Whole-image recursive-descent analysis of Nikon D40 firmware (FR, big endian).

Usage: python3 analyze.py B firmware/BD400111.bin outdir [atlas_symbols.csv]
       python3 analyze.py A firmware/AD400111.bin outdir

Produces functions.csv, callgraph.json, xrefs.json, strings.csv, listing.txt
Only reads the firmware as data; nothing is executed.
"""
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import fr  # noqa: E402

ACC_RE = re.compile(r'@r(\d+)(?![\d+])')


class Image:
    def __init__(self, kind, data):
        self.kind, self.data = kind, data
        if kind == 'B':
            # (cpu_start, cpu_end, file_start, is_code_candidate)
            self.maps = [(0x40000, 0x40000 + len(data) - 2, 0, True),
                         (0x83CE8658, 0x83CE8658 + 0x9BE, 0x11CB6C, True),
                         (0x83CDFFB0, 0x83CDFFB0 + 0x86A8, 0x1144C4, False)]
            self.vec_file = 0xAFC00
        else:
            self.maps = [(0xC0000, 0xC0000 + len(data) - 2, 0, True)]
            self.vec_file = 0x3FC00

    def to_file(self, a):
        for s, e, f, _ in self.maps:
            if s <= a < e:
                return f + a - s
        return None

    def is_code_addr(self, a):
        if a & 1:
            return False
        for s, e, f, code in self.maps:
            if s <= a < e:
                return code
        return False

    def read(self, a, n):
        for s, e, f, _ in self.maps:
            if s <= a and a + n <= e:
                o = f + a - s
                return self.data[o:o + n]
        return None

    def u32(self, off):
        return int.from_bytes(self.data[off:off + 4], 'big')


class Analyzer:
    def __init__(self, img):
        self.img = img
        self.insns = {}           # addr -> Insn
        self.owner = {}           # addr -> function entry
        self.funcs = {}           # entry -> dict
        self.sources = defaultdict(set)
        self.calls = defaultdict(set)     # caller -> callees
        self.callers = defaultdict(set)
        self.ints = defaultdict(lambda: defaultdict(int))  # func -> int# -> count
        self.consts = defaultdict(set)    # func -> 32-bit constants loaded
        self.acc = defaultdict(lambda: defaultdict(set))   # addr -> kind -> funcs
        self.dacc = defaultdict(lambda: defaultdict(set))  # direct I/O
        self.ijumps = defaultdict(list)
        self.icalls_unres = defaultdict(int)
        self.os_calls = defaultdict(set)
        self.fnptr = set()
        self.switch_tables = {}  # constants stored as values or passed as call args
        self.bad = {}

    def add_entry(self, a, src):
        if self.img.is_code_addr(a):
            self.sources[a].add(src)
            return True
        return False

    # ---------- per-function exploration ----------
    def explore(self, entry, known_entries):
        img = self.img
        blocks = [(entry, {})]
        seen = set()
        f = {'entry': entry, 'insns': 0, 'bytes': 0, 'blocks': 0, 'ret': False,
             'bad': None, 'ijump': 0, 'tail': set()}
        while blocks:
            start, regs = blocks.pop()
            if start in seen:
                continue
            seen.add(start)
            f['blocks'] += 1
            a = start
            regs = dict(regs)
            pending = None  # (insn) control transfer waiting for delay slot
            in_slot = False  # previous insn was CALL:D
            self._jt = None
            self._cmp = None
            while True:
                if a != start and a in seen and pending is None:
                    break  # fell into an already explored block
                if a != start and pending is None and a in known_entries and a != entry:
                    f['tail'].add(a)  # fell through into another function
                    break
                ins = fr.decode(img.read, a)
                if ins is None or self.illegal(ins, entry, pending if pending else
                                               (True if in_slot else None)):
                    f['bad'] = a
                    break
                if a in self.owner and self.owner[a] != entry and a == start:
                    pass
                if ins.name in ('CMP', 'CMP2') and ins.ops.startswith('#'):
                    self._cmp = ins.imm
                elif ins.name == 'LD' and ins.ops == '@(r13+r12),r12' and 12 in regs:
                    self._jt = regs[12]
                self.insns[a] = ins
                self.owner.setdefault(a, entry)
                f['insns'] += 1
                f['bytes'] += ins.size
                self.track(entry, ins, regs)
                nxt = a + ins.size
                if in_slot:
                    in_slot = False
                    self.clobber(regs)
                if pending is not None:
                    # this insn is a delay slot; now resolve pending transfer
                    self.transfer(entry, pending, nxt, blocks, regs, f, known_entries)
                    break
                if ins.flow in ('seq', 'int'):
                    a = nxt
                    continue
                if ins.flow in ('call', 'icall'):
                    self.do_call(entry, ins, regs)
                    if ins.delay:
                        # delay slot executes before the call; continue normally
                        in_slot = True
                        a = nxt
                        continue
                    self.clobber(regs)
                    a = nxt
                    continue
                if ins.delay:
                    pending = ins
                    a = nxt
                    continue
                self.transfer(entry, ins, nxt, blocks, regs, f, known_entries)
                break
            # handle call:D clobber lazily (ignored precision)
        return f

    @staticmethod
    def illegal(ins, entry, pending):
        """Patterns that compiled FR code does not contain."""
        if pending is not None and (ins.flow != 'seq' or ins.size != 2
                                    or ins.name in ('ENTER', 'LEAVE')):
            return True  # control transfer / long insn in a delay slot
        if ins.flow == 'int' and ins.imm < 0x40:
            return True  # INT #0..#0x3F: reset/exception/IRQ vectors
        if ins.name == 'ENTER' and ins.addr - entry > 12:
            return True
        return False

    def do_call(self, entry, ins, regs):
        for r in (4, 5, 6, 7):
            if r in regs and self.img.is_code_addr(regs[r]):
                self.fnptr.add(regs[r])
        if ins.flow == 'call':
            t = ins.target
        else:
            t = regs.get(ins.reg_i)
        if t is not None and self.img.is_code_addr(t):
            self.calls[entry].add(t)
            self.callers[t].add(entry)
            self.add_entry(t, 'call')
        elif ins.flow == 'icall':
            self.icalls_unres[entry] += 1

    @staticmethod
    def clobber(regs):
        for r in (0, 1, 2, 3, 4, 5, 6, 7, 12, 13):
            regs.pop(r, None)

    def transfer(self, entry, ins, nxt, blocks, regs, f, known):
        if ins.flow == 'ret':
            f['ret'] = True
            return
        if ins.flow == 'ijump' and ins.reg_i == 12 and self._jt is not None:
            tbl, n = self._jt, self._cmp
            n = 256 if n is None or not 0 < n <= 512 else n + 1
            got = 0
            for k in range(n):
                b = self.img.read(tbl + 4 * k, 4)
                if b is None:
                    break
                t = int.from_bytes(b, 'big')
                if not self.img.is_code_addr(t) or abs(t - ins.addr) > 0x8000:
                    break
                blocks.append((t, regs))
                got += 1
            if got:
                f['switch'] = f.get('switch', 0) + 1
                self.switch_tables[tbl] = got
                return
        if ins.flow == 'ijump':
            t = regs.get(ins.reg_i)
            if t is not None and self.img.is_code_addr(t):
                f['tail'].add(t)
                self.calls[entry].add(t)
                self.callers[t].add(entry)
                self.add_entry(t, 'tailjmp')
            else:
                f['ijump'] += 1
                self.ijumps[entry].append(ins.addr)
            return
        t = ins.target
        if t is not None and self.img.is_code_addr(t):
            if t in known and t != entry:
                f['tail'].add(t)
                self.calls[entry].add(t)
                self.callers[t].add(entry)
            else:
                blocks.append((t, regs))
        if ins.flow == 'cjump':
            blocks.append((nxt, regs))

    def track(self, entry, ins, regs):
        name = ins.name
        if ins.flow == 'int':
            code = regs.get(12)
            if code is not None and code & 0x80000000:
                code -= 1 << 32
            key = ins.imm if ins.imm != 0x40 or code is None else f'40:{code}'
            self.ints[entry][key] += 1
            self.os_calls[key].add(entry)
            self.clobber(regs)
            return
        if name in ('EXTSB', 'EXTSH', 'EXTUB', 'EXTUH') and ins.reg_i in regs:
            v = regs[ins.reg_i]
            if name == 'EXTUB':
                v &= 0xFF
            elif name == 'EXTUH':
                v &= 0xFFFF
            elif name == 'EXTSB':
                v = (v & 0xFF) | (0xFFFFFF00 if v & 0x80 else 0)
            else:
                v = (v & 0xFFFF) | (0xFFFF0000 if v & 0x8000 else 0)
            regs[ins.reg_i] = v
            return
        if name in ('LDI:32', 'LDI:20', 'LDI:8'):
            regs[ins.reg_i] = ins.imm
            if name != 'LDI:8':
                self.consts[entry].add(ins.imm)
            return
        if name == 'MOV' and ins.ops.startswith('r') and ',' in ins.ops:
            s, d = ins.ops.split(',')
            if s[1:].isdigit() and d.startswith('r') and d[1:].isdigit():
                if int(s[1:]) in regs:
                    regs[int(d[1:])] = regs[int(s[1:])]
                else:
                    regs.pop(int(d[1:]), None)
                return
        if name in ('ADD', 'ADDN', 'ADD2', 'ADDN2') and ins.ops.startswith('#'):
            r = ins.reg_i
            if r in regs and isinstance(ins.imm, int):
                regs[r] = (regs[r] + ins.imm) & 0xFFFFFFFF
                return
        if ins.direct is not None:
            kind = 'W' if ins.ops.startswith(('r13', '@r13+', '@r15+')) and \
                name.startswith('DMOV') else 'R'
            if name.startswith('DMOV'):
                kind = 'W' if ins.ops.split(',')[1].startswith('@0x') else 'R'
            self.dacc[ins.direct][kind].add(entry)
        if name == 'ST' and ins.ops.startswith('r'):
            src = int(ins.ops.split(',')[0][1:])
            if src in regs and self.img.is_code_addr(regs[src]):
                self.fnptr.add(regs[src])
        m = ACC_RE.search(ins.ops)
        if m and '@(' not in ins.ops:
            r = int(m.group(1))
            if r in regs:
                base = name.rstrip(':D')
                if base.startswith('ST'):
                    k = 'W'
                elif base.startswith('LD') or base == 'XCHB':
                    k = 'R'
                else:
                    k = 'M'
                self.acc[regs[r]][k + {'B': '8', 'H': '16'}.get(base[-1:], '32')
                                  if base[-1:] in 'BH' else k + '32'].add(entry)
        if ins.dest is not None:
            if ins.dest == -1:
                for r in list(regs):
                    if r < 15:
                        regs.pop(r)
            else:
                regs.pop(ins.dest, None)

    # ---------- driver ----------
    def run(self, extra=()):
        img = self.img
        for k in range(256):
            v = img.u32(img.vec_file + 4 * k)
            self.add_entry(v, f'vector{k}')
        for a, src in extra:
            self.add_entry(a, src)
        self.tasks = self.find_task_tables()
        for t in self.tasks:
            self.add_entry(t['entry'], f"task{t['id']}")
        self.done = set()
        self.rejected = set()
        self.fixpoint('trusted roots')
        for stage in range(10):
            n0 = len(self.funcs)
            # function pointers loaded as constants by accepted code
            cands = {c for c in self.fnptr if c not in self.funcs}
            self.try_candidates(cands, 'constptr')
            self.try_candidates(self.table_candidates(), 'ptrtable')
            if len(self.funcs) == n0:
                break
        self.try_candidates(self.prologue_candidates(), 'prologue')
        # prologue functions may load further pointers
        for stage in range(10):
            n0 = len(self.funcs)
            cands = {c for c in self.fnptr if c not in self.funcs}
            self.try_candidates(cands, 'constptr')
            self.try_candidates(self.table_candidates(), 'ptrtable')
            if len(self.funcs) == n0:
                break
        for stage in range(20):
            n0 = len(self.funcs)
            self.try_candidates(self.gap_candidates(), 'gapstart')
            cands = {c for c in self.fnptr if c not in self.funcs}
            self.try_candidates(cands, 'constptr')
            if len(self.funcs) == n0:
                break
        for stage in range(10):
            n0 = len(self.funcs)
            tg, enc = self.callsite_candidates()
            self.try_candidates(tg, 'callsite')
            self.try_candidates(enc, 'callsite_encl')
            self.try_candidates({c for c in self.fnptr if c not in self.funcs}, 'constptr')
            if len(self.funcs) == n0:
                break
        self.ptr_refs = self.ptr_scan()

    def callsite_candidates(self):
        """'LDI:32 #X,r12 ; CALL[:D] @r12' found in unexplored bytes: X is a
        callee; the nearest preceding prologue is a candidate for the caller."""
        img = self.img
        s, e, fo, _ = img.maps[0]
        d = img.data
        targets, encl = set(), set()
        for off in range(0, e - s - 8, 2):
            a = s + off
            if a in self.insns:
                continue
            if d[off] == 0x9F and d[off + 1] == 0x8C and \
                    d[off + 6:off + 8] in (b'\x97\x1c', b'\x9f\x1c', b'\x97\x0c', b'\x9f\x0c'):
                x = int.from_bytes(d[off + 2:off + 6], 'big')
                if img.is_code_addr(x) and x not in self.funcs:
                    targets.add(x)
                # nearest preceding prologue start
                b = a - 2
                lim = a - 0x1000
                while b > max(s, lim) and b not in self.insns:
                    w = int.from_bytes(img.read(b, 2), 'big')
                    if w == 0x1781 or (w >> 8) == 0x0F:
                        c = b
                        for _ in range(12):
                            p = c - 2
                            if p in self.insns:
                                break
                            pw = int.from_bytes(img.read(p, 2), 'big')
                            if (pw & 0xFFF0) == 0x1700 or (pw >> 8) in (0x8E, 0x8F) \
                                    or pw == 0x1781:
                                c = p
                            else:
                                break
                        encl.add(c)
                        break
                    b -= 2
        return targets, encl

    def gap_candidates(self):
        """First instruction address after the end of accepted code (skipping NOP/
        zero/FF padding), inside the primary map."""
        img = self.img
        s, e, fo, _ = img.maps[0]
        out = []
        for a, ins in self.insns.items():
            if not (s <= a < e):
                continue
            n = a + ins.size
            if n in self.insns:
                continue
            k = 0
            while n < e and k < 16:
                w = int.from_bytes(img.read(n, 2), 'big')
                if w in (0x9FA0, 0x0000, 0xFFFF):
                    n += 2
                    k += 1
                else:
                    break
            if n < e and n not in self.insns and n not in self.rejected:
                w = int.from_bytes(img.read(n, 2), 'big')
                if w != 0xFFFF:
                    out.append(n)
        return out

    def find_task_tables(self):
        """Static REALOS task table: header u16 count, u16 record size (0x1C),
        then records: TCB pointer, u16 id, u16 priority, 0, attr, entry,
        stack top, 0 (the kernel's sta_tsk handler 0xC23E6 indexes it by id-1).
        Detected by runs of >= 3 attr/entry/stack triples; id, priority and TCB
        are read from the 12 bytes before each attr word."""
        img = self.img
        d = img.data
        out = []
        for off in range(0, len(d) - 0x1C * 3, 4):
            def rec(o):
                atr = int.from_bytes(d[o:o + 4], 'big')
                ent = int.from_bytes(d[o + 4:o + 8], 'big')
                stk = int.from_bytes(d[o + 8:o + 12], 'big')
                z = int.from_bytes(d[o + 12:o + 16], 'big')
                if atr & 0x3FFFFFFF or z or not img.is_code_addr(ent):
                    return None
                if not (0x80000000 <= stk < 0x84000000 or 0x1000 <= stk < 0x100000) or stk & 7:
                    return None
                if o < 12:
                    return None
                return {'file_off': o - 12, 'attr': atr, 'entry': ent, 'stack': stk,
                        'exinf': int.from_bytes(d[o - 12:o - 8], 'big'),
                        'id': int.from_bytes(d[o - 8:o - 6], 'big'),
                        'priority': int.from_bytes(d[o - 6:o - 4], 'big')}
            if all(rec(off + k * 0x1C) for k in range(3)) and not (
                    off >= 0x1C and rec(off - 0x1C)):
                o = off
                while True:
                    r = rec(o)
                    if not r:
                        break
                    out.append(r)
                    o += 0x1C
        return out

    def fixpoint(self, label):
        for _round in range(200):
            todo = sorted(a for a in self.sources if a not in self.done)
            if not todo:
                break
            known = set(self.sources)
            for e in todo:
                self.done.add(e)
                self.funcs[e] = self.explore(e, known)
        print(f'{label}: {len(self.funcs)} funcs', file=sys.stderr, flush=True)

    def closure_ok(self, entry, limit=400, strict=False, need_end=True):
        """Tentatively explore entry and its new callees; reject on any invalid
        decode or overlap with already accepted instructions."""
        if entry in self.rejected or entry in self.insns:
            return False
        tmp = Analyzer(self.img)
        trusted = set(self.funcs)
        tmp.sources[entry].add('tmp')
        done = set()
        while True:
            todo = [a for a in tmp.sources if a not in done and a not in trusted]
            if not todo:
                return True
            if len(done) > limit:
                return False
            known = trusted | set(tmp.sources)
            for e in todo:
                done.add(e)
                f = tmp.explore(e, known)
                if f['bad'] is not None or f['insns'] == 0:
                    return False
                if e == entry and need_end and not (f['ret'] or f['tail'] or f['ijump']):
                    return False
                if e == entry and strict and (not f['ret'] or f['insns'] < 3):
                    return False
            for a in tmp.insns:
                if a in self.insns:
                    return False

    def try_candidates(self, cands, src):
        acc = 0
        for c in sorted(cands):
            if c in self.funcs or c in self.rejected:
                continue
            if self.closure_ok(c, strict=(src == 'gapstart'),
                               need_end=(src not in ('prologue', 'task'))):
                self.add_entry(c, src)
                acc += 1
                self.explore_pending()
            else:
                self.rejected.add(c)
        # explore accepted ones for real (quietly)
        for _round in range(200):
            todo = sorted(a for a in self.sources if a not in self.done)
            if not todo:
                break
            known = set(self.sources)
            for e in todo:
                self.done.add(e)
                self.funcs[e] = self.explore(e, known)
        print(f'{src}: {len(cands)} candidates, {acc} accepted, {len(self.funcs)} funcs',
              file=sys.stderr, flush=True)

    def explore_pending(self):
        while True:
            todo = sorted(a for a in self.sources if a not in self.done)
            if not todo:
                return
            known = set(self.sources)
            for e in todo:
                self.done.add(e)
                self.funcs[e] = self.explore(e, known)

    def prologue_candidates(self):
        img = self.img
        s, e, fo, _ = img.maps[0]
        out = []
        for a in range(s, e - 4, 2):
            if a in self.insns:
                continue
            w = int.from_bytes(img.read(a, 2), 'big')
            if w == 0x1781 or (w >> 8) == 0x0F:
                # walk back over the rest of a Softune prologue:
                # ST ri,@-r15 / STM0 / STM1 / ST RP,@-r15
                b = a
                for _ in range(12):
                    p = b - 2
                    if p < s or p in self.insns:
                        break
                    pw = int.from_bytes(img.read(p, 2), 'big')
                    if (pw & 0xFFF0) == 0x1700 or (pw >> 8) in (0x8E, 0x8F) or pw == 0x1781:
                        b = p
                    else:
                        break
                out.append(b)
        return sorted(set(out))

    def table_candidates(self):
        """Runs of >=3 aligned big-endian words pointing into code, where at least
        one already is an accepted function; words must lie outside code."""
        img = self.img
        d = img.data
        known = set(self.funcs)
        out = set()
        for phase in (0, 2):
            run = []
            for off in range(phase, len(d) - 4, 4):
                v = int.from_bytes(d[off:off + 4], 'big')
                cpu = img.maps[0][0] + off
                if img.is_code_addr(v) and cpu not in self.insns:
                    run.append(v)
                    continue
                if len(run) >= 3 and any(x in known for x in run):
                    out.update(x for x in run if x not in known)
                run = []
        return out

    def ptr_scan(self):
        """Data words (outside instructions) equal to accepted function entries."""
        img = self.img
        known = set(self.funcs)
        refs = defaultdict(list)
        d = img.data
        for off in range(0, len(d) - 4, 2):
            v = int.from_bytes(d[off:off + 4], 'big')
            if v in known and img.maps[0][0] + off not in self.insns:
                refs[v].append(off)
        return refs


def find_strings(img, minlen=5):
    out = []
    d = img.data
    cur = bytearray()
    start = 0
    for off, ch in enumerate(d):
        if 0x20 <= ch < 0x7F:
            if not cur:
                start = off
            cur.append(ch)
        else:
            if len(cur) >= minlen and ch == 0:
                out.append((start, cur.decode('ascii')))
            cur = bytearray()
    return out


def main():
    kind, path, outdir = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    outdir.mkdir(parents=True, exist_ok=True)
    img = Image(kind, path.read_bytes())
    names = {}
    extra = []
    if len(sys.argv) > 4:
        for row in csv.DictReader(open(sys.argv[4])):
            fw = row['firmware']
            if (kind == 'B' and fw.startswith('B')) or (kind == 'A' and fw.startswith('A')):
                try:
                    a = int(row['cpu_pc'], 16)
                except ValueError:
                    continue
                names[a] = row['name']
                extra.append((a, 'atlas'))
    an = Analyzer(img)
    an.run(extra)

    # strings and references
    strs = find_strings(img)
    str_by_cpu = {}
    for off, s in strs:
        for ms, me, mf, _ in img.maps:
            if mf <= off < mf + (me - ms):
                str_by_cpu[ms + off - mf] = s
    str_refs = defaultdict(set)
    for fn, cs in an.consts.items():
        for c in cs:
            if c in str_by_cpu:
                str_refs[fn].add(c)

    # function table
    rows = []
    for e in sorted(an.funcs):
        f = an.funcs[e]
        rows.append({
            'entry': f'0x{e:x}',
            'file_off': '' if img.to_file(e) is None else f'0x{img.to_file(e):x}',
            'name': names.get(e, ''),
            'source': '+'.join(sorted(an.sources[e]))[:60],
            'insns': f['insns'], 'bytes': f['bytes'], 'blocks': f['blocks'],
            'returns': int(f['ret']), 'bad_at': '' if f['bad'] is None else f'0x{f["bad"]:x}',
            'callers': len(an.callers[e]), 'callees': len(an.calls[e]),
            'os_ints': ' '.join(f'{k}*{v}' for k, v in sorted(an.ints[e].items(), key=str)),
            'unresolved_ijump': f['ijump'], 'unresolved_icall': an.icalls_unres[e],
            'ptr_refs': len(getattr(an, 'ptr_refs', {}).get(e, [])),
            'strings': ' | '.join(sorted(str_by_cpu[c][:40] for c in str_refs[e]))[:200],
        })
    with open(outdir / 'functions.csv', 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(outdir / 'tasks.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['id', 'priority', 'entry', 'stack_top', 'attr', 'tcb', 'record_file_off'])
        for t in an.tasks:
            w.writerow([t['id'], t['priority'], f"0x{t['entry']:x}", f"0x{t['stack']:x}",
                        f"0x{t['attr']:x}", f"0x{t['exinf']:x}", f"0x{t['file_off']:x}"])
    json.dump({f'0x{k:x}': sorted(f'0x{x:x}' for x in v) for k, v in an.calls.items()},
              open(outdir / 'callgraph.json', 'w'), indent=0)

    def accdump(acc):
        return {f'0x{a:x}': {k: sorted(f'0x{x:x}' for x in v) for k, v in kinds.items()}
                for a, kinds in sorted(acc.items())}
    json.dump({'memory': accdump(an.acc), 'direct_io': accdump(an.dacc)},
              open(outdir / 'xrefs.json', 'w'), indent=0)
    json.dump({str(k): sorted(f'0x{x:x}' for x in v) for k, v in
               sorted(an.os_calls.items(), key=lambda kv: -len(kv[1]))},
              open(outdir / 'os_calls.json', 'w'), indent=0)
    with open(outdir / 'strings.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['file_off', 'cpu', 'text', 'referencing_functions'])
        refs_by_str = defaultdict(set)
        for fn, cs in str_refs.items():
            for c in cs:
                refs_by_str[c].add(fn)
        for cpu, s in sorted(str_by_cpu.items()):
            w.writerow([f'0x{img.to_file(cpu):x}', f'0x{cpu:x}', s,
                        ' '.join(f'0x{x:x}' for x in sorted(refs_by_str[cpu]))])

    # listing
    by_owner = defaultdict(list)
    for a, o in an.owner.items():
        by_owner[o].append(a)
    with open(outdir / 'listing.txt', 'w') as fh:
        for e in sorted(an.funcs):
            addrs = sorted(by_owner.get(e, ()))
            if not addrs:
                continue
            nm = names.get(e, f'sub_{e:x}')
            fh.write(f'\n; ===== {nm}  entry 0x{e:x}  callers: '
                     f'{" ".join(hex(c) for c in sorted(an.callers[e])[:12])}\n')
            prev = None
            for a in addrs:
                ins = an.insns[a]
                if prev is not None and a != prev:
                    fh.write('        ; ...\n')
                fo = img.to_file(a)
                raw = img.read(a, ins.size).hex()
                cmt = ''
                tgt = ins.target
                if tgt is not None and tgt in an.funcs:
                    cmt = f' ; -> {names.get(tgt, "sub_%x" % tgt)}'
                if ins.name in ('LDI:32', 'LDI:20') and ins.imm in str_by_cpu:
                    cmt = f' ; "{str_by_cpu[ins.imm][:50]}"'
                elif ins.name in ('LDI:32', 'LDI:20') and ins.imm in an.funcs:
                    cmt = f' ; &{names.get(ins.imm, "sub_%x" % ins.imm)}'
                fh.write(f'{fo:08x} {a:08x} {raw:12s} {ins.name:9s} {ins.ops}{cmt}\n')
                prev = a + ins.size

    covered = sum(i.size for i in an.insns.values())
    code_map = img.maps[0][1] - img.maps[0][0]
    ff = img.data.count(b'\xff' * 1)
    summary = {
        'image': kind, 'file': path.name, 'functions': len(an.funcs),
        'instructions': len(an.insns), 'code_bytes_covered': covered,
        'image_bytes': len(img.data),
        'functions_with_bad_decode': sum(1 for f in an.funcs.values() if f['bad']),
        'unresolved_indirect_jumps': sum(f['ijump'] for f in an.funcs.values()),
        'sources': {s: sum(1 for v in an.sources.values() if any(x.startswith(s) for x in v))
                    for s in ('vector', 'task', 'call', 'tailjmp', 'atlas', 'constptr', 'ptrtable', 'prologue', 'gapstart', 'callsite')},
        'strings': len(str_by_cpu),
        'switch_tables_resolved': len(an.switch_tables),
        'memory_addresses_referenced': len(an.acc),
        'direct_io_addresses': len(an.dacc),
    }
    json.dump(summary, open(outdir / 'summary.json', 'w'), indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
