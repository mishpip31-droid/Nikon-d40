"""Reproduce the bounded A startup analysis. Never writes firmware or a camera.

Runs original CPU code from FEF32 to, but not including, FEFEA. Peripheral
writes are logged in a shadow map. No IRQ delivery, task execution or RETI.
Usage: python check_a_startup.py /path/to/originals /path/to/output.json [evidence-dir]
"""
import binascii
import csv
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

from fr_startup_machine import StartupMachine
from fr_decode import listing

BASE = 0xC0000
RAM = 0x3C000


def groups(addresses):
    result = []
    for x in sorted(set(addresses)):
        if result and result[-1][1] == x:
            result[-1][1] += 1
        else:
            result.append([x, x + 1])
    return result


class Probe(StartupMachine):
    def __init__(self, blob, ram):
        super().__init__(blob)
        self.map(RAM, ram)
        self.map(0, bytes(0x1000))
        self.regs[15] = 0x3F26C
        self.writes = []

    def store(self, address, value, size):
        self.writes.append((self.pc, address, value & ((1 << (8 * size)) - 1), size))
        super().store(address, value, size)


def task_table(blob):
    count, stride = struct.unpack_from('>HH', blob, 0x3EB0C)
    assert (count, stride) == (12, 28)
    result = []
    for i in range(count + 1):
        off = 0x3EB10 + i * stride
        tcb, ident, level, unknown, flags, entry, frame, arg = struct.unpack_from('>IHHIIIII', blob, off)
        result.append(dict(record_cpu=off + BASE, tcb=tcb, id=ident, queue_level=level,
                           unknown_u32_08=unknown, flags=flags, entry=entry,
                           initial_frame=frame, initial_r4=arg, ready_at_init=bool(flags & 0x80000000)))
    return result


def patterns():
    rng = random.Random(330)
    return [('zero', bytes(0x4000)), ('ff', b'\xff' * 0x4000),
            ('a5', b'\xa5' * 0x4000), ('5a', b'\x5a' * 0x4000),
            ('ascending', bytes(range(256)) * 64),
            ('random_seed_330', bytes(rng.randrange(256) for _ in range(0x4000)))]


def assert_init(m, blob, before, tasks):
    # Independent structural expectations, not a second instruction interpreter.
    bss_end = 0x30000 + int.from_bytes(blob[0x410:0x412], 'big') + 4
    cleared = bytearray(bss_end - RAM)
    cleared[0x3D390 - RAM:0x3D394 - RAM] = (2).to_bytes(4, 'big')
    assert m.load(RAM, len(cleared)) == int.from_bytes(cleared, 'big')
    assert m.regs[15] == 0x3F26C
    assert m.load(0x3EB60, 4) == 0  # current task assigned only after stop point
    assert m.load(0x3EB64, 4) == 0x50800000
    assert [x['id'] for x in tasks if x['ready_at_init']] == [1, 5, 0]
    for t in tasks:
        a = t['tcb']
        ready = t['ready_at_init']
        head = 0x3EB60 + t['queue_level'] * 8
        assert m.load(a, 4) == (head if ready else a)
        assert m.load(a + 4, 4) == (head if ready else a)
        assert m.load(a + 8, 4) == (0 if ready else 0x10)
        assert m.load(a + 12, 2) == t['queue_level']
        assert m.load(a + 16, 4) == 0
        assert m.load(a + 20, 4) == 0xFFFFFFFF
        assert m.load(a + 24, 4) == (t['initial_frame'] if ready else 0)
        assert m.load(a + 28, 4) == 0xFFFFFFFF
        assert m.load(a + 34, 2) == 0
        assert m.load(a + 36, 4) == t['record_cpu']
        assert m.load(a + 40, 4) == 0xFFFFFFFF
        if ready:
            f = t['initial_frame']
            assert m.load(f, 4) == t['entry']
            assert m.load(f + 4, 4) == 0x1F0030
            assert m.load(f + 8, 4) == 0xFED5C
            assert m.load(f + 36, 4) == t['initial_r4']
            assert m.load(head, 4) == a and m.load(head + 4, 4) == a
    # Ten 16-byte objects: constructor FF156 copies the initial flag word.
    assert struct.unpack_from('>HH', blob, 0x3EC80) == (10, 16)
    for i in range(10):
        rec = 0x3EC84 + 16 * i
        a = int.from_bytes(blob[rec:rec + 4], 'big')
        assert m.load(a, 4) == a and m.load(a + 4, 4) == a
        assert m.load(a + 8, 4) == int.from_bytes(blob[rec + 12:rec + 16], 'big')
        assert m.load(a + 12, 4) == rec + BASE
    a = 0x3EEB8  # single object constructed by FF17C
    assert m.load(a, 4) == a and m.load(a + 4, 4) == a
    assert m.load(a + 8, 4) == a + 8 and m.load(a + 12, 4) == a + 8
    assert m.load(a + 16, 4) == 0xFED28

    touched = {p for _, a, _, n in m.writes if a >= RAM for p in range(a, a + n)}
    allowed = set(range(RAM, bss_end)) | set(range(0x3EB60, 0x3F2CC))
    for t in tasks:
        if t['ready_at_init']:
            for d in (0, 4, 8, 36):
                allowed.update(range(t['initial_frame'] + d, t['initial_frame'] + d + 4))
    assert touched <= allowed
    after = m.load(RAM, 0x4000).to_bytes(0x4000, 'big')
    for i, v in enumerate(before):
        if RAM + i not in allowed:
            assert after[i] == v
    mmio = [(a, v, n) for _, a, v, n in m.writes if a < RAM]
    assert mmio == [(0x46F, 0x1E, 1), (0x44, 1, 1), (0x44, 1, 1), (0x44, 1, 1),
                    (0x424, 6, 1), (0x42A, 1, 1), (0x42B, 0x73, 1), (0x42E, 0xC1, 1)]
    return bss_end, groups(touched), mmio


def opcode_checks(blob):
    count = 0
    values = [(0, 0), (0, 0x80000000), (0x12345678, 0xF0000000), (0xFFFFFFFF, 0xFFFFFFFF)]
    for bits in range(16):
        flags = tuple(bool(bits & (1 << i)) for i in range(4))
        for a, b in values:
            m = StartupMachine(blob)
            m.map(RAM, a.to_bytes(4, 'big'))
            m.regs[9], m.regs[12] = RAM, b
            m.z, m.n, m.v, m.c = flags
            assert m.run(0xFF7C8, stop=0xFF7CA) == 1
            assert m.load(RAM, 4) == a | b
            assert (m.z, m.n, m.v, m.c) == (a | b == 0, bool((a | b) & 0x80000000), flags[2], flags[3])
            count += 1
        for value in (0, 0xFF, 0x12345678, 0xFFFFFFFF):
            m = StartupMachine(blob)
            m.map(0, bytes(256))
            m.regs[13] = value
            m.z, m.n, m.v, m.c = flags
            assert m.run(0xFF7CE, stop=0xFF7D0) == 1
            assert m.load(0x44, 1) == value & 255
            assert (m.z, m.n, m.v, m.c) == flags
            count += 1
    return count


def main():
    originals, output = Path(sys.argv[1]), Path(sys.argv[2])
    result = dict(status='PASS', version=9, hardware_runs=0,
                  scope='Original A FEF32 to FEFEA excluded, no hooks; shadow MMIO writes; no interrupts, scheduler or tasks executed',
                  models=['RAM byte arrays', 'shadow MMIO registers, no physical effects',
                          'bounded FR subset, not a complete CPU'], variants={},
                  sources=[
                      'https://www.manualsdir.com/manuals/103548/fujitsu-fr-family-32-bit-microcontroller-instruction-manuel-cm71-00101-5e.html?page=246',
                      'https://manualsdump.com/en/manuals/fujitsu-cm71-00101-5e/119873/117'])
    originals_data = []
    for name in ('AD400111.bin', 'AD400112.bin'):
        blob = (originals / name).read_bytes()
        StartupMachine(blob)  # refuse any other input hash
        assert len(blob) == 0x40002 and binascii.crc_hqx(blob, 0) == 0
        assert int.from_bytes(blob[0x3FFFC:0x40000], 'big') == 0xC0042
        tasks = task_table(blob)
        runs = []
        for label, initial in patterns():
            m = Probe(blob, initial)
            steps = m.run(0xFEF32, stop=0xFEFEA, budget=50000)
            end, touched, mmio = assert_init(m, blob, initial, tasks)
            runs.append(dict(pattern=label, steps=steps, unique_pcs=len(m.visited),
                             write_operations=len(m.writes), status='PASS'))
        entry_snippets = {str(t['id']): blob[t['entry']-BASE:t['entry']-BASE+16].hex() for t in tasks}
        result['variants'][name] = dict(sha256=hashlib.sha256(blob).hexdigest(),
              bss_range=[RAM, end], rtos_clear_ranges=[[0x3EB60, 0x3EECC], [0x3EECC, 0x3F26C], [0x3F26C, 0x3F2CC]],
              tasks=tasks, ready_ids=[1, 5, 0], ready_bitmap=0x50800000,
              run_results=runs, written_ram_ranges=touched, mmio_writes=mmio,
              entry_prefix_hex=entry_snippets, new_instruction_cases=opcode_checks(blob))
        originals_data.append(blob)
    a, b = originals_data
    result['version_comparison'] = dict(changed_byte_count=sum(x != y for x, y in zip(a, b)),
            a112_bss_growth=16,
            task_entries_changed=[t['id'] for t, u in zip(result['variants']['AD400111.bin']['tasks'], result['variants']['AD400112.bin']['tasks']) if t['entry'] != u['entry']],
            warning='Same-offset byte differences are not semantic change coverage; task correspondence follows stable table IDs.')
    result['totals'] = dict(startup_runs=12, added_opcode_cases=256, initialized_task_records=13,
                           active_initial_contexts_per_run=3, real_camera_tests=0)
    rejected = 0
    for blob in (b[:-1], b + b'\0', bytes([b[0] ^ 1]) + b[1:], bytes(len(b))):
        try:
            StartupMachine(blob)
        except ValueError:
            rejected += 1
    assert rejected == 4
    result['totals']['rejected_wrong_inputs'] = rejected
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    with output.with_name('a_tasks.csv').open('w', newline='') as f:
        rows = [dict(firmware=name, **t) for name, v in result['variants'].items() for t in v['tasks']]
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    if len(sys.argv) > 3:
        directory = Path(sys.argv[3])
        directory.mkdir(parents=True, exist_ok=True)
        # Separate code intervals avoid decoding the embedded copyright text.
        ranges = [(0x42, 0x6A), (0x402, 0x444), (0x3EF32, 0x3EF7E),
                  (0x3EFEA, 0x3F280), (0x3F59C, 0x3F5C0),
                  (0x3F5DC, 0x3F606), (0x3F7A2, 0x3F7D0)]
        for name, blob in zip(result['variants'], originals_data):
            text = ['Original A code. Addresses belong to A, not B. No physical startup test.']
            for start, end in ranges:
                text.append(f'\nCode interval file [{start:#x}, {end:#x})')
                text.extend(listing(blob, start, end, base=BASE))
            (directory / (name + '_rtos_startup_v9.asm.txt')).write_text('\n'.join(text) + '\n')
    print(json.dumps(dict(status='PASS', totals=result['totals'], output=str(output)), ensure_ascii=False))


if __name__ == '__main__':
    main()
