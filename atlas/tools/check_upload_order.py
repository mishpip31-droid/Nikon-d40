"""Trace original D40 configuration CPU code. Does NOT emulate image hardware.

Only 0x323C22 (tone builder) is replaced with an explicitly synthetic curve.
Original matrix copies, small-table expansion, saturation expansion, and upload
loops execute in the bounded FR interpreter. This establishes write order only.
"""
import json
import sys
from pathlib import Path
from fr_color_machine import ColorMachine, EXPECTED


class TraceMachine(ColorMachine):
    def __init__(self, blob):
        super().__init__(blob)
        self.writes = []

    def store(self, address, value, size):
        super().store(address, value, size)
        if 0x40010000 <= address < 0x40020000:
            self.writes.append((address, size, value & ((1 << (8 * size)) - 1)))


def check(blob):
    m = TraceMachine(blob)
    ctx, curve = 0x20000000, 0x83EB586C
    m.map(ctx, bytes(0x800))
    m.map(0x83EB3000, bytes(0x6000))
    m.map(0x40010000, bytes(0x10000))
    # Deliberately synthetic valid-width values make transfers identifiable.
    for offset in range(0x388, 0x466, 2):
        m.store(ctx + offset, offset & 0x1ff, 2)
    m.store(ctx + 0x388, 0x13572468, 4)
    m.store(ctx + 0x3D4, 0x24681357, 4)
    tone = [((i * 7) ^ 0x155) & 4095 for i in range(4096)]
    for i, v in enumerate(tone):
        m.store(curve + i * 2, v, 2)
    hook_calls = []

    def tone_hook(machine):
        assert machine.regs[4] == ctx
        hook_calls.append('0x323C22')
        machine.regs[4] = curve

    steps = m.run(0x4B41C, ctx, budget=300000, hooks={0x323C22: tone_hook})
    assert hook_calls == ['0x323C22']
    matrix = [(k, a, v) for k, (a, s, v) in enumerate(m.writes)
              if 0x40010022 <= a < 0x40010046]
    expected = []
    for i in range(9):
        expected.extend([(0x40010022 + 2*i, m.load(ctx+0x3A4+2*i, 2)),
                         (0x40010034 + 2*i, m.load(ctx+0x3B6+2*i, 2))])
    assert [(a, v) for _, a, v in matrix] == expected
    banks = [0x40018400, 0x4001A400, 0x4001C400]
    summaries = []
    for base in banks:
        events = [(k, a, s, v) for k, (a, s, v) in enumerate(m.writes)
                  if base <= a < base + 8192]
        assert [(a, s, v) for _, a, s, v in events] == [
            (base+2*i, 2, v) for i, v in enumerate(tone)]
        assert events[0][0] > matrix[-1][0]
        summaries.append({'bank': hex(base), 'first_write_index': events[0][0],
                          'last_write_index': events[-1][0], 'entries': len(events)})
    assert not any(0x40010200 <= a < 0x40018400 for a, _, _ in m.writes)
    scalars = []
    for a, size, value in m.writes:
        if a < 0x40010022 or 0x40010046 <= a < 0x40010058:
            scalars.append({'register': hex(a), 'bytes': size, 'value': value})
    return {
        'firmware_sha256': EXPECTED, 'result': 'PASS',
        'routine': '0x4B41C', 'instructions': steps,
        'MMIO_write_count': len(m.writes),
        'context': 'synthetic, ctx+0x73C=0; small and saturation selectors=0',
        'hooks': {'0x323C22': 'returns synthetic 4096-element curve at 0x83EB586C'},
        'matrix_writes': [{'write_index': k, 'address': hex(a), 'value': v}
                          for k, a, v in matrix],
        'tone_banks': summaries, 'scalar_writes': scalars,
        'static_sqrt_square_rescale_banks_written_by_this_routine': False,
        'camera_connected': False, 'firmware_modified': False,
        'hardware_emulated': False, 'ASIC_pixel_order_proven': False,
        'limitations': ['MMIO is ordinary memory; no pixel arithmetic is executed.',
                        'Only one synthetic configuration path is executed.',
                        'The tone builder is a declared hook, not executed here.',
                        'This test proves CPU upload order, not ASIC signal routing.']}


if __name__ == '__main__':
    result = check(Path(sys.argv[1]).read_bytes())
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(encoded)
    print(json.dumps({k: result[k] for k in ('result', 'instructions', 'MMIO_write_count',
                                           'ASIC_pixel_order_proven')}))
