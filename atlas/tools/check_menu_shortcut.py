#!/usr/bin/env python3
"""Research tests for original menus and an incomplete CPU-only eighth-row prototype.
No camera, flash-writing image, real input events, full renderer or persistence.
"""
import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

from atlas import require_b, BASE, DELTA, DATA_START, COPY_END
from fr_menu_machine import MenuMachine
from fr_decode import listing
from menu_shortcut_prototype import CURRENT, MENU, PARENT, CUSTOM, SAVED_MODE, WORK_MODE, WORK_TONE, ENTRY, LIMIT, INIT_ENTRY, prototype, in_memory_image, initializer_prototype, with_initializer

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_ROWS = 0x20000000   # test RAM only; never proposed as a real camera allocation


class Tracked(MenuMachine):
    def __init__(self, original, image=None):
        super().__init__(original)
        self.blob = original if image is None else image
        self.calls = []
        self.writes = []

    def store(self, address, value, size):
        super().store(address, value, size)
        self.writes.append((address, size))


def setup(original, image=None, row=0, saved=0, work=0, tone=0, scroll=0, relocate=False):
    m = Tracked(original, image)
    m.map(0x83CD0000, bytes(0x20000))
    for a, data in m.regions:
        if a == 0x83CD0000:
            offset = DATA_START + DELTA - a
            data[offset:offset + COPY_END-DATA_START] = original[DATA_START:COPY_END]
    if relocate:
        rows = original[0x119DE0:0x119E50] + struct.pack('>6HI', 0x809C, 601, 0x4049, 1, 1, 36, 0)
        m.map(SYNTHETIC_ROWS, rows)
        m.store(MENU+0x1C, SYNTHETIC_ROWS, 4)
        m.store(MENU+8, 8, 2)
        m.store(MENU+10, 8, 2)
    m.regs = [random.Random(400+i).getrandbits(32) for i in range(16)]
    m.regs[15], m.regs[14] = 0x10001000, 0x10001800
    m.store(CURRENT, MENU, 4)
    m.store(MENU+0xC, row-scroll, 2)
    m.store(MENU+0xE, scroll, 2)
    m.store(SAVED_MODE, saved, 1)
    m.store(WORK_MODE, work, 1)
    m.store(WORK_TONE, tone, 1)
    m.store(0x83CED108, PARENT, 4)
    m.writes.clear()
    return m


def apply_hook(m):
    # Synchronization 0x1468AE and any external task response are NOT executed.
    m.calls.append({'pc': '0x001468ae', 'arg': m.regs[4],
                    'saved_mode': m.load(SAVED_MODE, 1), 'work_mode': m.load(WORK_MODE, 1),
                    'work_tone': m.load(WORK_TONE, 1)})


def observed(m):
    return tuple(m.load(a, s) for a, s in ((SAVED_MODE, 1), (WORK_MODE, 1), (WORK_TONE, 1), (CURRENT, 4)))


def ram(m):
    return bytes(next(data for a, data in m.regions if a == 0x83CD0000))


def execute(m, pc=ENTRY, arg=0):
    before = list(m.regs)
    m.run(pc, arg=arg, hooks={0x1468AE: apply_hook})
    for i in (8, 9, 10, 11, 14, 15):
        assert m.regs[i] == before[i], ('callee-saved register', pc, i)
    return observed(m)


def main(path, output):
    original = require_b(path)
    image, labels = in_memory_image(original)
    code, _ = prototype()
    report = {'result': 'RUNNING', 'input_sha256': hashlib.sha256(original).hexdigest(),
              'prototype_kind': 'incomplete CPU-only action handler; not an installable firmware',
              'prototype_code_bytes': len(code), 'original_function_bytes': LIMIT-ENTRY,
              'prototype_code_hex': code.hex(), 'prototype_labels': {k: hex(v) for k,v in labels.items()},
              'hooks': ['0x1468ae synchronization and external responses are recorded, not executed'],
              'synthetic_row_address': hex(SYNTHETIC_ROWS), 'real_ram_allocation_proven': False}

    bad_inputs=0
    for position in (0,0x103FA4,len(original)-1):
        altered=bytearray(original);altered[position]^=1
        try: MenuMachine(bytes(altered))
        except ValueError: bad_inputs+=1
        else: raise AssertionError('Invalid firmware was accepted')
    try: MenuMachine(b'')
    except ValueError: bad_inputs+=1
    else: raise AssertionError('Empty firmware was accepted')
    report['invalid_original_inputs_rejected']=bad_inputs

    # The new instructions are checked independently against all nibble/byte cases.
    mask_cases = 0
    for op in (0x8000, 0x8100, 0x9000, 0x9100):
        for nibble in range(16):
            for old in range(256):
                m = MenuMachine(original)
                m.map(0x20000000, bytes([old]))
                m.map(0x21000000, struct.pack('>HH', op | nibble << 4, 0x9720))
                m.regs[0] = 0x20000000
                m.z, m.n, m.v, m.c = True, True, True, True
                m.run(0x21000000)
                hi = op in (0x8100, 0x9100)
                mask = nibble << 4 if hi else nibble
                expected = old | mask if op in (0x9000, 0x9100) else old & (mask | (15 if hi else 240))
                assert m.load(0x20000000, 1) == expected
                assert (m.z, m.n, m.v, m.c) == (True, True, True, True)
                mask_cases += 1
    report['nibble_instruction_cases'] = mask_cases

    baseline = 0
    for row, mode in enumerate((0, 1, 2, 3, 4, 6, None)):
        for old in range(256):
            for scroll in (0, min(2, row), row):
                saved, work, tone = old, (old*73+19)&255, (old*151+27)&255
                a = setup(original, row=row, saved=saved, work=work, tone=tone, scroll=scroll)
                b = setup(original, image, row=row, saved=saved, work=work, tone=tone, scroll=scroll)
                oa, ob = execute(a), execute(b)
                expected = (saved, work, tone, CUSTOM) if mode is None else ((saved&15)|(mode<<4), (work&0xC3)|(mode<<2), tone, PARENT)
                assert oa == ob == expected
                assert a.calls == b.calls
                assert ram(a) == ram(b), ('unexpected full RAM difference', row, old, scroll)
                baseline += 1
    report['original_vs_prototype_valid_row_cases'] = baseline

    cinema = 0
    for old in range(256):
        for scroll in (0, 1, 2, 7):
            saved, work, tone = (old*29+37)&255, (old*73+19)&255, old
            m = setup(original, image, row=7, saved=saved, work=work, tone=tone, scroll=scroll, relocate=True)
            assert execute(m) == ((saved&15)|0x50, (work&0xC3)|0x14, (tone&0xE3)|0x18, PARENT)
            assert len(m.calls) == 1 and m.calls[0]['arg'] == 2
            allowed = {SAVED_MODE, WORK_MODE, WORK_TONE, *range(CURRENT, CURRENT+4)}
            assert all(0x10000000 <= a < 0x10002000 or all(a+i in allowed for i in range(s)) for a,s in m.writes)
            cinema += 1
    report['cinema_synthetic_row_cases'] = cinema

    relocated = 0
    for row in range(7):
        m = setup(original, image, row=row, saved=0xA9, work=0xAB, tone=0xA5, relocate=True)
        execute(m)
        if row == 6: assert m.load(CURRENT, 4) == CUSTOM and not m.calls
        else: assert len(m.calls) == 1 and m.load(CURRENT, 4) == PARENT
        relocated += 1
    report['relocated_existing_row_cases'] = relocated

    # Actual original action plus Done, with normal submenu transitions unhooked.
    done_cases = 0
    for old in range(256):
        m = setup(original, row=6, saved=old, work=old ^ 0x55, tone=old)
        execute(m)
        assert m.load(CURRENT, 4) == CUSTOM
        m.store(CURRENT, 0x83CE5A9C, 4)
        m.store(0x83CE5A9C+0xC, 0, 2); m.store(0x83CE5A9C+0xE, 6, 2)
        execute(m, 0x144696)
        assert m.load(CURRENT, 4) == CUSTOM and m.load(WORK_TONE, 1) == (old&0xE3)|0x18
        m.store(CUSTOM+0xC, 0, 2); m.store(CUSTOM+0xE, 0, 2)
        execute(m, 0x144302)
        assert observed(m) == ((old&15)|0x50, ((old^0x55)&0xC3)|0x14, (old&0xE3)|0x18, PARENT)
        assert len(m.calls) == 1 and m.calls[0]['arg'] == 2
        done_cases += 1
    report['original_custom_tone_done_cases'] = done_cases

    # Candidate -> original context decoder and tone selector. No pixel ASIC model.
    bridge = 0
    for old in (0, 1, 127, 128, 254, 255):
        m = setup(original, image, row=7, saved=old, work=old, tone=old, relocate=True)
        execute(m)
        for group in (0, 1, 2):
            c = MenuMachine(original)
            c.map(0x20000000, bytes(0x1800)); c.map(0x83EB3000, bytes(0x6000))
            c.store(0x83EB5864, 0x20000000, 4)
            c.store(0x2000002C, m.load(WORK_TONE, 1), 1)
            c.store(0x2000002D, m.load(WORK_MODE, 1), 1)
            c.run(0x31ED1A, stop=0x31ED3C)
            assert c.load(0x83EB3D50, 4) == 6
            c.store(0x83EB3CD4, group, 4)
            c.run(0x31F7B6, stop=0x31FA64)
            assert c.load(0x83EB3CC0, 4) == 23
            bridge += 1
    report['shortcut_to_original_tone_selector_cases'] = bridge

    switch_cases = 0
    for row, mode in enumerate((0, 1, 2, 3, 4, 6)):
        m = setup(original, image, row=7, saved=0x59, work=0x54, tone=0x04, relocate=True)
        execute(m)
        m.store(CURRENT, MENU, 4); m.store(MENU+0xC, row, 2); m.store(MENU+0xE, 0, 2)
        execute(m)
        assert (m.load(SAVED_MODE,1)>>4) == mode
        assert ((m.load(WORK_MODE,1)>>2)&15) == mode
        assert m.load(WORK_TONE,1) == 0x18
        switch_cases += 1
    report['switch_out_of_shortcut_cases'] = switch_cases

    invalid = 0
    for row in (-1, -2, 8, 9, 32767):
        m = setup(original, image, row=row, saved=0x59, work=0x54, tone=0x04)
        before = ram(m)
        execute(m)
        assert ram(m) == before and not m.calls
        invalid += 1
    report['invalid_synthetic_indices_rejected'] = invalid

    # Direct proof that mode 7 is not a free persisted ID: original validator.
    validation = 0
    for mode in range(16):
        for low in range(16):
            m = setup(original, saved=mode<<4 | low)
            m.run(0x14325E, arg=0x83CE957B, stop=0x143274)
            assert m.load(SAVED_MODE,1) == ((mode<<4 | low) if mode <= 6 else low)
            validation += 1
    report['original_mode_validation_prefix_cases'] = validation

    # New handler isn't enough: unmodified cursor still selects Custom for mode 5.
    cursor = []
    for mode in range(7):
        m = setup(original, saved=mode<<4)
        m.run(0x143EF6)
        selected = m.load(MENU+0xC,2) + m.load(MENU+0xE,2)
        expected = (0,1,2,3,4,6,5)[mode]
        assert selected == expected
        cursor.append({'mode': mode, 'selected_row': selected})
    report['original_cursor_results'] = cursor
    m = setup(original, image, row=7)
    execute(m); m.store(CURRENT,MENU,4); m.run(0x143EF6)
    assert m.load(MENU+0xC,2)+m.load(MENU+0xE,2) == 6
    m = setup(original, image, row=7, relocate=True)
    execute(m); m.store(CURRENT,MENU,4); m.run(0x143EF6)
    selected = m.load(MENU+0xC,2)+m.load(MENU+0xE,2)
    assert selected == 146
    report['known_unresolved_cursor_after_shortcut'] = {
        'original_row_array': 'Unchanged initializer selects row 6 Custom, not proposed row 7 Cinema2383.',
        'relocated_synthetic_row_array': {'selected_sum':selected, 'viewport_start':m.load(MENU+0xE,2),
            'row_within_viewport':m.load(MENU+0xC,2),
            'meaning':'Invalid cursor: initializer subtracts the new row base from a hardcoded old row address.'}}

    fixed, init_labels = with_initializer(original)
    init_code, _ = initializer_prototype()
    cursor_fixed = 0
    for relocated in (False, True):
        for mode in range(16):
            for tone in range(256):
                m = setup(original, fixed, saved=(mode<<4)|9, tone=tone, relocate=relocated)
                # For eight rows the same layout values are explicitly used in both tests.
                # Nonrelocated row 7 aliases Custom header, so this only tests positioning;
                # no row content is read or selected in this part.
                m.store(MENU+8,8,2);m.store(MENU+10,8,2)
                m.run(INIT_ENTRY)
                selected=m.load(MENU+0xC,2)+m.load(MENU+0xE,2)
                expected=0 if mode>6 else ((7 if ((tone>>2)&7)==6 else 6) if mode==5 else (5 if mode==6 else mode))
                assert selected==expected
                assert m.load(0x83CE98F4,1)&0x40
                cursor_fixed += 1
    report['prototype_cursor_restore_cases'] = cursor_fixed
    report['prototype_initializer_bytes'] = len(init_code)
    report['prototype_initializer_hex'] = init_code.hex()
    report['prototype_initializer_labels'] = {k:hex(v) for k,v in init_labels.items()}

    # Original label measurement and drawing each dereference table[index+1].
    languages = json.loads((ROOT/'data/language_tables.json').read_text())
    spans = []; span_cases = 0
    for language in languages:
        table = int(language['table_rom'],16)
        for index in (34,40,43,45,48,65,600,601):
            m = setup(original)
            m.store(0x83CE3FEC,table,4)
            m.regs[9]=0x83CE3FE8; m.regs[7]=index
            m.run(0x7C222, stop=0x7C23A)
            start,end = m.regs[6],m.regs[7]
            assert (start,end) == (int.from_bytes(original[table-BASE+4*index:table-BASE+4*index+4],'big'),
                                  int.from_bytes(original[table-BASE+4*index+4:table-BASE+4*index+8],'big'))
            d = setup(original)
            d.store(0x83CE3FEC,table,4); d.regs[8]=index
            d.run(0x7CB78,stop=0x7CBB0)
            assert d.load(d.regs[15]+0x10,4)==start and d.load(d.regs[15]+0x14,4)==end
            valid = BASE <= start <= end <= BASE+len(original)
            if index <= 600: assert valid
            else: assert not valid
            spans.append({'table_rom':hex(table),'index':index,'start':hex(start),'end':hex(end),'valid_span':valid})
            span_cases += 2
    report['original_label_span_prefix_cases'] = span_cases
    report['language_tables_tested'] = len(languages)
    report['new_label_index_601_without_extension_is_invalid'] = True
    (ROOT/'data/menu_label_span_validation.json').write_text(json.dumps(spans,indent=2)+'\n')

    # Count-only edit aliases the next menu header; it cannot add a valid row.
    row7 = struct.unpack_from('>6HI', original, 0x119DE0+7*16)
    report['count_only_eighth_row'] = {'file_offset':'0x00119e50', 'aliases':'Custom menu header',
                                      'fields':[hex(x) for x in row7], 'is_valid_added_item':False}
    report['unresolved'] = ['Physical RAM placement and initializer for 8 contiguous mutable rows',
                            'Cinema2383 string span in every supported language and both string consumers',
                            'Parent menu indication for Custom/tone=6; prototype cursor tested only in synthetic layout',
                            'Actual button dispatcher, scrolling and row visibility',
                            'Synchronization success/errors, persistence across power cycles',
                            'Full-frame paired camera samples with EXIF and scene settings']
    report['result'] = 'PASS_WITH_EXPLICIT_INCOMPLETE_DEPLOYMENT'
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n')
    evidence = ROOT/'evidence'
    ranges = [('B_optimize_initializer',0x143EF6,0x143FA4), ('B_optimize_action',ENTRY,LIMIT),
              ('B_custom_done',0x144302,0x144380), ('B_selected_submenu',0x14C166,0x14C190),
              ('B_original_mode_validator_prefix',0x14325E,0x143274),
              ('B_cursor_position',0x132D0C,0x132D8C),
              ('B_string_span_measure',0x7C222,0x7C23E),
              ('B_string_span_draw',0x7CB78,0x7CBB4),
              ('B_settings_sync',0x1468AE,0x1468FC)]
    for name,start,end in ranges:
        (evidence/(name+'_v11.asm.txt')).write_text('\n'.join(listing(original,start-BASE,end-BASE))+'\n')
    (evidence/'B_CPU_ONLY_shortcut_prototype_v11.asm.txt').write_text(
        'Incomplete CPU-only prototype. NOT an installable firmware.\n' +
        '\n'.join(listing(image,ENTRY-BASE,ENTRY-BASE+len(code)))+'\n')
    (evidence/'B_CPU_ONLY_cursor_prototype_v11.asm.txt').write_text(
        'Incomplete CPU-only prototype. NOT an installable firmware.\n' +
        '\n'.join(listing(fixed,INIT_ENTRY-BASE,INIT_ENTRY-BASE+len(init_code)))+'\n')
    print(json.dumps({k:v for k,v in report.items() if k.endswith('_cases') or k in ('result','prototype_code_bytes')}, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('original_B'); p.add_argument('--output', type=Path, default=ROOT/'data/menu_shortcut_validation.json')
    a=p.parse_args(); main(a.original_B, a.output)
