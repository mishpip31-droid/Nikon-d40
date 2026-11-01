"""Reproduce the v2 storage, transport and tone evidence without modifying firmware."""
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from atlas import require_b
from fr_decode import listing


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')


def save_csv(path, rows):
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)


def extract(path, out):
    b = require_b(path)
    data, evidence = out/'data', out/'evidence'
    data.mkdir(parents=True, exist_ok=True); evidence.mkdir(parents=True, exist_ok=True)
    records = []
    for i in range(12):
        off = 0x95364 + i*8
        ram, length, reserved = struct.unpack_from('>IHH', b, off)
        records.append(dict(id=i, descriptor_file=hex(off), ram=hex(ram), length=length,
                            trailing_u16=reserved,
                            known_role={2:'Settings including Optimize/Custom',
                                        6:'PTP-uploaded tone-curve structure',
                                        8:'Alternate tone-curve structure; not a proven extra user slot'}.get(i,'Not assigned')))
    save_json(data/'storage_records.json', records); save_csv(data/'storage_records.csv', records)
    commands = []
    for i in range(48):
        off = 0xa482c + i*16
        ram, length, kind, callback = struct.unpack_from('>IIII', b, off)
        commands.append(dict(index=i, descriptor_file=hex(off), ram=hex(ram), length=length,
                             kind=kind, callback_cpu=hex(callback),
                             meaning={0:'receive/copy to descriptor RAM',1:'send/copy from descriptor RAM',
                                      2:'special; interpretation depends on command'}.get(kind,'unknown')))
    save_json(data/'transport_commands.json', commands); save_csv(data/'transport_commands.csv', commands)
    curve = struct.unpack_from('>2048H', b, 0x9c294)
    save_csv(data/'default_tone_curve.csv', [dict(index=i, value=v) for i,v in enumerate(curve)])
    corrections = struct.unpack_from('>36864b', b, 0x2f692e)
    save_json(data/'tone_correction_stats.json', {
        'rom':'0x33692e', 'file':'0x2f692e', 'size_bytes':0x9000,
        'layout':'4096 rows x 9 signed int8 columns; row stride initialized to 9 at CPU 0x31b6c6',
        'columns':[dict(index=i,min=min(corrections[i::9]),max=max(corrections[i::9]),
                        nonzero=sum(v!=0 for v in corrections[i::9])) for i in range(9)],
        'column_selection':'context[0x6ae]; selected earlier via CPU 0x31f7b6; not a free style ID'})
    save_json(data/'tone_pipeline.json', {
        'firmware_sha256':hashlib.sha256(b).hexdigest(), 'status':'static; not camera-tested',
        'upload':{'ptp_operation':'0x90c6','handler_cpu':'0x8510e','ram':'0x83e89310','bytes':0x1044,
                  'header_bytes':0x44,'sample_count':2048,'consumer_sample_type':'big-endian uint16',
                  'full_transport_format_verified':False,
                  'first_two_header_bytes':'both must be nonzero in observed consumers',
                  'full_header_semantics_known':False,'immediate_flash_commit_in_handler':False},
        'fallback':{'full_blob_rom':'0xdc250','samples_rom':'0xdc294','samples_file':'0x9c294'},
        'simple_expanders_cpu':['0x4bf06','0x4bf58'],
        'output':{'ram':'0x83eb586c','entries':4096,'bytes':8192,
                  'builder_cpu':'0x323c22','custom_branch_value':'0x17','selector_context_offset':'0x466',
                  'correction_context_offset':'0x6ae','correction_table_rom':'0x33692e',
                  'correction_table_all_zero_in_this_original':not any(corrections),
                  'formula':'clamp(interpolate_2048_to_4096(curve)[i]+signed8(correction[9*i+column]),0,4095)'},
        'hardware_copy':{'caller_cpu':'0x4b41c','copy_loop_cpu':'0x4bef6',
                         'destinations':['0x40018400','0x4001a400','0x4001c400'],
                         'uint16_entries_each':4096,'same_table_copied_to_all_three':True,
                         'channel_names':'not established from code alone'},
        'alternate_curve':{'ram':'0x83e882cc','storage_record':8,'fallback_rom':'0xdb250',
                           'condition':'selector==0x17, !(context[0x1d]&0x20), context[0x5a]>>4 < 4, ((context[0x2d]>>2)&15)==6'},
        'unresolved':['All 0x44 header fields','Precise transfer functions and pipeline color space',
                      'All context copies and shot-mode overrides','Color-matrix / 3D-LUT integration',
                      'Independent new style ID storage and menu dispatch','Hardware image validation']})
    ranges = [
        ('B_settings_commit',0x3fa,0x44c,0x40000),
        ('B_settings_restore_mirror',0x514,0x530,0x40000),
        ('B_storage_restore',0x2b44c,0x2b654,0x40000),
        ('B_storage_scan',0x2b654,0x2b708,0x40000),
        ('B_storage_commit_and_compare',0x2b708,0x2ba9a,0x40000),
        ('B_storage_flash_wrappers',0x2b40c,0x2b44c,0x40000),
        ('B_flash_erase_program_runtime',0x11ce68,0x11d1c4,0x83bcbaec),
        ('B_transport_prepare',0x694e0,0x69724,0x40000),
        ('B_transport_receive',0x69724,0x697e6,0x40000),
        ('B_transport_queue',0x6995a,0x69ab4,0x40000),
        ('B_transport_settings_callbacks',0x69cba,0x69f8e,0x40000),
        ('B_ptp_tone_transfer',0x45072,0x451de,0x40000),
        ('B_tone_simple_expanders',0xbf06,0xbfaa,0x40000),
        ('B_tone_builder',0x2e3c22,0x2e4020,0x40000),
        ('B_tone_hardware_setup',0xb41c,0xb5f8,0x40000),
        ('B_tone_copy_loop',0xbef6,0xbf06,0x40000),
        ('B_frame_settings_copy_call',0x5682,0x569c,0x40000),
        ('B_frame_settings_copy',0x793a,0x797e,0x40000),
        ('B_tone_context_decode_prefix',0x2ded1a,0x2ded6a,0x40000),
        ('B_tone_selector_and_correction',0x2df7b6,0x2dfb3c,0x40000),
        ('B_tone_context_result',0x2e34be,0x2e3562,0x40000),
        ('B_tone_correction_stride',0x2db6c6,0x2db6d2,0x40000),
    ]
    rows = []
    for name,start,end,base in ranges:
        lines = list(listing(b,start,end,base))
        if any('TRUNCATED' in line for line in lines):
            raise ValueError(f'Unaligned end: {name}')
        (evidence/(name+'.asm.txt')).write_text(
            'Static bounded listing; code/data boundaries and delay slots require review.\n'
            f'Original B SHA256: {hashlib.sha256(b).hexdigest()}\n'
            'FILE     CPU_PC   BYTES        MNEMONIC  OPERANDS\n'+'\n'.join(lines)+'\n')
        rows.append(dict(name=name,start_file=hex(start),end_file_exclusive=hex(end),
                         cpu_start=hex(base+start),address_delta=hex(base),
                         sha256=hashlib.sha256(b[start:end]).hexdigest()))
    save_json(data/'v2_evidence_ranges.json',rows)
    print(json.dumps({'storage_records':len(records),'transport_commands':len(commands),
                      'evidence_ranges':len(rows),'firmware_modified':False}))


if __name__ == '__main__':
    extract(Path(sys.argv[1]),Path(sys.argv[2]))
