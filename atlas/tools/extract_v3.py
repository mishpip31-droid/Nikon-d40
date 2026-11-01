"""Reproduce color evidence/tables from an exact, unmodified D40 B 1.11 file."""
import hashlib
import json
import struct
import sys
from pathlib import Path
from atlas import require_b
from color_tables import matrices, expand_profile, hue_model
from extract_v2 import save_json, save_csv
from fr_decode import listing


def extract(path,out):
    b = require_b(path)
    data,evidence = out/'data',out/'evidence'
    data.mkdir(parents=True,exist_ok=True); evidence.mkdir(parents=True,exist_ok=True)
    matrix_rows = []
    for bank,rom,count in [('M1',0x332888,18),('M2',0x33270e,21),('M1_mono',0x331b98,35)]:
        for i,values in enumerate(matrices(b,rom,count)):
            family = ('Ia','II','IIIa')[i//(6 if bank=='M1' else 7)] if bank!='M1_mono' else 'monochrome'
            matrix_rows.append(dict(bank=bank,index=i,family=family,rom=hex(rom+18*i),
                                    file=hex(rom-0x40000+18*i),
                                    **{f'm{r}{c}':values[3*r+c] for r in range(3) for c in range(3)},
                                    **{f'row_sum_{r}':sum(values[3*r:3*r+3]) for r in range(3)}))
    save_csv(data/'color_matrices.csv',matrix_rows)
    hue_rows = []
    for family in range(3):
        for h in range(7):
            values=[struct.unpack_from('>h',b,0x2f1af0+2*((family*4+k)*7+h))[0] for k in range(4)]
            hue_rows.append(dict(family=('Ia','II','IIIa')[family],internal_hue_step=h-3,menu_hue_degrees=3*(h-3),index=h,
                                 a=values[0],b=values[1],c=values[2],d=values[3],divisor=10000))
    save_csv(data/'hue_coefficients.csv',hue_rows)
    aux = []
    for profile in range(18):
        values=struct.unpack_from('>64H',b,0x2f1e0e+128*profile)
        for block in range(4):
            for i in range(16):
                aux.append(dict(profile=profile,block=block,index=i,value=values[16*block+i]))
    save_csv(data/'color_auxiliary_4x16.csv',aux)
    selectors = []
    for family,rom in enumerate((0x33fddb,0x33fc07,0x33fa33)):
        for row in range(78):
            selectors.append(dict(kind='auto',family=family,row=row,
                                  **{f'x_column_{i}':b[rom-0x40000+6*row+i] for i in range(6)}))
    for sat in range(1,4):
        selectors.append(dict(kind='manual',family='all',row=sat,
                              **{f'x_column_{i}':b[0x2fffaf+6*(sat-1)+i] for i in range(6)}))
    save_csv(data/'saturation_selection_tables.csv',selectors)
    lut_rows,stats = [],[]
    for profile in list(range(48))+list(range(1000,1005)):
        values = expand_profile(b,profile)
        stats.append(dict(profile=profile,generated_count=len(values),hardware_count=1024,
                          minimum=min(values),maximum=max(values),
                          sha256_generated_bytes=hashlib.sha256(bytes(values)).hexdigest()))
        lut_rows += [dict(profile=profile,index=i,value=v,hardware_copied=i<1024) for i,v in enumerate(values)]
    save_csv(data/'saturation_luts.csv',lut_rows)
    save_json(data/'saturation_lut_stats.json',stats)
    examples=[]
    for h in range(7):
        m=hue_model(b,matrices(b,0x33270e,1)[0],h,0)
        examples.append(dict(internal_hue_step=h-3,menu_hue_degrees=3*(h-3),**{f'm{r}{c}':m[3*r+c] for r in range(3) for c in range(3)}))
    save_csv(data/'hue_example_M2_index0_host_float32.csv',examples)
    ranges=[
        ('B_color_context_decode',0x31ed1a,0x31f380),
        ('B_color_stride_initialization',0x31b608,0x31b6b2),
        ('B_color_matrix_selection',0x320cd8,0x322504),
        ('B_color_hue_adjustment',0x322606,0x3229ca),
        ('B_color_saturation_selection',0x3232d8,0x3234be),
        ('B_color_context_serialization',0x3234be,0x3236da),
        ('B_color_hardware_configuration',0x4b41c,0x4b6a0),
        ('B_color_byte_to_halfword_copy',0x4bee6,0x4bef6),
        ('B_color_profile_expanders',0x324124,0x3243d6),
        ('B_integer_absolute_value',0xbecc2,0xbecd0),
    ]
    records=[]
    for name,start,end in ranges:
        lines=list(listing(b,start-0x40000,end-0x40000))
        if any('TRUNCATED' in line for line in lines): raise ValueError(name)
        (evidence/(name+'.asm.txt')).write_text(
            'Static bounded listing; not a complete CFG or proof of reachability.\n'
            f'Original B SHA256: {hashlib.sha256(b).hexdigest()}\n'
            'FILE     CPU_PC   BYTES        MNEMONIC  OPERANDS\n'+'\n'.join(lines)+'\n')
        records.append(dict(name=name,cpu_start=hex(start),cpu_end_exclusive=hex(end),
                            file_start=hex(start-0x40000),file_end_exclusive=hex(end-0x40000),
                            sha256=hashlib.sha256(b[start-0x40000:end-0x40000]).hexdigest()))
    save_json(data/'v3_evidence_ranges.json',records)
    save_json(data/'color_pipeline.json',{
        'firmware_sha256':hashlib.sha256(b).hexdigest(),
        'status':'Configuration path reverse engineered; pixel-domain order and image quality unverified',
        'context_global':'0x83eb5864',
        'decode_cpu':'0x31ed1a',
        'fields':{'tone':'(context[0x2c]>>2)&7','saturation':'context[0x2c]&3',
                  'color':'context[0x2d]>>6','hue':'signed8(context[0x2e])+3'},
        'color_mapping':{'Ia':{'stored':1,'processing':3,'M1_indices':[0,5],'M2_indices':[0,6]},
                         'II':{'stored':2,'processing':1,'M1_indices':[6,11],'M2_indices':[7,13]},
                         'IIIa':{'stored':0,'processing':4,'M1_indices':[12,17],'M2_indices':[14,20]}},
        'matrices':[
            {'name':'M1','table_rom':'0x332888','count':18,'ram':'0x83eb3be0',
             'context_offset':'0x3a4','negative_sign_bit':'0x400','hardware':'0x40010022'},
            {'name':'M2','table_rom':'0x33270e','count':21,'ram':'0x83eb3bbc',
             'context_offset':'0x3b6','negative_sign_bit':'0x200','hardware':'0x40010034'}],
        'hue':{'cpu':'0x322606','table_rom':'0x331af0','layout':'3 x 4 x 7 int16 / 10000',
               'families_identical':True,'rows_modified':[1,2],'clamp':[-511,511],
               'fp_validation':'Host float32 hooks, original FP helper implementations not executed'},
        'saturation':{'selector_cpu':'0x3232d8','ram_index':'0x83eb786c',
                      'context_offset':'0x46c','expand_cpu':'0x324124','color_decoder_cpu':'0x324306',
                      'compressed_rom':'0x34052b','profiles':48,'bytes_per_profile':511,
                      'output_ram':'0x83eb78f4','output_count':1024,'hardware':'0x4001ec00',
                      'copy_cpu':'0x4bee6','hardware_element_bytes':2,
                      'recurrence':'y[n]=(2*y[n-1]-y[n-2]+nibble-8)&255',
                      'x_ram':'0x83eb5858','q_ram':'0x83eb5868',
                      'x_q_physical_meaning':'unresolved'},
        'auxiliary':{'rom':'0x331e0e','profiles':18,'layout':'4 x 16 uint16 per profile',
                     'ram':['0x83eb3b7c','0x83eb3b3c','0x83eb3afc','0x83eb3abc'],
                     'context_offsets':['0x3dc','0x3fc','0x41c','0x43c'],
                     'hardware':['0x4001e400','0x4001e420','0x4001e440','0x4001e460'],
                     'pixel_function':'unresolved'},
        'monochrome':{'flag':'0x83eb3d1c','optimize_mode':6,'M1_rom':'0x331b98','M1_count':35,
                      'M2_rom':'0x3471f3','M2_values':list(b[0x3071f3:0x3071fc]),
                      'profile_ids':[1000,1004],'decoder_cpu':'0x3241a0',
                      'recurrence':'y[n]=(2*y[n-1]-y[n-2]+two_bit_field-2)&255',
                      'generated_count':1026,'hardware_copied_count':1024},
        'unresolved':['Sensor raw decoding and demosaic','All white-balance and scene overrides',
                      'Physical meanings and normalization of hardware LUT indices/values',
                      'Pixel-domain stage order and clipping/rounding',
                      'Availability of any programmable 3D LUT',
                      'Exact Cinema 2383 target transform; source file content unavailable',
                      'Camera/JPEG output and update acceptance']})
    print(json.dumps(dict(matrix_records=len(matrix_rows),color_profiles=48,mono_profiles=5,
                         evidence_ranges=len(ranges),firmware_modified=False)))


if __name__=='__main__': extract(Path(sys.argv[1]),Path(sys.argv[2]))
