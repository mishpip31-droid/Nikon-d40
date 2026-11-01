"""Verify exact EXP02 build, modeled update checks and known incoming references."""
import argparse,binascii,hashlib,json,struct
from pathlib import Path
from atlas import require_b
from build_menu_experiment import assemble
from check_updater import probe_image,flash_commands

ROOT=Path(__file__).resolve().parents[1]


def main(original_path,exp_path,image_path,output):
    original=require_b(original_path);exp=Path(exp_path).read_bytes();image=Path(image_path).read_bytes()
    expected,manifest=assemble(original,exp)
    assert image==expected
    probe=probe_image(original,image);assert probe['accepted']
    table=struct.unpack_from('>256H',original,0x83A88)
    crc=0
    for byte in image:crc=((crc<<8)^table[(crc>>8)^byte])&65535
    assert crc==binascii.crc_hqx(image,0)==0
    programs=[x for x in flash_commands(original)['commands'] if x['op']=='program']
    changed=[i for i,(x,y) in enumerate(zip(original,image)) if x!=y]
    assert all(any(int(c['address'],16)<=i+0x40000<int(c['address'],16)+int(c['length'],16) for c in programs) for i in changed)
    refs=[]
    for off in range(0,len(original)-3,2):
        value=int.from_bytes(original[off:off+4],'big')
        if 0x143EF6<=value<0x1441A8 and not 0x103EF6<=off<0x1041A8:
            refs.append((off,value))
    allowed={**{0x995FC+4*i:v for i,v in enumerate((0x143F22,0x143F30,0x143F40,0x143F50,0x143F60,0x143F70,0x143F80))},
             **{0x114E64+12*i:0x143FA4 for i in range(7)},0x1166FC:0x143EF6,
             0x11BE72:0x14405E,0x1B97B0:0x144040,0x1BCEC4:0x144000}
    assert dict(refs)==allowed,refs
    # Old initializer jump table has one literal reference, within replaced code.
    assert [i for i in range(len(original)-3) if original[i:i+4]==bytes.fromhex('000d95fc')]==[0x103F18]
    # Apparent relative CALL words outside the replacement are halves of LDI:32.
    assert original[0x103B76:0x103B7C]==bytes.fromhex('9f8483ced224')
    assert original[0x103EA2:0x103EA8]==bytes.fromhex('9f8c83ced0fe')
    result={'result':'PASS','image_sha256':hashlib.sha256(image).hexdigest(),'size':len(image),
            'stored_crc':image[-2:].hex(),'whole_image_crc_residual':0,'reproducible_build':True,
            'precheck':probe,'changed_bytes_from_original':len(changed),
            'changed_bytes_from_EXP01':sum(x!=y for x,y in zip(image,exp)),
            'all_changes_in_scheduled_program_ranges':True,
            'known_aligned_literal_references':[{'file_offset':hex(o),'value':hex(v)} for o,v in refs],
            'reference_classification':{'0x995fc..0x99618':'old initializer jump table, only literal consumer replaced',
               'action_and_screen_records':'entry points retained at same addresses',
               '0x11be72':'adjacent u16 text index 0x14 and field 0x405e in Small picture item',
               '0x1b97b0,0x1bcec4':'font bitmap bytes, not code pointers'},
            'limits':['Literal scan is not a proof against all computed jumps or data accesses',
                      'File/flash operations use previous bounded models; no physical write',
                      'CRC and precheck acceptance do not establish successful installation or recovery']}
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('result','image_sha256','size','stored_crc','changed_bytes_from_original','changed_bytes_from_EXP01','all_changes_in_scheduled_program_ranges')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('original_B');p.add_argument('EXP01');p.add_argument('EXP02');p.add_argument('--output',type=Path,default=ROOT/'data/EXP02_binary_validation.json')
    a=p.parse_args();main(a.original_B,a.EXP01,a.EXP02,a.output)
