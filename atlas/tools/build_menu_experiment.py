"""Experimental eight-row menu on exact EXP01. Device behavior is unconfirmed.

All new code, descriptors and text replace occupied optimize handler space
after compacting it. No guessed RAM address or expanded persisted enum.
"""
import argparse
import binascii
import hashlib
import json
import struct
from pathlib import Path
from atlas import require_b
from menu_shortcut_prototype import Asm, ENTRY, LIMIT, INIT_ENTRY, INIT_LIMIT, prototype, initializer_prototype

ROOT=Path(__file__).resolve().parents[1]
EXP01_SHA='8abfda8cc67f787be867fd3d348fd38fcc27b8e041702625d182a968052148a8'
TEXT_ID=601


class Encoder(Asm):
    def jump(self,target,reg=12):
        self.ldi(reg,target)
        self.word(0x9700|reg)


def measurement_wrapper(start,label):
    a=Encoder(start)
    a.ldi(0,TEXT_ID)
    a.word(0xAA07)                  # CMP r0,r7; r0 overwritten in normal path
    a.branch(3,'normal')
    a.word(0x8BE4);a.word(0xA5C4)
    a.ldi(6,label);a.ldi(7,label+10)
    a.jump(0x7C23A)
    a.label('normal')
    # Replay the original 8 bytes overwritten at 0x7c222.
    for word in (0xC04D,0x8BE4,0x0090,0xA5C4):a.word(word)
    a.jump(0x7C22A)
    return a.finish()


def drawing_wrapper(start,label):
    a=Encoder(start)
    # r0 will be replaced by the original LD @r12,r0 in the normal path.
    a.ldi(0,TEXT_ID);a.word(0xAA08)
    a.branch(3,'normal')
    # Reconstruct the exact arguments originally prepared by 0x7cb78..0x7cbb0.
    a.word(0x4111);a.word(0x97A1);a.word(0x1301)
    a.word(0x4131);a.word(0x8BE4);a.word(0xA5C4);a.word(0x97A1)
    a.word(0x1311);a.word(0x132A);a.word(0x1339)
    a.word(0x61F5);a.ldi(6,0,True)
    a.ldi(0,label);a.word(0x1340)
    a.ldi(0,label+10);a.word(0x1350)
    a.ldi(7,0,True);a.word(0x41D0);a.word(0x136B)
    a.jump(0x7CBB0)
    a.label('normal')
    a.ldi(12,0x83CE3FEC);a.word(0x4111)
    a.jump(0x7CB80,reg=0)          # keep r12 pointing at the language table global
    return a.finish()


def jump_bytes(target):
    return bytes.fromhex('9f8c')+struct.pack('>I',target)+bytes.fromhex('970c')


def assemble(original, exp01):
    assert len(exp01)==len(original) and hashlib.sha256(exp01).hexdigest()==EXP01_SHA
    assert binascii.crc_hqx(exp01,0)==0
    assert original[INIT_ENTRY-0x40000:LIMIT-0x40000]==exp01[INIT_ENTRY-0x40000:LIMIT-0x40000]
    action,_=prototype();init,_=initializer_prototype()
    measure=INIT_ENTRY+len(init)
    draw=ENTRY+len(action)
    # Layout sizes are independent of the literal label address.
    measure_code=measurement_wrapper(measure,0)
    draw_code=drawing_wrapper(draw,0)
    assert measure+len(measure_code)<=INIT_LIMIT
    rows=(draw+len(draw_code)+3)&~3
    label=rows+128
    assert label+10<=LIMIT
    measure_code=measurement_wrapper(measure,label)
    draw_code=drawing_wrapper(draw,label)
    descriptors=original[0x119DE0:0x119E50]+struct.pack('>6HI',0x809C,TEXT_ID,0x4049,1,1,36,0)
    block=bytearray(bytes.fromhex('9fa0')*((LIMIT-INIT_ENTRY)//2))
    for at,data in ((INIT_ENTRY,init),(measure,measure_code),(ENTRY,action),(draw,draw_code),(rows,descriptors),(label,b'Cinema2383')):
        off=at-INIT_ENTRY
        block[off:off+len(data)]=data
    patches=[(INIT_ENTRY-0x40000,bytes(block),'compact optimize initializer/action; wrappers, ROM row array and text'),
             (0x3C222,jump_bytes(measure),'new text ID in original measurement path'),
             (0x3CB78,jump_bytes(draw),'new text ID in original drawing path'),
             (0x119DC8,struct.pack('>HH',8,8),'eight rows in optimize header'),
             (0x119DDC,struct.pack('>I',rows),'row pointer uses read-only firmware descriptors')]
    assert original[0x3C222:0x3C22A]==bytes.fromhex('c04d8be40090a5c4')
    assert original[0x3CB78:0x3CB80]==bytes.fromhex('9f8c83ce3fec4111')
    image=bytearray(exp01)
    manifest=[]
    for off,data,reason in patches:
        assert original[off:off+len(data)]==exp01[off:off+len(data)],('overlap EXP01',hex(off))
        manifest.append({'file_offset':hex(off),'length':len(data),'before_hex':exp01[off:off+len(data)].hex(),'after_hex':data.hex(),'reason':reason})
        image[off:off+len(data)]=data
    crc=binascii.crc_hqx(image[:-2],0);image[-2:]=crc.to_bytes(2,'big')
    assert len(image)==len(original) and binascii.crc_hqx(image,0)==0
    result={'build':'EXP02_MENU_ROM_ROWS','camera_tested':False,'base_EXP01_sha256':EXP01_SHA,
            'size':len(image),'sha256':hashlib.sha256(image).hexdigest(),'crc16_xmodem':hex(crc),
            'layout':{'initializer':hex(INIT_ENTRY),'initializer_bytes':len(init),'action':hex(ENTRY),'action_bytes':len(action),
                      'measurement_wrapper':hex(measure),'measurement_bytes':len(measure_code),'drawing_wrapper':hex(draw),
                      'drawing_bytes':len(draw_code),'rows_ROM':hex(rows),'rows_bytes':128,'label_ROM':hex(label),'label_bytes':10},
            'patches':manifest,'crc_file_offset':hex(len(image)-2),
            'limitations':['Read-only row array relies on menu consumers not storing into row descriptors',
                           'Shares Normal action record 36 for enable/availability/help metadata',
                           'New label hooks cover the two recovered type-0 string consumers',
                           'Custom parameter bank reused; no independent Cinema bank',
                           'No hardware or power-cycle test of this menu build']}
    return bytes(image),result


def main():
    p=argparse.ArgumentParser();p.add_argument('original_B');p.add_argument('EXP01');p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();original=require_b(a.original_B);image,manifest=assemble(original,Path(a.EXP01).read_bytes())
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'D40_Cinema2383_EXP02_MENU_NOT_CAMERA_TESTED.bin').write_bytes(image)
    (a.output/'patch_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ('build','size','sha256','crc16_xmodem','layout')},indent=2))


if __name__=='__main__':main()
