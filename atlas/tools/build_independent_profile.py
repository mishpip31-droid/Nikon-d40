"""EXP04 candidate (EXP03 return-pointer fix): stock Custom and a separate fixed Cinema preset.

Uses a reserved on-disk optimize tag only at save/load boundaries. Runtime
camera/transport settings retain a stock mode. No new journal IDs or sizes.
"""
import argparse,binascii,hashlib,json,struct
from pathlib import Path
from atlas import require_b,BASE
from fr_decode import decode
from build_menu_experiment import assemble as menu_assemble, EXP01_SHA
from menu_shortcut_prototype import Asm,ENTRY,LIMIT,INIT_ENTRY,MENU,CURRENT,CUSTOM,PARENT,SAVED_MODE,WORK_MODE,WORK_TONE

ROOT=Path(__file__).resolve().parents[1]
FLAG=0x83CE58DB      # last byte of obsolete Normal descriptor; initialized to zero
ARENA=0x33692E
ARENA_END=ARENA+0x9000


class Encoder(Asm):
    def jump(self,target,reg=12):self.ldi(reg,target);self.word(0x9700|reg)
    def call_absolute(self,target):self.ldi(12,target);self.word(0x971C)


def farjump(target):return bytes.fromhex('9f8c')+struct.pack('>I',target)+bytes.fromhex('970c')


class Arena:
    def __init__(self):self.pos=ARENA;self.parts=[]
    def data(self,name,data,align=2):
        self.pos=(self.pos+align-1)&~(align-1);at=self.pos;self.parts.append((name,at,data));self.pos+=len(data)
        assert self.pos<=ARENA_END
        return at
    def code(self,name,fn):return self.data(name,fn(self.pos))


def action_code(base):
    a=Encoder(base);a.word(0x1708);a.word(0x1781);a.ldi(8,CURRENT);a.word(0x0480)
    a.ldi(1,MENU);a.word(0xAA10);a.branch(3,'ret')
    a.ldi(13,12,True);a.word(0x0101);a.word(0x97A1)
    a.ldi(13,14,True);a.word(0x0100);a.word(0x97A0);a.word(0xA610)
    a.word(0xA800);a.branch(10,'ret');a.word(0xA870);a.branch(13,'ret')
    a.word(0xA860);a.branch(2,'custom')
    a.ldi(5,FLAG);a.ldi(1,0,True);a.word(0x1651)
    a.word(0xA870);a.branch(3,'preset')
    a.ldi(1,1,True);a.word(0x1651);a.ldi(0,5,True);a.branch(0,'apply')
    a.label('preset');a.word(0xA850);a.branch(3,'apply');a.ldi(0,6,True)
    a.label('apply');a.word(0x8B03)
    a.ldi(5,SAVED_MODE);a.word(0x0651);a.ldi(2,15,True);a.word(0x8221);a.word(0x8B02);a.word(0xB442);a.word(0x9221);a.word(0x1651)
    a.ldi(5,WORK_MODE);a.word(0x0651);a.ldi(2,0xC3,True);a.word(0x8221);a.word(0x8B32);a.word(0xB422);a.word(0x9221);a.word(0x1651)
    a.ldi(4,2,True);a.call_absolute(0x1468AE);a.ldi(0,PARENT);a.branch(0,'set')
    a.label('custom');a.ldi(0,CUSTOM)
    a.label('set');a.word(0x1480)
    a.label('ret');a.word(0x0781);a.word(0x0708);a.word(0x9720)
    return a.finish()


def cursor_code(base):
    a=Encoder(base);a.word(0x1781);a.ldi(0,SAVED_MODE);a.word(0x0604);a.word(0xB044)
    a.word(0xA874);a.branch(10,'valid');a.ldi(4,0,True);a.branch(0,'position')
    a.label('valid');a.word(0xA854);a.branch(2,'custom');a.word(0xA864);a.branch(3,'position');a.ldi(4,5,True);a.branch(0,'position')
    a.label('custom');a.ldi(4,6,True);a.ldi(0,FLAG);a.word(0x0600);a.word(0xA810);a.branch(3,'position');a.ldi(4,7,True)
    a.label('position');a.call_absolute(0x132D0C);a.ldi(0,0x83CE98F4);a.word(0x9140);a.word(0x0781);a.word(0x9720)
    return a.finish()


def capture_code(base):
    a=Encoder(base)
    # Replay original initial two LDI:32 and complete original eight-byte copy.
    a.ldi(5,0x83CE97F3);a.ldi(6,0xCA818);a.ldi(0,WORK_TONE);a.ldi(13,8,True)
    a.label('copy');a.word(0xA5FD);a.word(0x020C);a.word(0x124C);a.word(0xA80D);a.branch(13,'copy')
    a.ldi(0,FLAG);a.word(0x0600);a.word(0xA810);a.branch(3,'leave')
    a.ldi(0,SAVED_MODE);a.word(0x0600);a.word(0xB040);a.word(0xA850);a.branch(3,'leave')
    # Independent snapshot: Normal sharpening, Normal saturation, Ia, hue 0.
    # Raw tone 7 marks the frame; the decoder presents tone 6 to stock math.
    a.ldi(0,0x3D,True);a.word(0x1640);a.ldi(13,1,True);a.ldi(0,0x54,True);a.word(0x1240)
    a.ldi(13,2,True);a.ldi(0,0,True);a.word(0x1240)
    a.label('leave');a.jump(0x47956)
    return a.finish()


def decoder_code(base):
    a=Encoder(base);a.ldi(11,0x83EB3D50);a.word(0xB5B0);a.word(0xB1D0)
    a.word(0xA870);a.branch(3,'store');a.ldi(0,6,True)
    a.label('store');a.word(0x14B0);a.jump(0x31ED3C)
    return a.finish()


def done_code(base):
    a=Encoder(base)
    # Clear the Cinema flag only for Custom's Done row, not its edit submenus.
    a.ldi(0,CURRENT);a.word(0x0401);a.ldi(13,12,True);a.word(0x0110)
    a.ldi(13,14,True);a.word(0x0111);a.word(0xA610);a.word(0xA800);a.branch(3,'original')
    a.ldi(0,FLAG);a.ldi(1,0,True);a.word(0x1601)
    a.label('original');a.word(0x1708);a.ldi(8,CURRENT);a.jump(0x14430A)
    return a.finish()


def save_code(base):
    a=Encoder(base);a.word(0x1781)
    a.ldi(0,FLAG);a.word(0x0600);a.word(0xA810);a.branch(3,'save')
    a.ldi(0,SAVED_MODE);a.word(0x0600);a.word(0xB040);a.word(0xA850);a.branch(3,'save')
    a.ldi(0,0x83CED21E);a.word(0x0601);a.ldi(2,15,True);a.word(0x8221);a.ldi(2,0x70,True);a.word(0x9221);a.word(0x1601)
    a.label('save');a.call_absolute(0x6B708)
    # Restore the working payload to the valid runtime byte, preserving return regs.
    a.word(0x1700);a.word(0x1701);a.ldi(0,0x83CED21E);a.ldi(1,SAVED_MODE);a.word(0x0611);a.word(0x1601);a.word(0x0701);a.word(0x0700)
    a.word(0x0781);a.jump(0x40440)
    return a.finish()


def load_code(base):
    a=Encoder(base);a.ldi(0,FLAG);a.ldi(1,0,True);a.word(0x1601)
    a.ldi(0,0x83CED21E);a.word(0x0601);a.word(0x8B12);a.word(0xB042);a.word(0xA872);a.branch(3,'original')
    a.ldi(0,FLAG);a.ldi(2,1,True);a.word(0x1602)
    a.ldi(0,0x83CED21E);a.ldi(2,15,True);a.word(0x8221);a.ldi(2,0x50,True);a.word(0x9221);a.word(0x1601)
    a.label('original');a.ldi(0,0x83CE957B);a.ldi(13,9,True);a.jump(0x40528)
    return a.finish()


def packing_code(base,matrices):
    a=Encoder(base)
    # Mark this frame before stock serialization continuation; keep all decisions per-frame.
    a.word(0x1702)
    a.word(0x0489);a.ldi(13,0x2C,True);a.word(0x0290);a.word(0xB5B0);a.word(0xB1D0);a.word(0xA870);a.branch(3,'pack_arrays')
    a.ldi(13,0x2D,True);a.word(0x0290);a.word(0xB5A0);a.word(0xB1C0);a.word(0xA850);a.branch(3,'normalize')
    a.ldi(0,0x1D,True);a.word(0xA690);a.word(0x8920);a.branch(3,'normalize')
    a.ldi(0,0x83EB3D1C);a.word(0x0400);a.word(0xA800);a.branch(3,'normalize')
    a.ldi(13,0x466);a.ldi(0,24,True);a.word(0x1290)
    # Normalize the transient raw marker before subsequent serialization/metadata use.
    a.label('normalize');a.ldi(0,0x2C,True);a.word(0xA690);a.word(0x0601);a.ldi(2,0xE3,True);a.word(0x8221);a.ldi(2,0x18,True);a.word(0x9221);a.word(0x1601)
    a.label('pack_arrays')
    a.word(0x0702)
    for source,offset,count,sign in ((0x83EB3BE0,0x3A4,9,0x400),(0x83EB3BBC,0x3B6,9,0x200),(0x83EB3B7C,0x3DC,16,0x200),(0x83EB3B3C,0x3FC,16,0x200),(0x83EB3AFC,0x41C,16,0x200),(0x83EB3ABC,0x43C,16,0x200)):
        a.word(0x0480);a.ldi(9,offset);a.word(0xA609);a.ldi(10,source);a.ldi(12,count,True);a.ldi(1,sign);a.fixups.append((len(a.data),16,'pack'));a.word(0)
    # The special fixup below is a relative CALL, not a condition branch.
    a.word(0x0489);a.ldi(13,0x466);a.word(0x0290);a.ldi(1,24,True);a.word(0xAA10);a.branch(3,'leave')
    a.ldi(0,0x1D,True);a.word(0xA690);a.word(0x8920);a.branch(3,'leave')
    a.ldi(0,0x3A4);a.word(0xA609);a.ldi(10,matrices);a.ldi(12,18,True)
    a.label('matrixcopy');a.word(0x05A0);a.word(0x1590);a.word(0xA42A);a.word(0xA429);a.word(0xA5FC);a.branch(3,'matrixcopy')
    a.label('leave');a.jump(0x3236DA)
    a.label('pack');a.word(0x04A4);a.word(0xA804);a.branch(11,'positive');a.ldi(0,0,True);a.word(0xAC40);a.word(0x9210);a.word(0x8B04)
    a.label('positive');a.word(0x1594);a.word(0xA44A);a.word(0xA429);a.word(0xA5FC);a.branch(3,'pack');a.word(0x9720)
    # Resolve CALLs using the same label map, then ordinary branches.
    calls=[x for x in a.fixups if x[1]==16];a.fixups=[x for x in a.fixups if x[1]!=16]
    for off,_,name in calls:
        displacement=(a.labels[name]-(a.base+off+2))//2;assert -1024<=displacement<=1023
        struct.pack_into('>H',a.data,off,0xD000|(displacement&2047))
    return a.finish()


def curve_code(base,curve):
    a=Encoder(base)
    a.ldi(13,0x466);a.word(0x0240);a.ldi(1,24,True);a.word(0xAA10);a.branch(3,'stock')
    a.word(0x1708);a.ldi(8,0x83EB586C);a.ldi(0,curve);a.ldi(1,4096)
    a.label('copy');a.word(0x0502);a.word(0x1582);a.word(0xA420);a.word(0xA428);a.word(0xA5F1);a.branch(3,'copy')
    a.ldi(4,0x83EB586C)  # ABI: return the start of the curve, not frame context.
    a.word(0x0708);a.word(0x9720)
    a.label('stock');a.word(0x8FF0);a.word(0x1781);a.word(0x0F04);a.ldi(8,0x83EB586C);a.jump(0x323C2E)
    return a.finish()


def assemble(original,exp01,candidate):
    menu,old_manifest=menu_assemble(original,exp01)
    image=bytearray(menu)
    # Return all five EXP01 color changes to stock before installing the separated path.
    for off,length in ((0x9C294,4096),(0x2E3562,376),(0x2E3EFE,2),(0xBF10,2),(0xBF62,2)):
        image[off:off+length]=original[off:off+length]
    assert original[ARENA-BASE:ARENA_END-BASE]==bytes(0x9000)
    arena=Arena()
    matrices=[]
    for name,sign in (('M1_candidate_Q9',0x400),('M2_candidate_Q8',0x200)):
        for row in candidate[name]:
            for x in row:matrices.append(x if x>=0 else -x|sign)
    matrix=arena.data('cinema_matrices',struct.pack('>18H',*matrices))
    curve=arena.data('cinema_curve_4096',struct.pack('>4096H',*candidate['curve_4096']))
    addresses={}
    for name,fn in (('menu_action',action_code),('menu_cursor',cursor_code),('capture',capture_code),('tone_decoder',decoder_code),('custom_done',done_code),('save',save_code),('load',load_code),('packing',lambda at:packing_code(at,matrix)),('curve',lambda at:curve_code(at,curve))):
        addresses[name]=arena.code(name,fn)
    # Replace every actual correction load in the original curve builder with zero.
    loads=[];off=0x2E3C22
    while off<0x2E4040:
        n,name,operands=decode(original,off)
        if name=='LDUB' and operands=='@(r13+r10),r0':
            assert original[off:off+2]==bytes.fromhex('02a0');image[off:off+2]=bytes.fromhex('c000');loads.append(hex(off))
        off+=n
    assert loads
    patches=((ENTRY,addresses['menu_action'],8),(INIT_ENTRY,addresses['menu_cursor'],8),
             (0x4793A,addresses['capture'],12),(0x31ED30,addresses['tone_decoder'],12),
             (0x144302,addresses['custom_done'],8),(0x40438,addresses['save'],8),
             (0x40520,addresses['load'],8),(0x323562,addresses['packing'],8),(0x323C22,addresses['curve'],12))
    for cpu,target,length in patches:image[cpu-BASE:cpu-BASE+length]=farjump(target)+bytes.fromhex('9fa0')*((length-8)//2)
    # Metadata generated before marker normalization labels reserved tone 7 as CS.
    assert original[0x8FC1C:0x8FC20]==bytes.fromhex('000cfc30')
    image[0x8FC1C:0x8FC20]=original[0x8FC18:0x8FC1C]
    for name,at,data in arena.parts:image[at-BASE:at-BASE+len(data)]=data
    image[-2:]=binascii.crc_hqx(image[:-2],0).to_bytes(2,'big')
    assert len(image)==len(original) and binascii.crc_hqx(image,0)==0
    return bytes(image),{'build':'EXP04_INDEPENDENT_PRESET_RETURN_POINTER_FIX','sha256':hashlib.sha256(image).hexdigest(),'size':len(image),'crc':image[-2:].hex(),'camera_tested':False,'flag_RAM':hex(FLAG),'arena_used':arena.pos-ARENA,'arena':[{ 'name':n,'cpu':hex(a),'bytes':len(d)} for n,a,d in arena.parts],'entry_addresses':{k:hex(v) for k,v in addresses.items()},'zero_correction_loads':loads,'on_disk_mode_tag':7,'curve_return_pointer':'0x83eb586c','runtime_mode':5,'Cinema_snapshot_bytes':'3d5400','Custom_parameters_overwritten':False,'stock_Custom_curve_bytes_restored':True,'stock_curve_getters_restored':True,'independent_parameters_are_fixed_ROM_preset':True}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('original_B');p.add_argument('EXP01');p.add_argument('candidate_json');p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();image,manifest=assemble(require_b(a.original_B),Path(a.EXP01).read_bytes(),json.loads(Path(a.candidate_json).read_text()))
    a.output.mkdir(parents=True,exist_ok=False);(a.output/'D40_EXP04_RETURN_POINTER_FIX_NOT_CAMERA_TESTED.bin').write_bytes(image);(a.output/'patch_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
