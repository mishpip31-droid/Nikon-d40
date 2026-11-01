"""Execute original JPEG argument setup and register setup with OS/helpers modeled.
Does not read real image buffers or establish DMA/cache ownership.
"""
import argparse,hashlib,json,struct
from pathlib import Path
from atlas import require_b
from fr_color_machine import ColorMachine

def check(original_path,exp04_path,out):
 original=require_b(original_path);image=Path(exp04_path).read_bytes()
 assert hashlib.sha256(image).hexdigest()=='7adc8ac1223c84faa3d3dcdfdb2ca67c9b2ed1649098a0d794c44dbb2b29a722'
 cases=[]
 for record in range(3):
  for crop in (0,16):
   m=ColorMachine(original);m.blob=image
   descriptor,output,base=0x20000000,0x20001000,0x21000000
   m.map(descriptor,bytes(0x2000));m.map(0x40030000,bytes(0x1000))
   m.regs[8]=descriptor;m.regs[9]=output;m.regs[10]=0x22000000;m.regs[11]=crop
   m.regs[14]=0x10001800;m.regs[15]=0x10001000
   geom=0xC62D0+record*24
   w,h,stride=struct.unpack_from('>3H',original,geom-0x40000)
   m.store(m.regs[14]-12,geom,4);m.store(descriptor+12,base,4)
   sp=m.regs[15]
   m.run(0x48890,stop=0x49A7C)
   expected=[base+off-crop for off in (0x2F90,0x5CF590,0x8B5890)]
   assert m.regs[4:8]==[w,h,stride,expected[0]]
   assert [m.load(sp+i,4) for i in (0,4)]==expected[1:]
   saved=[m.regs[i] for i in (8,9,10,11,14,15)]
   noop=lambda c:None
   m.run(0x49A7C,arg=w,stop=0x49B0A,hooks={x:noop for x in (0x44BE8,0x4A164,0x49F74,0x4A086)})
   assert m.load(0x40030F02,2)==stride and m.load(0x40030F08,2)==stride//2
   assert m.load(0x40030F04,2)==w and m.load(0x40030F06,2)==h
   assert [m.load(0x40030F10+4*i,4) for i in range(3)]==expected
   cases.append({'geometry_record':record,'width':w,'height':h,'y_stride':stride,'chroma_stride':stride//2,'pointer_shift_bytes':crop,'pointers':[hex(x) for x in expected]})
 result={'result':'PASS_BOUNDED_JPEG_HANDOFF','cases':cases,'candidate_entry':'0x488ce (requires separate wrapper preserving arguments/stack and original call)','known_problem':'base offsets alone are insufficient: source pointers may be shifted by 16 bytes','helper_calls_modeled':['0x44be8','0x4a164','0x49f74','0x4a086'],'CPU_pixels_processed':False,'format_range_verified':False,'DMA_cache_ownership_verified':False,'firmware_modified':False}
 out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':result['result'],'cases':len(cases)},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('original_B');p.add_argument('EXP04');p.add_argument('--output',type=Path,required=True);a=p.parse_args();check(a.original_B,a.EXP04,a.output)
