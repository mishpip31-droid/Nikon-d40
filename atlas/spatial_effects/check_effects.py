import ctypes as C,json,subprocess,tempfile,time,random
from pathlib import Path
ROOT=Path(__file__).resolve().parent
class Plane(C.Structure):_fields_=[('p',C.POINTER(C.c_uint8)),('bytes',C.c_size_t),('stride',C.c_uint)]
class Frame(C.Structure):_fields_=[('y',Plane),('cb',Plane),('cr',Plane),('width',C.c_uint),('height',C.c_uint),('limited_range',C.c_int)]
class Effects(C.Structure):_fields_=[(n,C.c_uint) for n in ('blur_radius','blur_mix','glow_strength','glow_threshold','vignette_strength','grain_strength','grain_size','seed')]
def effect(**kw):
 e=Effects();e.grain_size=1;e.glow_threshold=200;e.seed=40
 for k,v in kw.items():setattr(e,k,v)
 return e
class Buffers:
 def __init__(self,w,h,limited=0,seed=1):
  self.w,self.h=w,h;self.arr=[];self.planes=[];self.before=[]
  rng=random.Random(seed)
  for i,pw in enumerate((w,w//2,w//2)):
   stride=pw+13;n=stride*h;buf=(C.c_uint8*(n+64))(*([0xA7]*(n+64)))
   for y in range(h):
    for x in range(pw):buf[32+y*stride+x]=rng.randrange(16,236 if i==0 else 241) if limited else rng.randrange(256)
   self.arr.append(buf);self.planes.append(Plane(C.cast(C.byref(buf,32),C.POINTER(C.c_uint8)),n,stride));self.before.append(bytes(buf))
  self.f=Frame(*self.planes,w,h,limited)
 def fill(self,Y=128,Cb=128,Cr=128):
  for i,v in enumerate((Y,Cb,Cr)):
   p=self.planes[i]
   for y in range(self.h):
    for x in range(self.w if i==0 else self.w//2):p.p[y*p.stride+x]=v
 def active(self,i):
  p=self.planes[i];pw=self.w if i==0 else self.w//2
  return [[p.p[y*p.stride+x] for x in range(pw)] for y in range(self.h)]
 def guards(self):
  for i,(buf,p) in enumerate(zip(self.arr,self.planes)):
   raw=bytes(buf);assert raw[:32]==bytes([0xA7])*32 and raw[-32:]==bytes([0xA7])*32
   pw=self.w if i==0 else self.w//2
   for y in range(self.h):assert raw[32+y*p.stride+pw:32+(y+1)*p.stride]==bytes([0xA7])*13

def blur_ref(src,rx,ry,mix):
 h=len(src);w=len(src[0]);cl=lambda x,n:max(0,min(n-1,x))
 tmp=[[ (sum(src[y][cl(x+k,w)] for k in range(-rx,rx+1))+rx)//(2*rx+1) for x in range(w)] for y in range(h)]
 return [[(src[y][x]*(256-mix)+((sum(tmp[cl(y+k,h)][x] for k in range(-ry,ry+1))+ry)//(2*ry+1))*mix+128)//256 for x in range(w)] for y in range(h)]

def run():
 with tempfile.TemporaryDirectory() as td:
  so=Path(td)/'effects.so';subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-fPIC','-shared',str(ROOT/'effects.c'),'-o',str(so)],check=True)
  lib=C.CDLL(str(so));lib.effects_scratch.argtypes=[C.POINTER(Frame),C.POINTER(Effects)];lib.effects_scratch.restype=C.c_size_t
  lib.effects_apply.argtypes=[C.POINTER(Frame),C.POINTER(Effects),C.POINTER(C.c_uint8),C.c_size_t];lib.effects_apply.restype=C.c_int
  def apply(b,e,short=False):
   need=lib.effects_scratch(C.byref(b.f),C.byref(e));buf=(C.c_uint8*(need+64))(*([0x9B]*(need+64)))
   out=lib.effects_apply(C.byref(b.f),C.byref(e),C.cast(C.byref(buf,32),C.POINTER(C.c_uint8)),max(0,need-1) if short else need)
   assert bytes(buf[:32])==bytes([0x9B])*32 and bytes(buf[-32:])==bytes([0x9B])*32;b.guards();return out,need
  count=0
  for w,h in ((2,1),(2,3),(6,2),(18,17),(34,33),(128,64)):
   for limited in (0,1):
    b=Buffers(w,h,limited);assert apply(b,effect())[0]==0;assert [bytes(a) for a in b.arr]==b.before;count+=1
    for r in (1,3,8):
     b=Buffers(w,h,limited);src=[b.active(i) for i in range(3)]
     assert apply(b,effect(blur_radius=r,blur_mix=173))[0]==0
     for i in range(3):assert b.active(i)==blur_ref(src[i],r if i==0 else (r+1)//2,r,173)
     count+=1
    for e in (effect(grain_strength=12,grain_size=2),effect(vignette_strength=180),effect(glow_strength=120),effect(blur_radius=3,blur_mix=96,glow_strength=80,vignette_strength=90,grain_strength=8)):
     b=Buffers(w,h,limited);assert apply(b,e)[0]==0
     if limited:
      for i in range(3):assert all(16<=v<=(235 if i==0 else 240) for row in b.active(i) for v in row)
     count+=1
  # Flat fields, deterministic grain and zero-mean behaviour before clipping.
  b=Buffers(128,64);b.fill();assert apply(b,effect(blur_radius=8,blur_mix=256,glow_strength=128))[0]==0;assert all(v==128 for row in b.active(0) for v in row);count+=1
  a=Buffers(512,256);b=Buffers(512,256);a.fill();b.fill();e=effect(grain_strength=12,grain_size=2)
  apply(a,e);apply(b,e);assert a.active(0)==b.active(0);vals=[v for row in a.active(0) for v in row];assert min(vals)<128<max(vals) and abs(sum(vals)/len(vals)-128)<0.25
  assert all(v==128 for row in a.active(1) for v in row);count+=1
  b=Buffers(64,64);b.fill(200,128,128);apply(b,effect(vignette_strength=180));y=b.active(0);assert y[0][0]<y[31][31] and y[0]==list(reversed(y[0])) and y==list(reversed(y));count+=1
  b=Buffers(128,128);b.fill(0);b.planes[0].p[64*b.planes[0].stride+64]=255;apply(b,effect(glow_strength=160));y=b.active(0);assert y[64][64]==255 and y[63][63]>0 and y[0][0]==0;count+=1
  # Invalid descriptors/options and scratch shortage must leave all planes intact.
  for kind in ('short','stride','odd','overlap','scratch_alias','option'):
   b=Buffers(34,17);e=effect(blur_radius=3,blur_mix=100)
   if kind=='short':rc,_=apply(b,e,True)
   elif kind=='scratch_alias':rc=lib.effects_apply(C.byref(b.f),C.byref(e),b.f.y.p,10000)
   else:
    if kind=='stride':b.f.y.stride=1
    if kind=='odd':b.f.width=33
    if kind=='overlap':b.f.cb.p=b.f.y.p
    if kind=='option':e.blur_radius=9
    rc=lib.effects_apply(C.byref(b.f),C.byref(e),None,0)
   assert rc<0 and [bytes(a) for a in b.arr]==b.before;count+=1
  # Full-size execution establishes buffer feasibility on host, not camera timing.
  b=Buffers(3008,2000);e=effect(blur_radius=3,blur_mix=64,glow_strength=48,vignette_strength=70,grain_strength=5,grain_size=2)
  start=time.monotonic();rc,need=apply(b,e);elapsed=time.monotonic()-start;assert rc==0;count+=1
  report={'result':'PASS_HOST_REFERENCE','checks':count,'full_size':[3008,2000],'scratch_bytes_all_effects':need,'host_full_size_seconds':round(elapsed,3),'camera_speed_measured':False,'firmware_modified':False,'assumed_format':'planar 8-bit YCbCr 4:2:2; range supplied by caller','limitations':['no camera memory ownership/cache validation','glow uses low-resolution max mask and has block-grid bias','grain uses small constant cells, not calibrated film statistics','no target FR build or installed effect']}
  (ROOT/'validation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':run()
