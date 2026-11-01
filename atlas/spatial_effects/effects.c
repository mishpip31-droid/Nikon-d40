#include "effects.h"
#include <stdint.h>
#include <string.h>
static unsigned lo(unsigned a,unsigned b){return a<b?a:b;}
static int clamp(int x,int a,int b){return x<a?a:x>b?b:x;}
static int div_round(int n,int d){return n<0?-((-n+d/2)/d):(n+d/2)/d;}
static int params(const Frame*f,const Effects*e){
 return f&&e&&f->width>=2&&f->width<=4096&&!(f->width&1)&&f->height&&f->height<=4096
 &&(f->limited_range==0||f->limited_range==1)&&e->blur_radius<=8&&e->blur_mix<=256
 &&e->glow_strength<=256&&e->glow_threshold<=254&&e->vignette_strength<=256
 &&e->grain_strength<=32&&e->grain_size>=1&&e->grain_size<=8;
}
static size_t used(const Plane*p,unsigned w,unsigned h){return (size_t)(h-1)*p->stride+w;}
static int valid_plane(const Plane*p,unsigned w,unsigned h){return p->p&&p->stride>=w&&p->stride<=8192&&used(p,w,h)<=p->bytes;}
static int overlap(const void*a,size_t an,const void*b,size_t bn){
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 1;
 return x<y+bn&&y<x+an;
}
size_t effects_scratch(const Frame*f,const Effects*e){
 if(!params(f,e))return 0;
 size_t blur=(e->blur_radius&&e->blur_mix)?(2*e->blur_radius+1)*(size_t)f->width:0;
 size_t gw=(f->width+15)/16,gh=(f->height+15)/16;
 size_t glow=e->glow_strength?gw*gh+7*gw:0;
 return blur>glow?blur:glow;
}
static void hrow(const Plane*p,unsigned w,unsigned y,unsigned r,uint8_t*out){
 const uint8_t*s=p->p+(size_t)y*p->stride;unsigned n=2*r+1,sum=0;
 for(int k=-(int)r;k<=(int)r;k++)sum+=s[clamp(k,0,(int)w-1)];
 for(unsigned x=0;x<w;x++){
  out[x]=(uint8_t)((sum+n/2)/n);
  sum-=s[clamp((int)x-(int)r,0,(int)w-1)];
  sum+=s[clamp((int)x+(int)r+1,0,(int)w-1)];
 }
}
static void blur_plane(Plane*p,unsigned w,unsigned h,unsigned rx,unsigned ry,unsigned mix,uint8_t*ring){
 unsigned n=2*ry+1,head=0;
 for(unsigned i=0;i<n;i++)hrow(p,w,(unsigned)clamp((int)i-(int)ry,0,(int)h-1),rx,ring+(size_t)i*w);
 for(unsigned y=0;y<h;y++){
  uint8_t*d=p->p+(size_t)y*p->stride;
  for(unsigned x=0;x<w;x++){
   unsigned sum=0;for(unsigned i=0;i<n;i++)sum+=ring[(size_t)i*w+x];
   unsigned b=(sum+n/2)/n;d[x]=(uint8_t)((d[x]*(256-mix)+b*mix+128)/256);
  }
  if(y+1<h){hrow(p,w,lo(y+ry+1,h-1),rx,ring+(size_t)head*w);head=(head+1)%n;}
 }
}
/* Coordinate hash is deterministic and has no mutable global random state. */
static uint32_t hash(uint32_t x){x^=x>>16;x*=0x7feb352dU;x^=x>>15;x*=0x846ca68bU;return x^(x>>16);}
static int noise(unsigned x,unsigned y,const Effects*e){
 uint32_t h=hash((x/e->grain_size)*0x9e3779b9U^(y/e->grain_size)*0x85ebca6bU^e->seed);
 return (int)(h&255)-(int)((h>>8)&255);
}
static unsigned gain_at(unsigned x,unsigned y,unsigned w,unsigned h,unsigned strength){
 int nx=((int)(2*x)-(int)w+1)*256/(int)(w-1);
 int ny=h>1?((int)(2*y)-(int)h+1)*256/(int)(h-1):0;
 unsigned radius=(unsigned)(nx*nx+ny*ny)/2;
 /* Quadratic falloff gives a smooth derivative at the centre. */
 unsigned fall=(unsigned)(((uint64_t)radius*radius+32768)/65536);
 return 256-(unsigned)(((uint64_t)strength*fall+32768)/65536);
}
static unsigned sample(const uint8_t*map,unsigned gw,unsigned gh,unsigned x,unsigned y){
 unsigned ix=lo(x/16,gw-1),iy=lo(y/16,gh-1),jx=lo(ix+1,gw-1),jy=lo(iy+1,gh-1);
 unsigned fx=x%16,fy=y%16;
 unsigned a=map[iy*gw+ix]*(16-fx)+map[iy*gw+jx]*fx;
 unsigned b=map[jy*gw+ix]*(16-fx)+map[jy*gw+jx]*fx;
 return (a*(16-fy)+b*fy+128)/256;
}
int effects_apply(Frame*f,const Effects*e,uint8_t*scratch,size_t bytes){
 if(!params(f,e))return -1;
 unsigned w=f->width,h=f->height;Plane*planes[3]={&f->y,&f->cb,&f->cr};size_t lens[3];
 for(unsigned i=0;i<3;i++){unsigned pw=i?w/2:w;if(!valid_plane(planes[i],pw,h))return -1;lens[i]=used(planes[i],pw,h);}
 for(unsigned i=0;i<3;i++)for(unsigned j=i+1;j<3;j++)if(overlap(planes[i]->p,lens[i],planes[j]->p,lens[j]))return -1;
 size_t need=effects_scratch(f,e);
 if(need&&(!scratch||bytes<need))return -2;
 if(need)for(unsigned i=0;i<3;i++)if(overlap(scratch,need,planes[i]->p,lens[i]))return -1;
 if(e->blur_radius&&e->blur_mix){
  blur_plane(&f->y,w,h,e->blur_radius,e->blur_radius,e->blur_mix,scratch);
  unsigned cr=(e->blur_radius+1)/2;
  blur_plane(&f->cb,w/2,h,cr,e->blur_radius,e->blur_mix,scratch);blur_plane(&f->cr,w/2,h,cr,e->blur_radius,e->blur_mix,scratch);
 }
 int black=f->limited_range?16:0,white=f->limited_range?235:255;
 int cmin=f->limited_range?16:0,cmax=f->limited_range?240:255;
 unsigned gw=(w+15)/16,gh=(h+15)/16;
 if(e->glow_strength){
  /* Max extraction keeps small lights in the low-resolution mask. Artistic bloom,
     not optical simulation; interpolation is anchored to the block grid. */
  for(unsigned gy=0;gy<gh;gy++)for(unsigned gx=0;gx<gw;gx++){
   unsigned peak=0;
   for(unsigned y=gy*16;y<lo((gy+1)*16,h);y++)for(unsigned x=gx*16;x<lo((gx+1)*16,w);x++){
    unsigned v=(unsigned)clamp(((int)f->y.p[(size_t)y*f->y.stride+x]-black)*255/(white-black),0,255);if(v>peak)peak=v;
   }
   scratch[gy*gw+gx]=peak>e->glow_threshold?(uint8_t)((peak-e->glow_threshold)*255/(255-e->glow_threshold)):0;
  }
  Plane mask={scratch,(size_t)gw*gh,gw};blur_plane(&mask,gw,gh,3,3,256,scratch+(size_t)gw*gh);
 }
 if(!(e->glow_strength||e->vignette_strength||e->grain_strength))return 0;
 for(unsigned y=0;y<h;y++)for(unsigned x=0;x<w;x+=2){
  unsigned gains[2],alphas[2];
  for(unsigned k=0;k<2;k++){
   unsigned xx=x+k;uint8_t*p=f->y.p+(size_t)y*f->y.stride+xx;int v=*p;
   unsigned a=e->glow_strength?(sample(scratch,gw,gh,xx,y)*e->glow_strength+128)/256:0;
   v+=div_round((white-v)*(int)a,255);
   unsigned g=gain_at(xx,y,w,h,e->vignette_strength);v=black+div_round((v-black)*(int)g,256);
   if(e->grain_strength){int edge=clamp(v-black,0,(white-black)/2);int upper=clamp(white-v,0,(white-black)/2);if(upper<edge)edge=upper;
    v+=div_round(noise(xx,y,e)*(int)e->grain_strength*edge,255*((white-black)/2));}
   *p=(uint8_t)clamp(v,black,white);gains[k]=g;alphas[k]=a;
  }
  unsigned g=(gains[0]+gains[1]+1)/2,a=(alphas[0]+alphas[1]+1)/2;
  for(unsigned j=1;j<3;j++){
   uint8_t*p=planes[j]->p+(size_t)y*planes[j]->stride+x/2;int v=(int)*p-128;
   v=div_round(v*(int)(255-a),255);v=div_round(v*(int)g,256);*p=(uint8_t)clamp(128+v,cmin,cmax);
  }
 }
 return 0;
}
