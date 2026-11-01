#include "effects.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void){
 unsigned cases=0;
 for(unsigned w=2;w<=128;w*=2)for(unsigned h=1;h<=65;h=h*2+1){
  Frame f={0};f.width=w;f.height=h;Plane*p[3]={&f.y,&f.cb,&f.cr};
  for(unsigned i=0;i<3;i++){p[i]->stride=(i?w/2:w)+3;p[i]->bytes=p[i]->stride*h;p[i]->p=malloc(p[i]->bytes);assert(p[i]->p);for(size_t k=0;k<p[i]->bytes;k++)p[i]->p[k]=(uint8_t)(k*37+19);}
  Effects e={8,256,256,254,256,32,8,0xffffffff};size_t n=effects_scratch(&f,&e);uint8_t*s=malloc(n);assert(s);
  assert(effects_apply(&f,&e,s,n)==0);
  free(s);for(unsigned i=0;i<3;i++)free(p[i]->p);cases++;
 }
 printf("PASS ASan/UBSan: %u dimensions, all effects at maximum settings\n",cases);
 return 0;
}
