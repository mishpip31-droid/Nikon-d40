#ifndef D40_EFFECTS_H
#define D40_EFFECTS_H
#include <stddef.h>
#include <stdint.h>
/* Host-tested portable integer reference. NOT a Nikon firmware hook. */
typedef struct { uint8_t *p; size_t bytes; unsigned stride; } Plane;
typedef struct { Plane y,cb,cr; unsigned width,height; int limited_range; } Frame;
typedef struct {
 unsigned blur_radius,blur_mix; /* 0..8; mix 0..256 */
 unsigned glow_strength,glow_threshold; /* 0..256, 0..254 normalized luma */
 unsigned vignette_strength; /* 0..256 */
 unsigned grain_strength,grain_size; /* 0..32 code values; cells 1..8 */
 uint32_t seed;
} Effects;
size_t effects_scratch(const Frame*,const Effects*);
/* Returns 0 success, -1 invalid descriptor/options/overlap, -2 short scratch.
   Invalid calls do not modify planes. Buffers remain owned by caller. */
int effects_apply(Frame*,const Effects*,uint8_t*,size_t);
#endif
