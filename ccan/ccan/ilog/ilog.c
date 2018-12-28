/*(C) Timothy B. Terriberry (tterribe@xiph.org) 2001-2009 CC0 (Public domain).
 * See LICENSE file for details. */
#include "ilog.h"
#include <limits.h>

/*The fastest fallback strategy for platforms with fast multiplication appears
   to be based on de Bruijn sequences~\cite{LP98}.
  Tests confirmed this to be true even on an ARM11, where it is actually faster
   than using the native clz instruction.
  Define ILOG_NODEBRUIJN to use a simpler fallback on platforms where
   multiplication or table lookups are too expensive.

  @UNPUBLISHED{LP98,
    author="Charles E. Leiserson and Harald Prokop",
    title="Using de {Bruijn} Sequences to Index a 1 in a Computer Word",
    month=Jun,
    year=1998,
    note="\url{http://supertech.csail.mit.edu/papers/debruijn.pdf}"
  }*/
static UNNEEDED const unsigned char DEBRUIJN_IDX32[32]={
   0, 1,28, 2,29,14,24, 3,30,22,20,15,25,17, 4, 8,
  31,27,13,23,21,19,16, 7,26,12,18, 6,11, 5,10, 9
};

/* We always compile these in, in case someone takes address of function. */
#undef ilog32_nz
#undef ilog32
#undef ilog64_nz
#undef ilog64

int ilog32(uint32_t _v){
/*On a Pentium M, this branchless version tested as the fastest version without
   multiplications on 1,000,000,000 random 32-bit integers, edging out a
   similar version with branches, and a 256-entry LUT version.*/
# if defined(ILOG_NODEBRUIJN)
  int ret;
  int m;
  ret=_v>0;
  m=(_v>0xFFFFU)<<4;
  _v>>=m;
  ret|=m;
  m=(_v>0xFFU)<<3;
  _v>>=m;
  ret|=m;
  m=(_v>0xFU)<<2;
  _v>>=m;
  ret|=m;
  m=(_v>3)<<1;
  _v>>=m;
  ret|=m;
  ret+=_v>1;
  return ret;
/*This de Bruijn sequence version is faster if you have a fast multiplier.*/
# else
  int ret;
  ret=_v>0;
  _v|=_v>>1;
  _v|=_v>>2;
  _v|=_v>>4;
  _v|=_v>>8;
  _v|=_v>>16;
  _v=(_v>>1)+1;
  ret+=DEBRUIJN_IDX32[_v*0x77CB531U>>27&0x1F];
  return ret;
# endif
}

int ilog32_nz(uint32_t _v)
{
  return ilog32(_v);
}

int ilog64(uint64_t _v){
# if defined(ILOG_NODEBRUIJN)
  uint32_t v;
  int      ret;
  int      m;
  ret=_v>0;
  m=(_v>0xFFFFFFFFU)<<5;
  v=(uint32_t)(_v>>m);
  ret|=m;
  m=(v>0xFFFFU)<<4;
  v>>=m;
  ret|=m;
  m=(v>0xFFU)<<3;
  v>>=m;
  ret|=m;
  m=(v>0xFU)<<2;
  v>>=m;
  ret|=m;
  m=(v>3)<<1;
  v>>=m;
  ret|=m;
  ret+=v>1;
  return ret;
# else
/*If we don't have a 64-bit word, split it into two 32-bit halves.*/
#  if LONG_MAX<9223372036854775807LL
  uint32_t v;
  int      ret;
  int      m;
  ret=_v>0;
  m=(_v>0xFFFFFFFFU)<<5;
  v=(uint32_t)(_v>>m);
  ret|=m;
  v|=v>>1;
  v|=v>>2;
  v|=v>>4;
  v|=v>>8;
  v|=v>>16;
  v=(v>>1)+1;
  ret+=DEBRUIJN_IDX32[v*0x77CB531U>>27&0x1F];
  return ret;
/*Otherwise do it in one 64-bit operation.*/
#  else
  static const unsigned char DEBRUIJN_IDX64[64]={
     0, 1, 2, 7, 3,13, 8,19, 4,25,14,28, 9,34,20,40,
     5,17,26,38,15,46,29,48,10,31,35,54,21,50,41,57,
    63, 6,12,18,24,27,33,39,16,37,45,47,30,53,49,56,
    62,11,23,32,36,44,52,55,61,22,43,51,60,42,59,58
  };
  int ret;
  ret=_v>0;
  _v|=_v>>1;
  _v|=_v>>2;
  _v|=_v>>4;
  _v|=_v>>8;
  _v|=_v>>16;
  _v|=_v>>32;
  _v=(_v>>1)+1;
  ret+=DEBRUIJN_IDX64[_v*0x218A392CD3D5DBF>>58&0x3F];
  return ret;
#  endif
# endif
}

int ilog64_nz(uint64_t _v)
{
  return ilog64(_v);
}

