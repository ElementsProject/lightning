#include <ccan/ilog/ilog.h>
#include <ccan/ilog/ilog.c>
#include <stdio.h>
#include <ccan/tap/tap.h>

/*Dead simple (but slow) versions to compare against.*/

static int test_ilog32(uint32_t _v){
  int ret;
  for(ret=0;_v;ret++)_v>>=1;
  return ret;
}

static int test_ilog64(uint64_t _v){
  int ret;
  for(ret=0;_v;ret++)_v>>=1;
  return ret;
}

#define NTRIALS (64)

int main(int _argc,const char *_argv[]){
  int i;
  int j;
  /*This is how many tests you plan to run.*/
  plan_tests(33 * NTRIALS * 3 + 65 * NTRIALS * 3);
  for(i=0;i<=32;i++){
    uint32_t v;
    /*Test each bit in turn (and 0).*/
    v=i?(uint32_t)1U<<(i-1):0;
    for(j=0;j<NTRIALS;j++){
      int l;
      l=test_ilog32(v);
      ok1(STATIC_ILOG_32(v)==l);
      ok1(ilog32(v)==l);
      ok1(ilog32_nz(v) == l || v == 0);
      /*Also try a few more pseudo-random values with at most the same number
         of bits.*/
      v=(1103515245U*v+12345U)&0xFFFFFFFFU>>((33-i)>>1)>>((32-i)>>1);
    }
  }

  for(i=0;i<=64;i++){
    uint64_t v;
    /*Test each bit in turn (and 0).*/
    v=i?(uint64_t)1U<<(i-1):0;
    for(j=0;j<NTRIALS;j++){
      int l;
      l=test_ilog64(v);
      ok1(STATIC_ILOG_64(v)==l);
      ok1(ilog64(v)==l);
      ok1(ilog64_nz(v) == l || v == 0);
      /*Also try a few more pseudo-random values with at most the same number
         of bits.*/
      v=(uint64_t)((2862933555777941757ULL*v+3037000493ULL)
	&0xFFFFFFFFFFFFFFFFULL>>((65-i)>>1)>>((64-i)>>1));
    }
  }
  return exit_status();
}
