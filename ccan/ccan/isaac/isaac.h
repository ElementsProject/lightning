/* CC0 (Public domain) - see LICENSE file for details */
#if !defined(_isaac_H)
# define _isaac_H (1)
# include <stdint.h>



typedef struct isaac_ctx isaac_ctx;



/*This value may be lowered to reduce memory usage on embedded platforms, at
   the cost of reducing security and increasing bias.
  Quoting Bob Jenkins: "The current best guess is that bias is detectable after
   2**37 values for [ISAAC_SZ_LOG]=3, 2**45 for 4, 2**53 for 5, 2**61 for 6,
   2**69 for 7, and 2**77 values for [ISAAC_SZ_LOG]=8."*/
#define ISAAC_SZ_LOG      (8)
#define ISAAC_SZ          (1<<ISAAC_SZ_LOG)
#define ISAAC_SEED_SZ_MAX (ISAAC_SZ<<2)



/*ISAAC is the most advanced of a series of pseudo-random number generators
   designed by Robert J. Jenkins Jr. in 1996.
  http://www.burtleburtle.net/bob/rand/isaac.html
  To quote:
    No efficient method is known for deducing their internal states.
    ISAAC requires an amortized 18.75 instructions to produce a 32-bit value.
    There are no cycles in ISAAC shorter than 2**40 values.
    The expected cycle length is 2**8295 values.*/
struct isaac_ctx{
  unsigned n;
  uint32_t r[ISAAC_SZ];
  uint32_t m[ISAAC_SZ];
  uint32_t a;
  uint32_t b;
  uint32_t c;
};


/**
 * isaac_init - Initialize an instance of the ISAAC random number generator.
 * @_ctx:   The instance to initialize.
 * @_seed:  The specified seed bytes.
 *          This may be NULL if _nseed is less than or equal to zero.
 * @_nseed: The number of bytes to use for the seed.
 *          If this is greater than ISAAC_SEED_SZ_MAX, the extra bytes are
 *           ignored.
 */
void isaac_init(isaac_ctx *_ctx,const unsigned char *_seed,int _nseed);

/**
 * isaac_reseed - Mix a new batch of entropy into the current state.
 * To reset ISAAC to a known state, call isaac_init() again instead.
 * @_ctx:   The instance to reseed.
 * @_seed:  The specified seed bytes.
 *          This may be NULL if _nseed is zero.
 * @_nseed: The number of bytes to use for the seed.
 *          If this is greater than ISAAC_SEED_SZ_MAX, the extra bytes are
 *           ignored.
 */
void isaac_reseed(isaac_ctx *_ctx,const unsigned char *_seed,int _nseed);
/**
 * isaac_next_uint32 - Return the next random 32-bit value.
 * @_ctx: The ISAAC instance to generate the value with.
 */
uint32_t isaac_next_uint32(isaac_ctx *_ctx);
/**
 * isaac_next_uint - Uniform random integer less than the given value.
 * @_ctx: The ISAAC instance to generate the value with.
 * @_n:   The upper bound on the range of numbers returned (not inclusive).
 *        This must be greater than zero and less than 2**32.
 *        To return integers in the full range 0...2**32-1, use
 *         isaac_next_uint32() instead.
 * Return: An integer uniformly distributed between 0 and _n-1 (inclusive).
 */
uint32_t isaac_next_uint(isaac_ctx *_ctx,uint32_t _n);
/**
 * isaac_next_float - Uniform random float in the range [0,1).
 * @_ctx: The ISAAC instance to generate the value with.
 * Returns a high-quality float uniformly distributed between 0 (inclusive)
 *  and 1 (exclusive).
 * All of the float's mantissa bits are random, e.g., the least significant bit
 *  may still be non-zero even if the value is less than 0.5, and any
 *  representable float in the range [0,1) has a chance to be returned, though
 *  values very close to zero become increasingly unlikely.
 * To generate cheaper float values that do not have these properties, use
 *   ldexpf((float)isaac_next_uint32(_ctx),-32);
 */
float isaac_next_float(isaac_ctx *_ctx);
/**
 * isaac_next_signed_float - Uniform random float in the range (-1,1).
 * @_ctx: The ISAAC instance to generate the value with.
 * Returns a high-quality float uniformly distributed between -1 and 1
 *  (exclusive).
 * All of the float's mantissa bits are random, e.g., the least significant bit
 *  may still be non-zero even if the magnitude is less than 0.5, and any
 *  representable float in the range (-1,1) has a chance to be returned, though
 *  values very close to zero become increasingly unlikely.
 * To generate cheaper float values that do not have these properties, use
 *   ldexpf((float)isaac_next_uint32(_ctx),-31)-1;
 *  though this returns values in the range [-1,1).
 */
float isaac_next_signed_float(isaac_ctx *_ctx);
/**
 * isaac_next_double - Uniform random double in the range [0,1).
 * @_ctx: The ISAAC instance to generate the value with.
 * Returns a high-quality double uniformly distributed between 0 (inclusive)
 *  and 1 (exclusive).
 * All of the double's mantissa bits are random, e.g., the least significant
 *  bit may still be non-zero even if the value is less than 0.5, and any
 *  representable double in the range [0,1) has a chance to be returned, though
 *  values very close to zero become increasingly unlikely.
 * To generate cheaper double values that do not have these properties, use
 *   ldexp((double)isaac_next_uint32(_ctx),-32);
 */
double isaac_next_double(isaac_ctx *_ctx);
/**
 * isaac_next_signed_double - Uniform random double in the range (-1,1).
 * @_ctx: The ISAAC instance to generate the value with.
 * Returns a high-quality double uniformly distributed between -1 and 1
 *  (exclusive).
 * All of the double's mantissa bits are random, e.g., the least significant
 *  bit may still be non-zero even if the value is less than 0.5, and any
 *  representable double in the range (-1,1) has a chance to be returned,
 *  though values very close to zero become increasingly unlikely.
 * To generate cheaper double values that do not have these properties, use
 *   ldexp((double)isaac_next_uint32(_ctx),-31)-1;
 *  though this returns values in the range [-1,1).
 */
double isaac_next_signed_double(isaac_ctx *_ctx);

#endif
