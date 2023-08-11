#ifndef LIGHTNING_COMMON_PSEUDORAND_H
#define LIGHTNING_COMMON_PSEUDORAND_H
#include "config.h"
#include <stdint.h>
#include <stdlib.h>

/**
 * pseudorand - pseudo (guessable!) random number between 0 and max-1.
 */
uint64_t pseudorand(uint64_t max);

/**
 * pseudorand - pseudo (guessable!) random number between 0 and UINT64_MAX.
 */
uint64_t pseudorand_u64(void);

/**
 * pseudorand - pseudo (guessable!) random number between 0 (inclusive) and 1
 * (exclusive).
 */
double pseudorand_double(void);

/**
 * Get the siphash seed for hash tables.
 */
const struct siphash_seed *siphash_seed(void);

/* Shuffle a tal array of type type. */
#define tal_arr_randomize(arr, type) \
	tal_arr_randomize_((arr), sizeof(type) + 0*sizeof(arr == (type *)NULL))
void tal_arr_randomize_(void *arr, size_t elemsize);

#endif /* LIGHTNING_COMMON_PSEUDORAND_H */
