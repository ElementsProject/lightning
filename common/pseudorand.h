#ifndef LIGHTNING_COMMON_PSEUDORAND_H
#define LIGHTNING_COMMON_PSEUDORAND_H
#include "config.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * pseudorand - pseudo (guessable!) random number between 0 and max-1.
 */
#define pseudorand(max) ({static uint64_t offset; pseudorand_((max), &offset);})
uint64_t pseudorand_(uint64_t max, uint64_t *offset);

/**
 * pseudorand_u64 - pseudo (guessable!) random number between 0 and UINT64_MAX.
 */
#define pseudorand_u64() ({static uint64_t offset; pseudorand_u64_(&offset);})
uint64_t pseudorand_u64_(uint64_t *offset);

/**
 * pseudorand - pseudo (guessable!) random number between 0 (inclusive) and 1
 * (exclusive).
 */
#define pseudorand_double()  ({static uint64_t offset; pseudorand_double_(&offset);})
double pseudorand_double_(uint64_t *offset);

/**
 * Get the siphash seed for hash tables.
 */
const struct siphash_seed *siphash_seed(void);

/* Shuffle a tal array of type type. */
#define tal_arr_randomize(arr, type) \
	tal_arr_randomize_((arr), sizeof(type) + 0*sizeof(arr == (type *)NULL))
void tal_arr_randomize_(void *arr, size_t elemsize);

#endif /* LIGHTNING_COMMON_PSEUDORAND_H */
