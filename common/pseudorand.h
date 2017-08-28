#ifndef LIGHTNING_COMMON_PSEUDORAND_H
#define LIGHTNING_COMMON_PSEUDORAND_H
#include "config.h"
#include <stdint.h>

/**
 * pseudorand - pseudo (guessable!) random number between 0 and max-1.
 */
uint64_t pseudorand(uint64_t max);

/**
 * Get the siphash seed for hash tables.
 */
const struct siphash_seed *siphash_seed(void);

#endif /* LIGHTNING_COMMON_PSEUDORAND_H */
