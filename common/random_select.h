#ifndef LIGHTNING_COMMON_RANDOM_SELECT_H
#define LIGHTNING_COMMON_RANDOM_SELECT_H
#include "config.h"
#include <stdbool.h>

/* Use weighted reservoir sampling, see:
 * https://en.wikipedia.org/wiki/Reservoir_sampling#Algorithm_A-Chao
 * But (currently) the result will consist of only one sample (k=1)
 */

/**
 * random_select: return true if we should select this one.
 * @weight: weight for this option (use 1.0 if all the same)
 * @tot_weight: returns with sum of weights (must be initialized to zero)
 *
 * This always returns true on the first non-zero weight, and weighted
 * randomly from then on.
 */
bool random_select(double weight, double *tot_weight);
#endif /* LIGHTNING_COMMON_RANDOM_SELECT_H */
