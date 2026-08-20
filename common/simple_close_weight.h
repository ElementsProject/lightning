#ifndef LIGHTNING_COMMON_SIMPLE_CLOSE_WEIGHT_H
#define LIGHTNING_COMMON_SIMPLE_CLOSE_WEIGHT_H
#include "config.h"
/* When lightningd checks the closing tx, it must use the same weight
 * approximation as simpleclosed, otherwise it might reject it, so we share
 * this constant. */

/* Approx weight of a simple-close tx with both outputs (vbytes * 4 for weight).
 * Input: 41vb, witness: ~222wu/4=55.5vb, outputs: ~65vb each, overhead: 11vb
 * Total ~236 vbytes = ~704 weight + witness ~222 = ~926wu, round to 900. */
#define SIMPLE_CLOSE_WEIGHT 900
#endif /* LIGHTNING_COMMON_SIMPLE_CLOSE_WEIGHT_H */
