#ifndef LIGHTNING_CLOSE_TX_H
#define LIGHTNING_CLOSE_TX_H
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

struct sha256_double;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   OpenChannel *ours,
				   OpenChannel *theirs,
				   int64_t delta,
				   const struct sha256_double *anchor_txid,
				   unsigned int anchor_output);
#endif
