#ifndef LIGHTNING_ESCAPE_TX_H
#define LIGHTNING_ESCAPE_TX_H
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

struct sha256_double;
struct sha256;

/* Create escape tx to spend our anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_escape_tx(const tal_t *ctx,
				    OpenChannel *ours,
				    OpenChannel *theirs,
				    const struct sha256_double *anchor_txid,
				    unsigned int anchor_index,
				    uint64_t input_amount,
				    uint64_t escape_fee);

/* Create fast escape tx to spend our anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_fast_escape_tx(const tal_t *ctx,
					 OpenChannel *ours,
					 OpenChannel *theirs,
					 const struct sha256_double *anchor_txid,
					 unsigned int anchor_index,
					 uint64_t input_amount,
					 uint64_t escape_fee);
#endif
