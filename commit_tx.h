#ifndef LIGHTNING_COMMIT_TX_H
#define LIGHTNING_COMMIT_TX_H
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

struct sha256_double;
struct sha256;

/* Create commitment tx to spend the anchor tx outputs; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    OpenChannel *ours,
				    OpenChannel *theirs,
				    const struct sha256 *revocation_hash,
				    int64_t delta,
				    const struct sha256_double *anchor_txid1,
				    unsigned int index1, uint64_t input_amount1,
				    const struct sha256_double *anchor_txid2,
				    unsigned int index2, uint64_t input_amount2,
				    size_t inmap[2]);
#endif
