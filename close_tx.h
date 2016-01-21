#ifndef LIGHTNING_CLOSE_TX_H
#define LIGHTNING_CLOSE_TX_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/tal/tal.h>

struct sha256_double;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   OpenChannel *ours,
				   OpenChannel *theirs,
				   OpenAnchor *anchor,
				   uint64_t to_us, uint64_t to_them);
#endif
