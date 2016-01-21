#ifndef LIGHTNING_COMMIT_TX_H
#define LIGHTNING_COMMIT_TX_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/tal/tal.h>

struct channel_state;
struct sha256_double;
struct sha256;

/* Create commitment tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    OpenChannel *ours,
				    OpenChannel *theirs,
				    OpenAnchor *anchor,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate);
#endif
