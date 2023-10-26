#ifndef LIGHTNING_LIGHTNINGD_ANCHORSPEND_H
#define LIGHTNING_LIGHTNINGD_ANCHORSPEND_H
#include "config.h"
#include <ccan/tal/tal.h>

struct channel;
struct bitcoin_tx;

/* Find anchor, figure out details.  Returns NULL if not an anchor channel,
 * or we don't have any HTLCs and don't need to boost. */
struct anchor_details *create_anchor_details(const tal_t *ctx,
					     struct channel *channel,
					     const struct bitcoin_tx *tx);

/* Called when commit_tx returns from sendrawtx.
 * Not called once commit_tx is mined, however. */
void commit_tx_boost(struct channel *channel,
		     struct anchor_details *adet,
		     bool success);

#endif /* LIGHTNING_LIGHTNINGD_ANCHORSPEND_H */
