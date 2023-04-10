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

/* Actual commit_tx refresh function: does CPFP using anchors if
 * worthwhile. */
bool commit_tx_boost(struct channel *channel,
		     const struct bitcoin_tx **tx,
		     struct anchor_details *adet);

#endif /* LIGHTNING_LIGHTNINGD_ANCHORSPEND_H */
