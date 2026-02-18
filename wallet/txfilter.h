#ifndef LIGHTNING_WALLET_TXFILTER_H
#define LIGHTNING_WALLET_TXFILTER_H
#include "config.h"
#include <bitcoin/tx.h>

/**
 * outpointfilter -- Simple filter that keeps track of outpoints
 */
struct outpointfilter;

/**
 * outpointfilter_new -- Create a new outpointfilter
 */
struct outpointfilter *outpointfilter_new(tal_t *ctx);

/**
 * outpointfilter_add -- Add an outpoint to the filter
 */
void outpointfilter_add(struct outpointfilter *of,
			const struct bitcoin_outpoint *outpoint);

/**
 * outpointfilter_matches -- Are we tracking this outpoint?
 */
bool outpointfilter_matches(struct outpointfilter *of,
			    const struct bitcoin_outpoint *outpoint);
/**
 * outpointfilter_remove -- Do not match this outpoint in the future
 */
void outpointfilter_remove(struct outpointfilter *of,
			   const struct bitcoin_outpoint *outpoint);

#endif /* LIGHTNING_WALLET_TXFILTER_H */
