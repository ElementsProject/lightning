#ifndef LIGHTNING_WALLET_TXFILTER_H
#define LIGHTNING_WALLET_TXFILTER_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct txfilter;

/**
 * outpointfilter -- Simple filter that keeps track of outpoints
 */
struct outpointfilter;

/**
 * txfilter_new -- Construct and initialize a new txfilter
 */
struct txfilter *txfilter_new(const tal_t *ctx);

/**
 * txfilter_add_derkey -- Add a scriptpubkeys matching the der key to the filter
 *
 * This ensures that we recognize the scriptpubkeys to our keys when
 * filtering transactions. If any of the outputs matches the
 * scriptpubkey then the transaction is marked as a match. Adds
 * scriptpubkey for both raw p2wpkh and p2wpkh wrapped in p2sh.
 */
void txfilter_add_derkey(struct txfilter *filter,
			 const u8 derkey[PUBKEY_CMPR_LEN]);

/**
 * txfilter_match -- Check whether the tx matches the filter
 */
bool txfilter_match(const struct txfilter *filter, const struct bitcoin_tx *tx);

/**
 * txfilter_add_scriptpubkey -- Add a serialized scriptpubkey to the filter
 */
void txfilter_add_scriptpubkey(struct txfilter *filter, const u8 *script TAKES);

/**
 * outpointfilter_new -- Create a new outpointfilter
 */
struct outpointfilter *outpointfilter_new(tal_t *ctx);

/**
 * outpointfilter_add -- Add an outpoint to the filter
 */
void outpointfilter_add(struct outpointfilter *of,
			const struct bitcoin_txid *txid, const u32 outnum);

/**
 * outpointfilter_matches -- Are we tracking this outpoint?
 */
bool outpointfilter_matches(struct outpointfilter *of,
			    const struct bitcoin_txid *txid, const u32 outnum);
/**
 * outpointfilter_remove -- Do not match this outpoint in the future
 */
void outpointfilter_remove(struct outpointfilter *of,
			   const struct bitcoin_txid *txid, const u32 outnum);

#endif /* LIGHTNING_WALLET_TXFILTER_H */
