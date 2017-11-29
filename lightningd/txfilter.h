#ifndef LIGHTNING_LIGHTNINGD_TXFILTER_H
#define LIGHTNING_LIGHTNINGD_TXFILTER_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct txfilter;

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
void txfilter_add_derkey(struct txfilter *filter, u8 derkey[PUBKEY_DER_LEN]);

/**
 * txfilter_match -- Check whether the tx matches the filter
 */
bool txfilter_match(const struct txfilter *filter, const struct bitcoin_tx *tx);

#endif /* LIGHTNING_LIGHTNINGD_TXFILTER_H */
