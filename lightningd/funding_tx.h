#ifndef LIGHTNING_LIGHTNINGD_FUNDING_TX_H
#define LIGHTNING_LIGHTNINGD_FUNDING_TX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct bitcoin_tx;
struct privkey;
struct pubkey;
struct sha256_double;
struct utxo;

/**
 * funding_tx: create a P2WSH funding transaction for a channel.
 * @ctx: context to tal from.
 * @outnum: (out) txout (0 or 1) which is the funding output.
 * @utxomap: (in/out) tal_arr of UTXO pointers to spend (permuted to match)
 * @funding_satoshis: (in) satoshis to output.
 * @local_fundingkey: (in) local key for 2of2 funding output.
 * @remote_fundingkey: (in) remote key for 2of2 funding output.
 * @change_satoshis: (in) amount to send as change.
 * @changekey: (in) key to send change to (only used if change_satoshis != 0).
 */
struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      u32 *outnum,
			      const struct utxo **utxomap,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      u64 change_satoshis,
			      const struct pubkey *changekey);
#endif /* LIGHTNING_LIGHTNINGD_FUNDING_TX_H */
