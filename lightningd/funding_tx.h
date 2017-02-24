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
 * @outnum: txout (0 or 1) which is the funding output.
 * @utxo: tal_arr of UTXO to spend as inputs.
 * @funding_satoshis: satoshis to output.
 * @local_fundingkey: local key for 2of2 funding output.
 * @remote_fundingkey: remote key for 2of2 funding output.
 * @changekey: key to send change to (if any).
 * @feerate_per_kw: feerate for transaction.
 * @dust_limit_satoshis: dust limit to trim change output by.
 */
struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      u32 *outnum,
			      const struct utxo *utxos,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      const struct pubkey *changekey,
			      u64 feerate_per_kw,
			      u64 dust_limit_satoshis);
#endif /* LIGHTNING_LIGHTNINGD_FUNDING_TX_H */
