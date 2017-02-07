#ifndef LIGHTNING_LIGHTNINGD_FUNDING_TX_H
#define LIGHTNING_LIGHTNINGD_FUNDING_TX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct bitcoin_tx;
struct privkey;
struct pubkey;
struct sha256_double;

/* Create funding tx which spends a single P2PKH input, produces a
 * P2WPKH change output (if over dust limit). */
struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      const struct sha256_double *input_txid,
			      unsigned int input_txout,
			      u64 input_satoshis,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      const struct pubkey *changekey,
			      u64 feerate_per_kw,
			      u64 dust_limit_satoshis);

void sign_funding_tx(struct bitcoin_tx *funding,
		     const struct pubkey *inputkey,
		     const struct privkey *input_privkey);

#endif /* LIGHTNING_LIGHTNINGD_FUNDING_TX_H */
