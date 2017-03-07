#ifndef LIGHTNING_LIGHTNINGD_BUILD_UTXOS_H
#define LIGHTNING_LIGHTNINGD_BUILD_UTXOS_H
#include "config.h"
#include <lightningd/lightningd.h>
#include <lightningd/utxo.h>

/* Reserves UTXOs to build tx which pays this amount; returns NULL if
 * impossible.  *change_satoshis 0 if no change needed. */
const struct utxo **build_utxos(const tal_t *ctx,
				struct lightningd *ld, u64 satoshi_out,
				u32 feerate_per_kw, u64 dust_limit,
				u64 *change_satoshis, u32 *change_keyindex);

/* Once we've spent them, mark them confirmed. */
void confirm_utxos(struct lightningd *ld, const struct utxo **utxos);

struct ext_key;
bool bip32_pubkey(const struct ext_key *bip32_base,
		  struct pubkey *pubkey, u32 index);

#endif /* LIGHTNING_LIGHTNINGD_BUILD_UTXOS_H */
