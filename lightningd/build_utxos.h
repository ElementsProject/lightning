#ifndef LIGHTNING_LIGHTNINGD_BUILD_UTXOS_H
#define LIGHTNING_LIGHTNINGD_BUILD_UTXOS_H
#include "config.h"
#include <common/utxo.h>
#include <lightningd/lightningd.h>

/* Reserves UTXOs to build tx which pays this amount; returns NULL if
 * impossible. */
const struct utxo **build_utxos(const tal_t *ctx,
				struct lightningd *ld, u64 satoshi_out,
				u32 feerate_per_kw, u64 dust_limit,
				size_t outputscriptlen,
				u64 *change_satoshis, u32 *change_keyindex);

#endif /* LIGHTNING_LIGHTNINGD_BUILD_UTXOS_H */
