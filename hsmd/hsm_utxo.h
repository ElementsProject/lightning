#ifndef LIGHTNING_HSMD_HSM_UTXO_H
#define LIGHTNING_HSMD_HSM_UTXO_H
#include "config.h"
#include <common/utxo.h>

/* FIXME: If we make our static_remotekey a normal keypath key, we can
 * simply put that close information inside the PSBT, and we don't
 * need to hand the utxo to hsmd at all. */

/* /!\ This is part of the HSM ABI: do not change! /!\ */
struct hsm_utxo {
	struct bitcoin_outpoint outpoint;
	struct amount_sat amount;
	u32 keyindex;

	/* Optional unilateral close information, NULL if this is just
	 * a HD key */
	struct unilateral_close_info *close_info;

	/* The scriptPubkey if it is known */
	u8 *scriptPubkey;
};

void towire_hsm_utxo(u8 **pptr, const struct hsm_utxo *utxo);
struct hsm_utxo *fromwire_hsm_utxo(const tal_t *ctx, const u8 **ptr, size_t *max);

const struct hsm_utxo **utxos_to_hsm_utxos(const tal_t *ctx,
					   struct utxo **utxos);
#endif /* LIGHTNING_HSMD_HSM_UTXO_H */
