#ifndef LIGHTNING_LIGHTNINGD_UTXO_H
#define LIGHTNING_LIGHTNINGD_UTXO_H
#include "config.h"
#include <bitcoin/shadouble.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct utxo {
	struct sha256_double txid;
	u32 outnum;
	u64 amount;
	u32 keyindex;
	bool is_p2sh;
	u8 status;
};

void towire_utxo(u8 **pptr, const struct utxo *utxo);
void fromwire_utxo(const u8 **ptr, size_t *max, struct utxo *utxo);

/* build_utxos/funding_tx use array of pointers, but marshall code
 * wants arr of structs */
struct utxo *from_utxoptr_arr(const tal_t *ctx, const struct utxo **utxos);
const struct utxo **to_utxoptr_arr(const tal_t *ctx, const struct utxo *utxos);
#endif /* LIGHTNING_LIGHTNINGD_UTXO_H */
