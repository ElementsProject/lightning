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
};

void towire_utxo(u8 **pptr, const struct utxo *utxo);
void fromwire_utxo(const u8 **ptr, size_t *max, struct utxo *utxo);

void fromwire_utxo_array(const u8 **ptr, size_t *max,
			 struct utxo *utxo, size_t num);

void towire_utxo_array(u8 **pptr, const struct utxo *utxo, size_t num);
#endif /* LIGHTNING_LIGHTNINGD_UTXO_H */
