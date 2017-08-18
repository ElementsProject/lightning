#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_WIRE_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_WIRE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <daemon/htlc.h>

/* The minimal info about an htlc. */
struct htlc_stub {
	enum side owner;
	u32 cltv_expiry;
	struct ripemd160 ripemd;
};

void towire_htlc_stub(u8 **pptr, const struct htlc_stub *htlc_stub);
void fromwire_htlc_stub(const u8 **cursor, size_t *max,
			struct htlc_stub *htlc_stub);
#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_WIRE_H */
