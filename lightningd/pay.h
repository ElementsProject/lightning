#ifndef LIGHTNING_LIGHTNINGD_PAY_H
#define LIGHTNING_LIGHTNINGD_PAY_H
#include "config.h"
#include <wire/gen_onion_wire.h>

struct htlc_out;
struct lightningd;
struct preimage;
struct pubkey;

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval);

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail);

#endif /* LIGHTNING_LIGHTNINGD_PAY_H */
