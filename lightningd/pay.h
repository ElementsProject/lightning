#ifndef LIGHTNING_LIGHTNINGD_PAY_H
#define LIGHTNING_LIGHTNINGD_PAY_H
#include "config.h"
#include <wire/gen_onion_wire.h>

struct htlc_end;
struct lightningd;
struct preimage;
struct pubkey;

void payment_succeeded(struct lightningd *ld, struct htlc_end *dst,
		       const struct preimage *rval);

void payment_failed(struct lightningd *ld, struct htlc_end *dst,
		    const struct pubkey *sender,
		    enum onion_type failure_code);

#endif /* LIGHTNING_LIGHTNINGD_PAY_H */
