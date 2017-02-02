#ifndef LIGHTNING_DAEMON_PAY_H
#define LIGHTNING_DAEMON_PAY_H
#include "config.h"

struct htlc;
struct lightningd_state;
struct preimage;

void complete_pay_command(struct lightningd_state *dstate,
			  const struct htlc *htlc);

bool pay_add(struct lightningd_state *dstate,
	     const struct sha256 *rhash,
	     u64 msatoshi,
	     const struct pubkey *ids,
	     struct htlc *htlc,
	     const u8 *fail,
	     const struct preimage *r);
#endif /* LIGHTNING_DAEMON_PAY_H */
