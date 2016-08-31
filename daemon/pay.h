#ifndef LIGHTNING_DAEMON_PAY_H
#define LIGHTNING_DAEMON_PAY_H
#include "config.h"

struct lightningd_state;
struct htlc;

void complete_pay_command(struct lightningd_state *dstate,
			  const struct htlc *htlc);

#endif /* LIGHTNING_DAEMON_PAY_H */
