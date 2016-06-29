#ifndef LIGHTNING_DAEMON_PAY_H
#define LIGHTNING_DAEMON_PAY_H
#include "config.h"

struct peer;
struct htlc;
struct rval;

void complete_pay_command(struct peer *peer,
			  struct htlc *htlc,
			  const struct rval *rval);

#endif /* LIGHTNING_DAEMON_PAY_H */
