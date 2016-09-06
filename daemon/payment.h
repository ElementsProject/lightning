#ifndef LIGHTNING_DAEMON_PAYMENT_H
#define LIGHTNING_DAEMON_PAYMENT_H
#include "config.h"
#include "peer.h"

struct lightningd_state;

struct payment {
	struct list_node list;
	u64 msatoshis;
	struct rval r;
	struct sha256 rhash;
	bool complete;
};

/* From database */
void payment_add(struct lightningd_state *dstate,
		 const struct rval *r,
		 u64 msatoshis,
		 bool complete);

struct payment *find_payment(struct lightningd_state *dstate,
			     const struct sha256 *rhash);

#endif /* LIGHTNING_DAEMON_PAYMENT_H */
