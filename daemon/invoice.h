#ifndef LIGHTNING_DAEMON_INVOICE_H
#define LIGHTNING_DAEMON_INVOICE_H
#include "config.h"
#include "peer.h"

struct lightningd_state;

struct invoice {
	struct list_node list;
	const char *label;
	u64 msatoshi;
	struct rval r;
	struct sha256 rhash;
	bool complete;
};

#define INVOICE_MAX_LABEL_LEN 128

/* From database */
void invoice_add(struct lightningd_state *dstate,
		 const struct rval *r,
		 u64 msatoshi,
		 const char *label,
		 bool complete);

struct invoice *find_invoice(struct lightningd_state *dstate,
			     const struct sha256 *rhash);

#endif /* LIGHTNING_DAEMON_INVOICE_H */
