#ifndef LIGHTNING_DAEMON_INVOICE_H
#define LIGHTNING_DAEMON_INVOICE_H
#include "config.h"
#include "protobuf_convert.h"

struct invoices;
struct lightningd_state;

struct invoice {
	struct list_node list;
	const char *label;
	u64 msatoshi;
	struct rval r;
	struct sha256 rhash;
	u64 paid_num;
};

#define INVOICE_MAX_LABEL_LEN 128

/* From database */
void invoice_add(struct invoices *i,
		 const struct rval *r,
		 u64 msatoshi,
		 const char *label,
		 u64 complete);

void resolve_invoice(struct lightningd_state *dstate, struct invoice *invoice);

struct invoice *find_unpaid(struct invoices *i,
			    const struct sha256 *rhash);

struct invoices *invoices_init(struct lightningd_state *dstate);
#endif /* LIGHTNING_DAEMON_INVOICE_H */
