#ifndef LIGHTNING_DAEMON_INVOICE_H
#define LIGHTNING_DAEMON_INVOICE_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/list/list.h>
#include <ccan/tal/tal.h>

struct invoices;
struct lightningd_state;

struct invoice {
	struct list_node list;
	const char *label;
	u64 msatoshi;
	struct preimage r;
	struct sha256 rhash;
	u64 paid_num;
};

#define INVOICE_MAX_LABEL_LEN 128

/* From database */
void invoice_add(struct invoices *i,
		 const struct preimage *r,
		 u64 msatoshi,
		 const char *label,
		 u64 complete);

void resolve_invoice(struct lightningd_state *dstate, struct invoice *invoice);

struct invoice *find_unpaid(struct invoices *i,
			    const struct sha256 *rhash);

struct invoices *invoices_init(const tal_t *ctx);
#endif /* LIGHTNING_DAEMON_INVOICE_H */
