#ifndef LIGHTNING_LIGHTNINGD_INVOICE_H
#define LIGHTNING_LIGHTNINGD_INVOICE_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/list/list.h>
#include <ccan/tal/tal.h>

struct invoices;
struct lightningd;

/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum invoice_status {
	UNPAID,
	PAID,
};

struct invoice {
	u64 id;
	enum invoice_status state;
	struct list_node list;
	const char *label;
	u64 msatoshi;
	struct preimage r;
	u64 expiry_time;
	struct sha256 rhash;
};

#define INVOICE_MAX_LABEL_LEN 128

/* From database */
void invoice_add(struct invoices *invs,
		 struct invoice *inv);

void resolve_invoice(struct lightningd *ld, struct invoice *invoice);

struct invoice *find_unpaid(struct invoices *i,
			    const struct sha256 *rhash);

struct invoices *invoices_init(const tal_t *ctx);
#endif /* LIGHTNING_LIGHTNINGD_INVOICE_H */
