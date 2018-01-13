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
	/* List off ld->invoices->invlist */
	struct list_node list;
	/* Database ID */
	u64 id;
	enum invoice_status state;
	const char *label;
	/* NULL if they specified "any" */
	u64 *msatoshi;
	/* Set if state == PAID */
	u64 msatoshi_received;
	struct preimage r;
	u64 expiry_time;
	struct sha256 rhash;
	/* Non-zero if state == PAID */
	u64 pay_index;
	/* Any JSON waitinvoice calls waiting for this to be paid. */
	struct list_head waitone_waiters;
};

#define INVOICE_MAX_LABEL_LEN 128

/* From database */
void invoice_add(struct invoices *invs,
		 struct invoice *inv);

void resolve_invoice(struct lightningd *ld, struct invoice *invoice,
		     u64 msatoshi_received);

struct invoice *find_unpaid(struct invoices *i,
			    const struct sha256 *rhash);

struct invoices *invoices_init(const tal_t *ctx);
#endif /* LIGHTNING_LIGHTNINGD_INVOICE_H */
