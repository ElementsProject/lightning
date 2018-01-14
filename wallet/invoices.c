#include "db.h"
#include "invoices.h"
#include "wallet.h"
#include <assert.h>
#include <ccan/list/list.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <lightningd/invoice.h>
#include <lightningd/log.h>
#include <sodium/randombytes.h>
#include <sqlite3.h>
#include <common/utils.h>

struct invoice_waiter {
	bool triggered;
	struct list_node list;
	void (*cb)(const struct invoice *, void*);
	void *cbarg;
};

struct invoices {
	/* The database connection to use. */
	struct db *db;
	/* The log to report to. */
	struct log *log;
	/* The invoice list. */
	struct list_head invlist;
	/* Waiters waiting for any new invoice to be paid. */
	struct list_head waitany_waiters;
};

static void trigger_invoice_waiter(struct invoice_waiter *w,
				   struct invoice *invoice)
{
	w->triggered = true;
	w->cb(invoice, w->cbarg);
}

static bool wallet_stmt2invoice(sqlite3_stmt *stmt, struct invoice *inv)
{
	inv->id = sqlite3_column_int64(stmt, 0);
	inv->state = sqlite3_column_int(stmt, 1);

	assert(sqlite3_column_bytes(stmt, 2) == sizeof(struct preimage));
	memcpy(&inv->r, sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));

	assert(sqlite3_column_bytes(stmt, 3) == sizeof(struct sha256));
	memcpy(&inv->rhash, sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3));

	inv->label = tal_strndup(inv, sqlite3_column_blob(stmt, 4), sqlite3_column_bytes(stmt, 4));

	if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
		inv->msatoshi = tal(inv, u64);
		*inv->msatoshi = sqlite3_column_int64(stmt, 5);
	} else {
		inv->msatoshi = NULL;
	}

	inv->expiry_time = sqlite3_column_int64(stmt, 6);
	/* Correctly 0 if pay_index is NULL. */
	inv->pay_index = sqlite3_column_int64(stmt, 7);

	if (inv->state == PAID)
		inv->msatoshi_received = sqlite3_column_int64(stmt, 8);

	list_head_init(&inv->waitone_waiters);
	return true;
}

struct invoices *invoices_new(const tal_t *ctx,
			      struct db *db,
			      struct log *log)
{
	struct invoices *invs = tal(ctx, struct invoices);

	invs->db = db;
	invs->log = log;

	list_head_init(&invs->invlist);
	list_head_init(&invs->waitany_waiters);

	return invs;
}


bool invoices_load(struct invoices *invoices)
{
	int count = 0;
	struct invoice *i;
	sqlite3_stmt *stmt;

	/* Load invoices from db. */
	stmt = db_query(__func__, invoices->db,
			"SELECT id, state, payment_key, payment_hash"
			"     , label, msatoshi, expiry_time, pay_index"
			"     , msatoshi_received"
			"  FROM invoices;");
	if (!stmt) {
		log_broken(invoices->log, "Could not load invoices");
		return false;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		i = tal(invoices, struct invoice);
		if (!wallet_stmt2invoice(stmt, i)) {
			log_broken(invoices->log, "Error deserializing invoice");
			sqlite3_finalize(stmt);
			return false;
		}
		list_add_tail(&invoices->invlist, &i->list);
		count++;
	}
	log_debug(invoices->log, "Loaded %d invoices from DB", count);

	sqlite3_finalize(stmt);
	return true;
}

const struct invoice *invoices_create(struct invoices *invoices,
				      u64 *msatoshi TAKES,
				      const char *label TAKES,
				      u64 expiry)
{
	sqlite3_stmt *stmt;
	struct invoice *invoice;
	struct preimage r;
	struct sha256 rhash;
	u64 expiry_time;

	if (invoices_find_by_label(invoices, label)) {
		if (taken(msatoshi))
			tal_free(msatoshi);
		if (taken(label))
			tal_free(label);
		return NULL;
	}

	/* Compute expiration. */
	expiry_time = time_now().ts.tv_sec + expiry;
	/* Generate random secret preimage and hash. */
	randombytes_buf(r.r, sizeof(r.r));
	sha256(&rhash, r.r, sizeof(r.r));

	/* Save to database. */
	/* Need to use the lower level API of sqlite3 to bind
	 * label. Otherwise we'd need to implement sanitization of
	 * that string for sql injections... */
	stmt = db_prepare(invoices->db,
			  "INSERT INTO invoices"
			  "            (payment_hash, payment_key, state, msatoshi, label, expiry_time, pay_index, msatoshi_received)"
			  "     VALUES (?, ?, ?, ?, ?, ?, NULL, NULL);");

	sqlite3_bind_blob(stmt, 1, &rhash, sizeof(rhash), SQLITE_TRANSIENT);
	sqlite3_bind_blob(stmt, 2, &r, sizeof(r), SQLITE_TRANSIENT);
	sqlite3_bind_int(stmt, 3, UNPAID);
	if (msatoshi)
		sqlite3_bind_int64(stmt, 4, *msatoshi);
	else
		sqlite3_bind_null(stmt, 4);
	sqlite3_bind_text(stmt, 5, label, strlen(label), SQLITE_TRANSIENT);
	sqlite3_bind_int64(stmt, 6, expiry_time);

	db_exec_prepared(invoices->db, stmt);

	/* Create and load in-memory structure. */
	invoice	= tal(invoices, struct invoice);

	invoice->id = sqlite3_last_insert_rowid(invoices->db->sql);
	invoice->state = UNPAID;
	invoice->label = tal_strdup(invoice, label);
	invoice->msatoshi = tal_dup(invoice, u64, msatoshi); /* Works even if msatoshi == NULL. */
	memcpy(&invoice->r, &r, sizeof(invoice->r));
	memcpy(&invoice->rhash, &rhash, sizeof(invoice->rhash));
	invoice->expiry_time = expiry_time;
	invoice->pay_index = 0;
	list_head_init(&invoice->waitone_waiters);

	/* Add to invoices object. */
	list_add_tail(&invoices->invlist, &invoice->list);

	return invoice;
}


const struct invoice *invoices_find_by_label(struct invoices *invoices,
					     const char *label)
{
	struct invoice *i;

	/* FIXME: Use something better than a linear scan. */
	list_for_each(&invoices->invlist, i, list) {
		if (streq(i->label, label))
			return i;
	}
	return NULL;
}

const struct invoice *invoices_find_unpaid(struct invoices *invoices,
					   const struct sha256 *rhash)
{
	struct invoice *i;

	list_for_each(&invoices->invlist, i, list) {
		if (structeq(rhash, &i->rhash) && i->state == UNPAID) {
			if (time_now().ts.tv_sec > i->expiry_time)
				break;
			return i;
		}
	}
	return NULL;
}

bool invoices_delete(struct invoices *invoices,
		     const struct invoice *cinvoice)
{
	sqlite3_stmt *stmt;
	struct invoice_waiter *w;
	struct invoice *invoice = (struct invoice *) cinvoice;
	const tal_t *tmpctx = tal_tmpctx(NULL);

	/* Delete from database. */
	stmt = db_prepare(invoices->db, "DELETE FROM invoices WHERE id=?;");
	sqlite3_bind_int64(stmt, 1, invoice->id);
	db_exec_prepared(invoices->db, stmt);

	if (sqlite3_changes(invoices->db->sql) != 1)
		return false;

	/* Delete from invoices object. */
	list_del_from(&invoices->invlist, &invoice->list);

	/* Tell all the waiters about the fact that it was deleted. */
	while ((w = list_pop(&invoice->waitone_waiters,
			     struct invoice_waiter,
			     list)) != NULL) {
		/* Acquire the watcher for ourself first. */
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, NULL);
	}

	/* Free all watchers and the invoice. */
	tal_free(tmpctx);
	tal_free(invoice);
	return true;
}

const struct invoice *invoices_iterate(struct invoices *invoices,
				       const struct invoice *invoice)
{
	if (invoice)
		return list_next(&invoices->invlist, invoice, list);
	else
		return list_top(&invoices->invlist, struct invoice, list);
}

static s64 get_next_pay_index(struct db *db)
{
	/* Equivalent to (next_pay_index++) */
	s64 next_pay_index;
	next_pay_index = db_get_intvar(db, "next_pay_index", 0);
	/* Variable should exist. */
	assert(next_pay_index > 0);
	db_set_intvar(db, "next_pay_index", next_pay_index + 1);
	return next_pay_index;
}


void invoices_resolve(struct invoices *invoices,
		      const struct invoice *cinvoice,
		      u64 msatoshi_received)
{
	sqlite3_stmt *stmt;
	struct invoice_waiter *w;
	struct invoice *invoice = (struct invoice *)cinvoice;
	s64 pay_index;
	const tal_t *tmpctx = tal_tmpctx(NULL);

	/* Assign a pay-index. */
	pay_index = get_next_pay_index(invoices->db);
	/* FIXME: Save time of payment. */

	/* Update database. */
	stmt = db_prepare(invoices->db,
			  "UPDATE invoices"
			  "   SET state=?"
			  "     , pay_index=?"
			  "     , msatoshi_received=?"
			  " WHERE id=?;");
	sqlite3_bind_int(stmt, 1, PAID);
	sqlite3_bind_int64(stmt, 2, pay_index);
	sqlite3_bind_int64(stmt, 3, msatoshi_received);
	sqlite3_bind_int64(stmt, 4, invoice->id);
	db_exec_prepared(invoices->db, stmt);

	/* Update in-memory structure. */
	invoice->state = PAID;
	invoice->pay_index = pay_index;
	invoice->msatoshi_received = msatoshi_received;

	/* Tell all the waitany waiters about the new paid invoice. */
	while ((w = list_pop(&invoices->waitany_waiters,
			     struct invoice_waiter,
			     list)) != NULL) {
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, invoice);
	}
	/* Tell any waitinvoice waiters about the specific invoice
	 * getting paid. */
	while ((w = list_pop(&invoice->waitone_waiters,
			     struct invoice_waiter,
			     list)) != NULL) {
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, invoice);
	}

	/* Free all watchers. */
	tal_free(tmpctx);
}

/* Called when an invoice waiter is destructed. */
static void invoice_waiter_dtor(struct invoice_waiter *w)
{
	/* Already triggered. */
	if (w->triggered)
		return;
	list_del(&w->list);
}

/* Add an invoice waiter to the specified list of invoice waiters. */
static void add_invoice_waiter(const tal_t *ctx,
			       struct list_head *waiters,
			       void (*cb)(const struct invoice *, void*),
			       void* cbarg)
{
	struct invoice_waiter *w = tal(ctx, struct invoice_waiter);
	w->triggered = false;
	list_add_tail(waiters, &w->list);
	w->cb = cb;
	w->cbarg = cbarg;
	tal_add_destructor(w, &invoice_waiter_dtor);
}


void invoices_waitany(const tal_t *ctx,
		      struct invoices *invoices,
		      u64 lastpay_index,
		      void (*cb)(const struct invoice *, void*),
		      void *cbarg)
{
	sqlite3_stmt *stmt;
	const struct invoice *invoice;
	int res;
	char const* label;

	/* Look for an already-paid invoice. */
	stmt = db_prepare(invoices->db,
			  "SELECT label"
			  "  FROM invoices"
			  " WHERE pay_index NOT NULL"
			  "   AND pay_index > ?"
			  " ORDER BY pay_index ASC LIMIT 1;");
	sqlite3_bind_int64(stmt, 1, lastpay_index);

	res = sqlite3_step(stmt);
	if (res == SQLITE_ROW) {
		/* Invoice found. Look up the invoice object. */
		label = tal_strndup(ctx, sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));
		sqlite3_finalize(stmt);

		/* The invoice should definitely exist in-memory. */
		invoice = invoices_find_by_label(invoices, label);
		assert(invoice);
		tal_free(label);

		cb(invoice, cbarg);
		return;
	}

	sqlite3_finalize(stmt);

	/* None found. */
	add_invoice_waiter(ctx, &invoices->waitany_waiters, cb, cbarg);
}


void invoices_waitone(const tal_t *ctx,
		      struct invoices *invoices,
		      struct invoice const *cinvoice,
		      void (*cb)(const struct invoice *, void*),
		      void *cbarg)
{
	struct invoice *invoice = (struct invoice*) cinvoice;
	/* FIXME: Handle expired state. */
	if (invoice->state == PAID) {
		cb(invoice, cbarg);
		return;
	}

	/* Not yet paid. */
	add_invoice_waiter(ctx, &invoice->waitone_waiters, cb, cbarg);
}
