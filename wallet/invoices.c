#include "db.h"
#include "invoices.h"
#include "wallet.h"
#include <assert.h>
#include <ccan/list/list.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <lightningd/invoice.h>
#include <lightningd/log.h>
#include <sodium/randombytes.h>
#include <sqlite3.h>
#include <string.h>
#include <common/timeout.h>
#include <common/utils.h>

struct invoice_waiter {
	/* Is this waiter already triggered? */
	bool triggered;
	/* Is this waiting for any invoice to resolve? */
	bool any;
	/* If !any, the specific invoice this is waiting on */
	u64 id;

	struct list_node list;

	/* The callback to use */
	void (*cb)(const struct invoice *, void*);
	void *cbarg;
};

struct invoices {
	/* The database connection to use. */
	struct db *db;
	/* The log to report to. */
	struct log *log;
	/* The timers object to use for expirations. */
	struct timers *timers;
	/* The invoice list. */
	struct list_head invlist;
	/* Waiters waiting for invoices to be paid, expired, or deleted. */
	struct list_head waiters;
	/* Earliest time for some invoice to expire */
	u64 min_expiry_time;
	/* Expiration timer */
	struct oneshot *expiration_timer;
};

static void trigger_invoice_waiter(struct invoice_waiter *w,
				   const struct invoice *invoice)
{
	w->triggered = true;
	w->cb(invoice, w->cbarg);
}

static void trigger_invoice_waiter_resolve(struct invoices *invoices,
					   u64 id,
					   const struct invoice *invoice)
{
	const tal_t *tmpctx = tal_tmpctx(invoices);
	struct invoice_waiter *w;
	struct invoice_waiter *n;

	list_for_each_safe(&invoices->waiters, w, n, list) {
		if (!w->any && w->id != id)
			continue;
		list_del_from(&invoices->waiters, &w->list);
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, invoice);
	}

	tal_free(tmpctx);
}
static void
trigger_invoice_waiter_expire_or_delete(struct invoices *invoices,
					u64 id,
					const struct invoice *invoice)
{
	const tal_t *tmpctx = tal_tmpctx(invoices);
	struct invoice_waiter *w;
	struct invoice_waiter *n;

	list_for_each_safe(&invoices->waiters, w, n, list) {
		if (w->any || w->id != id)
			continue;
		list_del_from(&invoices->waiters, &w->list);
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, invoice);
	}

	tal_free(tmpctx);
}

static bool wallet_stmt2invoice_details(sqlite3_stmt *stmt,
					struct invoice *invoice,
					struct invoice_details *dtl)
{
	invoice->id = sqlite3_column_int64(stmt, 0);
	dtl->state = sqlite3_column_int(stmt, 1);

	assert(sqlite3_column_bytes(stmt, 2) == sizeof(struct preimage));
	memcpy(&dtl->r, sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));

	assert(sqlite3_column_bytes(stmt, 3) == sizeof(struct sha256));
	memcpy(&dtl->rhash, sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3));

	dtl->label = tal_strndup(dtl, sqlite3_column_blob(stmt, 4), sqlite3_column_bytes(stmt, 4));

	if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
		dtl->msatoshi = tal(dtl, u64);
		*dtl->msatoshi = sqlite3_column_int64(stmt, 5);
	} else {
		dtl->msatoshi = NULL;
	}

	dtl->expiry_time = sqlite3_column_int64(stmt, 6);

	if (dtl->state == PAID) {
		dtl->pay_index = sqlite3_column_int64(stmt, 7);
		dtl->msatoshi_received = sqlite3_column_int64(stmt, 8);
		dtl->paid_timestamp = sqlite3_column_int64(stmt, 9);
	}

	return true;
}

struct invoices *invoices_new(const tal_t *ctx,
			      struct db *db,
			      struct log *log,
			      struct timers *timers)
{
	struct invoices *invs = tal(ctx, struct invoices);

	invs->db = db;
	invs->log = log;
	invs->timers = timers;

	list_head_init(&invs->invlist);
	list_head_init(&invs->waiters);

	invs->expiration_timer = NULL;

	return invs;
}

/* Update expirations. */
static void update_db_expirations(struct invoices *invoices, u64 now)
{
	sqlite3_stmt *stmt;
	stmt = db_prepare(invoices->db,
			  "UPDATE invoices"
			  "   SET state = ?"
			  " WHERE state = ?"
			  "   AND expiry_time <= ?;");
	sqlite3_bind_int(stmt, 1, EXPIRED);
	sqlite3_bind_int(stmt, 2, UNPAID);
	sqlite3_bind_int64(stmt, 3, now);
	db_exec_prepared(invoices->db, stmt);
}

static struct invoice *invoices_find_by_id(struct invoices *invoices,
					   u64 id)
{
	struct invoice *i;

	/* FIXME: Use something better than a linear scan. */
	list_for_each(&invoices->invlist, i, list) {
		if (i->id == id)
			return i;
	}
	return NULL;
}

struct invoice_id_node {
	struct list_node list;
	u64 id;
};

static void install_expiration_timer(struct invoices *invoices);
static void trigger_expiration(struct invoices *invoices)
{
	const tal_t *tmpctx = tal_tmpctx(invoices);
	struct list_head idlist;
	struct invoice_id_node *idn;
	u64 now = time_now().ts.tv_sec;
	sqlite3_stmt *stmt;
	struct invoice *i;

	/* Free current expiration timer */
	invoices->expiration_timer = tal_free(invoices->expiration_timer);

	/* Acquire all expired invoices and save them in a list */
	list_head_init(&idlist);
	stmt = db_prepare(invoices->db,
			  "SELECT id"
			  "  FROM invoices"
			  " WHERE state = ?"
			  "   AND expiry_time <= ?;");
	sqlite3_bind_int(stmt, 1, UNPAID);
	sqlite3_bind_int64(stmt, 2, now);
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		idn = tal(tmpctx, struct invoice_id_node);
		list_add_tail(&idlist, &idn->list);
		idn->id = sqlite3_column_int64(stmt, 0);
	}
	sqlite3_finalize(stmt);

	/* Expire all those invoices */
	update_db_expirations(invoices, now);

	/* Trigger expirations */
	list_for_each(&idlist, idn, list) {
		/* Update in-memory structure */
		i = invoices_find_by_id(invoices, idn->id);
		i->details->state = EXPIRED;
		/* Trigger expiration */
		trigger_invoice_waiter_expire_or_delete(invoices,
							idn->id,
							i);
	}

	install_expiration_timer(invoices);

	tal_free(tmpctx);
}

static void install_expiration_timer(struct invoices *invoices)
{
	int res;
	sqlite3_stmt *stmt;
	struct timerel rel;
	struct timeabs expiry;
	struct timeabs now = time_now();

	assert(!invoices->expiration_timer);

	/* Find unpaid invoice with nearest expiry time */
	stmt = db_prepare(invoices->db,
			  "SELECT MIN(expiry_time)"
			  "  FROM invoices"
			  " WHERE state = ?;");
	sqlite3_bind_int(stmt, 1, UNPAID);
	res = sqlite3_step(stmt);
	assert(res == SQLITE_ROW);
	if (sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
		/* Nothing to install */
		sqlite3_finalize(stmt);
		return;
	} else
		invoices->min_expiry_time = sqlite3_column_int64(stmt, 0);
	sqlite3_finalize(stmt);

	memset(&expiry, 0, sizeof(expiry));
	expiry.ts.tv_sec = invoices->min_expiry_time;

	/* now > expiry */
	if (time_after(now, expiry))
		expiry = now;

	/* rel = expiry - now */
	rel = time_between(expiry, now);

	/* Have it called at indicated timerel. */
	invoices->expiration_timer = new_reltimer(invoices->timers,
						  invoices,
						  rel,
						  &trigger_expiration,
						  invoices);
}

bool invoices_load(struct invoices *invoices)
{
	int count = 0;
	u64 now = time_now().ts.tv_sec;
	struct invoice *i;
	sqlite3_stmt *stmt;

	update_db_expirations(invoices, now);

	/* Load invoices from db. */
	stmt = db_query(__func__, invoices->db,
			"SELECT id, state, payment_key, payment_hash"
			"     , label, msatoshi, expiry_time, pay_index"
			"     , msatoshi_received, paid_timestamp"
			"  FROM invoices;");
	if (!stmt) {
		log_broken(invoices->log, "Could not load invoices");
		return false;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		i = tal(invoices, struct invoice);
		i->owner = invoices;
		i->details = tal(i, struct invoice_details);
		if (!wallet_stmt2invoice_details(stmt, i, i->details)) {
			log_broken(invoices->log, "Error deserializing invoice");
			sqlite3_finalize(stmt);
			return false;
		}
		list_add_tail(&invoices->invlist, &i->list);
		count++;
	}
	log_debug(invoices->log, "Loaded %d invoices from DB", count);

	sqlite3_finalize(stmt);

	install_expiration_timer(invoices);

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
	u64 now = time_now().ts.tv_sec;

	if (invoices_find_by_label(invoices, label)) {
		if (taken(msatoshi))
			tal_free(msatoshi);
		if (taken(label))
			tal_free(label);
		return NULL;
	}

	/* Compute expiration. */
	expiry_time = now + expiry;
	/* Generate random secret preimage and hash. */
	randombytes_buf(r.r, sizeof(r.r));
	sha256(&rhash, r.r, sizeof(r.r));

	/* Save to database. */
	/* Need to use the lower level API of sqlite3 to bind
	 * label. Otherwise we'd need to implement sanitization of
	 * that string for sql injections... */
	stmt = db_prepare(invoices->db,
			  "INSERT INTO invoices"
			  "            ( payment_hash, payment_key, state"
			  "            , msatoshi, label, expiry_time"
			  "            , pay_index, msatoshi_received"
			  "            , paid_timestamp)"
			  "     VALUES ( ?, ?, ?"
			  "            , ?, ?, ?"
			  "            , NULL, NULL"
			  "            , NULL);");

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
	invoice->owner = invoices;

	invoice->id = sqlite3_last_insert_rowid(invoices->db->sql);
	invoice->details = tal(invoice, struct invoice_details);
	invoice->details->state = UNPAID;
	invoice->details->label = tal_strdup(invoice->details, label);
	invoice->details->msatoshi = tal_dup(invoice->details, u64, msatoshi); /* Works even if msatoshi == NULL. */
	memcpy(&invoice->details->r, &r, sizeof(invoice->details->r));
	memcpy(&invoice->details->rhash, &rhash, sizeof(invoice->details->rhash));
	invoice->details->expiry_time = expiry_time;

	/* Add to invoices object. */
	list_add_tail(&invoices->invlist, &invoice->list);

	/* Install expiration trigger. */
	if (!invoices->expiration_timer ||
	    expiry_time < invoices->min_expiry_time) {
		invoices->expiration_timer
			= tal_free(invoices->expiration_timer);
		install_expiration_timer(invoices);
	}

	return invoice;
}


const struct invoice *invoices_find_by_label(struct invoices *invoices,
					     const char *label)
{
	struct invoice *i;

	/* FIXME: Use something better than a linear scan. */
	list_for_each(&invoices->invlist, i, list) {
		if (streq(i->details->label, label))
			return i;
	}
	return NULL;
}

const struct invoice *invoices_find_unpaid(struct invoices *invoices,
					   const struct sha256 *rhash)
{
	struct invoice *i;

	list_for_each(&invoices->invlist, i, list) {
		if (structeq(rhash, &i->details->rhash) &&
		    i->details->state == UNPAID) {
			if (time_now().ts.tv_sec > i->details->expiry_time)
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
	struct invoice *invoice = (struct invoice *) cinvoice;

	/* Delete from database. */
	stmt = db_prepare(invoices->db, "DELETE FROM invoices WHERE id=?;");
	sqlite3_bind_int64(stmt, 1, invoice->id);
	db_exec_prepared(invoices->db, stmt);

	if (sqlite3_changes(invoices->db->sql) != 1)
		return false;

	/* Delete from invoices object. */
	list_del_from(&invoices->invlist, &invoice->list);

	/* Tell all the waiters about the fact that it was deleted. */
	trigger_invoice_waiter_expire_or_delete(invoices,
						invoice->id, NULL);

	/* Free all watchers and the invoice. */
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
	struct invoice *invoice = (struct invoice *)cinvoice;
	s64 pay_index;
	u64 paid_timestamp;
	const tal_t *tmpctx = tal_tmpctx(NULL);

	/* Assign a pay-index. */
	pay_index = get_next_pay_index(invoices->db);
	paid_timestamp = time_now().ts.tv_sec;

	/* Update database. */
	stmt = db_prepare(invoices->db,
			  "UPDATE invoices"
			  "   SET state=?"
			  "     , pay_index=?"
			  "     , msatoshi_received=?"
			  "     , paid_timestamp=?"
			  " WHERE id=?;");
	sqlite3_bind_int(stmt, 1, PAID);
	sqlite3_bind_int64(stmt, 2, pay_index);
	sqlite3_bind_int64(stmt, 3, msatoshi_received);
	sqlite3_bind_int64(stmt, 4, paid_timestamp);
	sqlite3_bind_int64(stmt, 5, invoice->id);
	db_exec_prepared(invoices->db, stmt);

	/* Update in-memory structure. */
	invoice->details->state = PAID;
	invoice->details->pay_index = pay_index;
	invoice->details->msatoshi_received = msatoshi_received;
	invoice->details->paid_timestamp = paid_timestamp;

	/* Tell all the waiters about the paid invoice. */
	trigger_invoice_waiter_resolve(invoices, invoice->id, invoice);

	/* Free all watchers. */
	tal_free(tmpctx);
}

/* Called when an invoice waiter is destructed. */
static void destroy_invoice_waiter(struct invoice_waiter *w)
{
	/* Already triggered. */
	if (w->triggered)
		return;
	list_del(&w->list);
}

/* Add an invoice waiter to the specified list of invoice waiters. */
static void add_invoice_waiter(const tal_t *ctx,
			       struct list_head *waiters,
			       bool any,
			       u64 id,
			       void (*cb)(const struct invoice *, void*),
			       void* cbarg)
{
	struct invoice_waiter *w = tal(ctx, struct invoice_waiter);
	w->triggered = false;
	w->any = any;
	w->id = id;
	list_add_tail(waiters, &w->list);
	w->cb = cb;
	w->cbarg = cbarg;
	tal_add_destructor(w, &destroy_invoice_waiter);
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
	add_invoice_waiter(ctx, &invoices->waiters,
			   true, 0, cb, cbarg);
}


void invoices_waitone(const tal_t *ctx,
		      struct invoices *invoices UNUSED,
		      struct invoice const *cinvoice,
		      void (*cb)(const struct invoice *, void*),
		      void *cbarg)
{
	struct invoice *invoice = (struct invoice*) cinvoice;
	if (invoice->details->state == PAID || invoice->details->state == EXPIRED) {
		cb(invoice, cbarg);
		return;
	}

	/* Not yet paid. */
	add_invoice_waiter(ctx, &invoices->waiters,
			   false, invoice->id, cb, cbarg);
}

void invoices_get_details(const tal_t *ctx,
			  struct invoices *invoices,
			  const struct invoice *invoice,
			  struct invoice_details *dtl)
{
	dtl->state = invoice->details->state;
	dtl->r = invoice->details->r;
	dtl->rhash = invoice->details->rhash;
	dtl->label = tal_strdup(ctx, invoice->details->label);
	dtl->msatoshi =
		invoice->details->msatoshi ?
				tal_dup(ctx, u64, invoice->details->msatoshi) :
		/*otherwise*/	NULL ;
	dtl->expiry_time = invoice->details->expiry_time;
	if (dtl->state == PAID) {
		dtl->pay_index = invoice->details->pay_index;
		dtl->msatoshi_received = invoice->details->msatoshi_received;
		dtl->paid_timestamp = invoice->details->paid_timestamp;
	}
}
