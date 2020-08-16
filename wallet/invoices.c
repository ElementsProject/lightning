#include "db.h"
#include "invoices.h"
#include "wallet.h"
#include <assert.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <common/amount.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <lightningd/invoice.h>
#include <sodium/randombytes.h>
#include <string.h>

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
	/* The timers object to use for expirations. */
	struct timers *timers;
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
	struct invoice_waiter *w;
	struct invoice_waiter *n;

	list_for_each_safe(&invoices->waiters, w, n, list) {
		if (!w->any && w->id != id)
			continue;
		list_del_from(&invoices->waiters, &w->list);
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, invoice);
	}
}
static void
trigger_invoice_waiter_expire_or_delete(struct invoices *invoices,
					u64 id,
					const struct invoice *invoice)
{
	struct invoice_waiter *w;
	struct invoice_waiter *n;

	list_for_each_safe(&invoices->waiters, w, n, list) {
		if (w->any || w->id != id)
			continue;
		list_del_from(&invoices->waiters, &w->list);
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, invoice);
	}
}

static struct invoice_details *wallet_stmt2invoice_details(const tal_t *ctx,
							   struct db_stmt *stmt)
{
	struct invoice_details *dtl = tal(ctx, struct invoice_details);
	dtl->state = db_column_int(stmt, 0);

	db_column_preimage(stmt, 1, &dtl->r);

	db_column_sha256(stmt, 2, &dtl->rhash);

	dtl->label = db_column_json_escape(dtl, stmt, 3);

	if (!db_column_is_null(stmt, 4)) {
		dtl->msat = tal(dtl, struct amount_msat);
		db_column_amount_msat(stmt, 4, dtl->msat);
	} else {
		dtl->msat = NULL;
	}

	dtl->expiry_time = db_column_u64(stmt, 5);

	if (dtl->state == PAID) {
		dtl->pay_index = db_column_u64(stmt, 6);
		db_column_amount_msat(stmt, 7, &dtl->received);
		dtl->paid_timestamp = db_column_u64(stmt, 8);
	}

	dtl->bolt11 = tal_strndup(dtl, db_column_blob(stmt, 9),
				  db_column_bytes(stmt, 9));

	if (!db_column_is_null(stmt, 10))
		dtl->description = tal_strdup(
		    dtl, (const char *)db_column_text(stmt, 10));
	else
		dtl->description = NULL;

	dtl->features = tal_dup_arr(dtl, u8,
				    db_column_blob(stmt, 11),
				    db_column_bytes(stmt, 11), 0);
	return dtl;
}

/* Update expirations. */
static void update_db_expirations(struct invoices *invoices, u64 now)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(invoices->db, SQL("UPDATE invoices"
					       "   SET state = ?"
					       " WHERE state = ?"
					       "   AND expiry_time <= ?;"));
	db_bind_int(stmt, 0, EXPIRED);
	db_bind_int(stmt, 1, UNPAID);
	db_bind_u64(stmt, 2, now);
	db_exec_prepared_v2(take(stmt));
}

static void install_expiration_timer(struct invoices *invoices);

struct invoices *invoices_new(const tal_t *ctx,
			      struct db *db,
			      struct timers *timers)
{
	struct invoices *invs = tal(ctx, struct invoices);

	invs->db = db;
	invs->timers = timers;

	list_head_init(&invs->waiters);

	invs->expiration_timer = NULL;

	update_db_expirations(invs, time_now().ts.tv_sec);
	install_expiration_timer(invs);
	return invs;
}

struct invoice_id_node {
	struct list_node list;
	u64 id;
};

static void trigger_expiration(struct invoices *invoices)
{
	struct list_head idlist;
	struct invoice_id_node *idn;
	u64 now = time_now().ts.tv_sec;
	struct db_stmt *stmt;
	struct invoice i;

	/* Free current expiration timer */
	invoices->expiration_timer = tal_free(invoices->expiration_timer);

	/* Acquire all expired invoices and save them in a list */
	list_head_init(&idlist);
	stmt = db_prepare_v2(invoices->db, SQL("SELECT id"
					       "  FROM invoices"
					       " WHERE state = ?"
					       "   AND expiry_time <= ?"));
	db_bind_int(stmt, 0, UNPAID);
	db_bind_u64(stmt, 1, now);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		idn = tal(tmpctx, struct invoice_id_node);
		list_add_tail(&idlist, &idn->list);
		idn->id = db_column_u64(stmt, 0);
	}
	tal_free(stmt);

	/* Expire all those invoices */
	update_db_expirations(invoices, now);

	/* Trigger expirations */
	list_for_each(&idlist, idn, list) {
		/* Trigger expiration */
		i.id = idn->id;
		trigger_invoice_waiter_expire_or_delete(invoices, idn->id, &i);
	}

	install_expiration_timer(invoices);
}

static void install_expiration_timer(struct invoices *invoices)
{
	bool res;
	struct db_stmt *stmt;
	struct timerel rel;
	struct timeabs expiry;
	struct timeabs now = time_now();

	assert(!invoices->expiration_timer);

	/* Find unpaid invoice with nearest expiry time */
	stmt = db_prepare_v2(invoices->db, SQL("SELECT MIN(expiry_time)"
					       "  FROM invoices"
					       " WHERE state = ?;"));
	db_bind_int(stmt, 0, UNPAID);

	db_query_prepared(stmt);

	res = db_step(stmt);
	assert(res);

	if (db_column_is_null(stmt, 0))
		/* Nothing to install */
		goto done;

	invoices->min_expiry_time = db_column_u64(stmt, 0);

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
done:
	tal_free(stmt);
}

bool invoices_create(struct invoices *invoices,
		     struct invoice *pinvoice,
		     const struct amount_msat *msat TAKES,
		     const struct json_escape *label TAKES,
		     u64 expiry,
		     const char *b11enc,
		     const char *description,
		     const u8 *features,
		     const struct preimage *r,
		     const struct sha256 *rhash)
{
	struct db_stmt *stmt;
	struct invoice dummy;
	u64 expiry_time;
	u64 now = time_now().ts.tv_sec;

	if (invoices_find_by_label(invoices, &dummy, label)) {
		if (taken(msat))
			tal_free(msat);
		if (taken(label))
			tal_free(label);
		return false;
	}

	/* Compute expiration. */
	expiry_time = now + expiry;

	/* Save to database. */
	stmt = db_prepare_v2(
	    invoices->db,
	    SQL("INSERT INTO invoices"
		"            ( payment_hash, payment_key, state"
		"            , msatoshi, label, expiry_time"
		"            , pay_index, msatoshi_received"
		"            , paid_timestamp, bolt11, description, features)"
		"     VALUES ( ?, ?, ?"
		"            , ?, ?, ?"
		"            , NULL, NULL"
		"            , NULL, ?, ?, ?);"));

	db_bind_sha256(stmt, 0, rhash);
	db_bind_preimage(stmt, 1, r);
	db_bind_int(stmt, 2, UNPAID);
	if (msat)
		db_bind_amount_msat(stmt, 3, msat);
	else
		db_bind_null(stmt, 3);
	db_bind_json_escape(stmt, 4, label);
	db_bind_u64(stmt, 5, expiry_time);
	db_bind_text(stmt, 6, b11enc);
	db_bind_text(stmt, 7, description);
	db_bind_blob(stmt, 8, features, tal_bytelen(features));

	db_exec_prepared_v2(stmt);

	pinvoice->id = db_last_insert_id_v2(take(stmt));

	/* Install expiration trigger. */
	if (!invoices->expiration_timer ||
	    expiry_time < invoices->min_expiry_time) {
		invoices->expiration_timer
			= tal_free(invoices->expiration_timer);
		install_expiration_timer(invoices);
	}

	if (taken(msat))
		tal_free(msat);
	if (taken(label))
		tal_free(label);
	return true;
}


bool invoices_find_by_label(struct invoices *invoices,
			    struct invoice *pinvoice,
			    const struct json_escape *label)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(invoices->db, SQL("SELECT id"
					       "  FROM invoices"
					       " WHERE label = ?;"));
	db_bind_json_escape(stmt, 0, label);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	}

	pinvoice->id = db_column_u64(stmt, 0);
	tal_free(stmt);
	return true;
}

bool invoices_find_by_rhash(struct invoices *invoices,
			    struct invoice *pinvoice,
			    const struct sha256 *rhash)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(invoices->db, SQL("SELECT id"
					       "  FROM invoices"
					       " WHERE payment_hash = ?;"));
	db_bind_sha256(stmt, 0, rhash);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	} else {
		pinvoice->id = db_column_u64(stmt, 0);
		tal_free(stmt);
		return true;
	}
}

bool invoices_find_unpaid(struct invoices *invoices,
			  struct invoice *pinvoice,
			  const struct sha256 *rhash)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(invoices->db, SQL("SELECT id"
					       "  FROM invoices"
					       " WHERE payment_hash = ?"
					       "   AND state = ?;"));
	db_bind_sha256(stmt, 0, rhash);
	db_bind_int(stmt, 1, UNPAID);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	} else  {
		pinvoice->id = db_column_u64(stmt, 0);
		tal_free(stmt);
		return true;
	}
}

bool invoices_delete(struct invoices *invoices, struct invoice invoice)
{
	struct db_stmt *stmt;
	int changes;
	/* Delete from database. */
	stmt = db_prepare_v2(invoices->db,
			     SQL("DELETE FROM invoices WHERE id=?;"));
	db_bind_u64(stmt, 0, invoice.id);
	db_exec_prepared_v2(stmt);

	changes = db_count_changes(stmt);
	tal_free(stmt);

	if (changes != 1) {
		return false;
	}
	/* Tell all the waiters about the fact that it was deleted. */
	trigger_invoice_waiter_expire_or_delete(invoices, invoice.id, NULL);
	return true;
}

void invoices_delete_expired(struct invoices *invoices,
			     u64 max_expiry_time)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(invoices->db, SQL(
			  "DELETE FROM invoices"
			  " WHERE state = ?"
			  "   AND expiry_time <= ?;"));
	db_bind_int(stmt, 0, EXPIRED);
	db_bind_u64(stmt, 1, max_expiry_time);
	db_exec_prepared_v2(take(stmt));
}

bool invoices_iterate(struct invoices *invoices,
		      struct invoice_iterator *it)
{
	struct db_stmt *stmt;

	if (!it->p) {
		stmt = db_prepare_v2(invoices->db, SQL("SELECT"
						       "  state"
						       ", payment_key"
						       ", payment_hash"
						       ", label"
						       ", msatoshi"
						       ", expiry_time"
						       ", pay_index"
						       ", msatoshi_received"
						       ", paid_timestamp"
						       ", bolt11"
						       ", description"
						       ", features"
						       " FROM invoices"
						       " ORDER BY id;"));
		db_query_prepared(stmt);
		it->p = stmt;
	} else
		stmt = it->p;


	if (db_step(stmt))
		/* stmt doesn't need to be freed since we expect to be called
		 * again, and stmt will be freed on the last iteration. */
		return true;

	tal_free(stmt);
	it->p = NULL;
	return false;
}

const struct invoice_details *
invoices_iterator_deref(const tal_t *ctx, struct invoices *invoices UNUSED,
			const struct invoice_iterator *it)
{
	assert(it->p);
	return wallet_stmt2invoice_details(ctx, (struct db_stmt*) it->p);
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

static enum invoice_status invoice_get_status(struct invoices *invoices, struct invoice invoice)
{
	struct db_stmt *stmt;
	enum invoice_status state;
	bool res;

	stmt = db_prepare_v2(
	    invoices->db, SQL("SELECT state FROM invoices WHERE id = ?;"));
	db_bind_u64(stmt, 0, invoice.id);
	db_query_prepared(stmt);

	res = db_step(stmt);
	assert(res);
	state = db_column_int(stmt, 0);
	tal_free(stmt);
	return state;
}

void invoices_resolve(struct invoices *invoices,
		      struct invoice invoice,
		      struct amount_msat received)
{
	struct db_stmt *stmt;
	s64 pay_index;
	u64 paid_timestamp;
	enum invoice_status state = invoice_get_status(invoices, invoice);

	assert(state == UNPAID);

	/* Assign a pay-index. */
	pay_index = get_next_pay_index(invoices->db);
	paid_timestamp = time_now().ts.tv_sec;

	/* Update database. */
	stmt = db_prepare_v2(invoices->db, SQL("UPDATE invoices"
					       "   SET state=?"
					       "     , pay_index=?"
					       "     , msatoshi_received=?"
					       "     , paid_timestamp=?"
					       " WHERE id=?;"));
	db_bind_int(stmt, 0, PAID);
	db_bind_u64(stmt, 1, pay_index);
	db_bind_amount_msat(stmt, 2, &received);
	db_bind_u64(stmt, 3, paid_timestamp);
	db_bind_u64(stmt, 4, invoice.id);
	db_exec_prepared_v2(take(stmt));

	/* Tell all the waiters about the paid invoice. */
	trigger_invoice_waiter_resolve(invoices, invoice.id, &invoice);
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
	struct db_stmt *stmt;
	struct invoice invoice;

	/* Look for an already-paid invoice. */
	stmt = db_prepare_v2(invoices->db,
			     SQL("SELECT id"
				 "  FROM invoices"
				 " WHERE pay_index IS NOT NULL"
				 "   AND pay_index > ?"
				 " ORDER BY pay_index ASC LIMIT 1;"));
	db_bind_u64(stmt, 0, lastpay_index);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		invoice.id = db_column_u64(stmt, 0);

		cb(&invoice, cbarg);
	} else {
		/* None found. */
		add_invoice_waiter(ctx, &invoices->waiters,
			   true, 0, cb, cbarg);
	}
	tal_free(stmt);
}


void invoices_waitone(const tal_t *ctx,
		      struct invoices *invoices,
		      struct invoice invoice,
		      void (*cb)(const struct invoice *, void*),
		      void *cbarg)
{
	enum invoice_status state;

	state = invoice_get_status(invoices, invoice);

	if (state == PAID || state == EXPIRED) {
		cb(&invoice, cbarg);
		return;
	}

	/* Not yet paid. */
	add_invoice_waiter(ctx, &invoices->waiters,
			   false, invoice.id, cb, cbarg);
}

const struct invoice_details *invoices_get_details(const tal_t *ctx,
						   struct invoices *invoices,
						   struct invoice invoice)
{
	struct db_stmt *stmt;
	bool res;
	struct invoice_details *details;

	stmt = db_prepare_v2(invoices->db, SQL("SELECT"
					       "  state"
					       ", payment_key"
					       ", payment_hash"
					       ", label"
					       ", msatoshi"
					       ", expiry_time"
					       ", pay_index"
					       ", msatoshi_received"
					       ", paid_timestamp"
					       ", bolt11"
					       ", description"
					       ", features"
					       " FROM invoices"
					       " WHERE id = ?;"));
	db_bind_u64(stmt, 0, invoice.id);
	db_query_prepared(stmt);
	res = db_step(stmt);
	assert(res);

	details = wallet_stmt2invoice_details(ctx, stmt);
	tal_free(stmt);
	return details;
}
