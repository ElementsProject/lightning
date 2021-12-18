#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/timeout.h>
#include <wallet/db.h>
#include <wallet/invoices.h>
#include <wallet/wallet.h>

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
	dtl->state = db_col_int(stmt, "state");

	db_col_preimage(stmt, "payment_key", &dtl->r);

	db_col_sha256(stmt, "payment_hash", &dtl->rhash);

	dtl->label = db_col_json_escape(dtl, stmt, "label");

	if (!db_col_is_null(stmt, "msatoshi")) {
		dtl->msat = tal(dtl, struct amount_msat);
		db_col_amount_msat(stmt, "msatoshi", dtl->msat);
	} else {
		dtl->msat = NULL;
	}

	dtl->expiry_time = db_col_u64(stmt, "expiry_time");

	if (dtl->state == PAID) {
		dtl->pay_index = db_col_u64(stmt, "pay_index");
		db_col_amount_msat(stmt, "msatoshi_received", &dtl->received);
		dtl->paid_timestamp = db_col_u64(stmt, "paid_timestamp");
	} else {
		db_col_ignore(stmt, "pay_index");
		db_col_ignore(stmt, "msatoshi_received");
		db_col_ignore(stmt, "paid_timestamp");
	}

	dtl->invstring = db_col_strdup(dtl, stmt, "bolt11");

	if (!db_col_is_null(stmt, "description"))
		dtl->description = db_col_strdup(dtl, stmt,
						 "description");
	else
		dtl->description = NULL;

	dtl->features = db_col_arr(dtl, stmt, "features", u8);
	if (!db_col_is_null(stmt, "local_offer_id")) {
		dtl->local_offer_id = tal(dtl, struct sha256);
		db_col_sha256(stmt, "local_offer_id",
			      dtl->local_offer_id);
	} else
		dtl->local_offer_id = NULL;

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
		idn->id = db_col_u64(stmt, "id");
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

	if (db_col_is_null(stmt, "MIN(expiry_time)"))
		/* Nothing to install */
		goto done;

	invoices->min_expiry_time = db_col_u64(stmt,
					       "MIN(expiry_time)");

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
		     const struct sha256 *rhash,
		     const struct sha256 *local_offer_id)
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
		"            , paid_timestamp, bolt11, description, features, local_offer_id)"
		"     VALUES ( ?, ?, ?"
		"            , ?, ?, ?"
		"            , NULL, NULL"
		"            , NULL, ?, ?, ?, ?);"));

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
	if (!description)
		db_bind_null(stmt, 7);
	else
		db_bind_text(stmt, 7, description);
	db_bind_talarr(stmt, 8, features);
	if (local_offer_id)
		db_bind_sha256(stmt, 9, local_offer_id);
	else
		db_bind_null(stmt, 9);

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

	pinvoice->id = db_col_u64(stmt, "id");
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
		pinvoice->id = db_col_u64(stmt, "id");
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
		pinvoice->id = db_col_u64(stmt, "id");
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
						       ", local_offer_id"
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
	state = db_col_int(stmt, "state");
	tal_free(stmt);
	return state;
}

/* If there's an associated offer, mark it used. */
static void maybe_mark_offer_used(struct db *db, struct invoice invoice)
{
	struct db_stmt *stmt;
	struct sha256 local_offer_id;

	stmt = db_prepare_v2(
		db, SQL("SELECT local_offer_id FROM invoices WHERE id = ?;"));
	db_bind_u64(stmt, 0, invoice.id);
	db_query_prepared(stmt);

	db_step(stmt);
	if (db_col_is_null(stmt, "local_offer_id")) {
		tal_free(stmt);
		return;
	}
	db_col_sha256(stmt, "local_offer_id", &local_offer_id);
	tal_free(stmt);

	wallet_offer_mark_used(db, &local_offer_id);
}

bool invoices_resolve(struct invoices *invoices,
		      struct invoice invoice,
		      struct amount_msat received)
{
	struct db_stmt *stmt;
	s64 pay_index;
	u64 paid_timestamp;
	enum invoice_status state = invoice_get_status(invoices, invoice);

	if (state != UNPAID)
		return false;

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

	maybe_mark_offer_used(invoices->db, invoice);

	/* Tell all the waiters about the paid invoice. */
	trigger_invoice_waiter_resolve(invoices, invoice.id, &invoice);
	return true;
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
		invoice.id = db_col_u64(stmt, "id");

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
					       ", local_offer_id"
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
