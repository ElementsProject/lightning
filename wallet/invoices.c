#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/timeout.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <lightningd/invoice.h>
#include <lightningd/lightningd.h>
#include <lightningd/wait.h>
#include <wallet/invoices.h>

struct invoice_waiter {
	/* Is this waiter already triggered? */
	bool triggered;
	/* Is this waiting for any invoice to resolve? */
	bool any;
	/* If !any, the specific invoice this is waiting on */
	u64 inv_dbid;

	struct list_node list;

	/* The callback to use */
	void (*cb)(const u64 *inv_dbid, void*);
	void *cbarg;
};

struct invoices {
	/* The database connection to use. */
	struct wallet *wallet;
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
				   const u64 *inv_dbid)
{
	w->triggered = true;
	w->cb(inv_dbid, w->cbarg);
}

static void trigger_invoice_waiter_resolve(struct invoices *invoices,
					   u64 inv_dbid)
{
	struct invoice_waiter *w;
	struct invoice_waiter *n;

	list_for_each_safe(&invoices->waiters, w, n, list) {
		if (!w->any && w->inv_dbid != inv_dbid)
			continue;
		list_del_from(&invoices->waiters, &w->list);
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, &inv_dbid);
	}
}

static void
trigger_invoice_waiter_expire_or_delete(struct invoices *invoices,
					u64 inv_dbid,
					bool deleted)
{
	struct invoice_waiter *w;
	struct invoice_waiter *n;

	list_for_each_safe(&invoices->waiters, w, n, list) {
		if (w->any || w->inv_dbid != inv_dbid)
			continue;
		list_del_from(&invoices->waiters, &w->list);
		tal_steal(tmpctx, w);
		trigger_invoice_waiter(w, deleted ? NULL : &inv_dbid);
	}
}

static struct invoice_details *wallet_stmt2invoice_details(const tal_t *ctx,
							   struct db_stmt *stmt)
{
	struct invoice_details *dtl = tal(ctx, struct invoice_details);
	struct bitcoin_outpoint *paid_outpoint;
	dtl->state = db_col_int(stmt, "state");

	db_col_preimage(stmt, "payment_key", &dtl->r);

	db_col_sha256(stmt, "payment_hash", &dtl->rhash);

	dtl->label = db_col_json_escape(dtl, stmt, "label");

	if (db_col_is_null(stmt, "msatoshi"))
		dtl->msat = NULL;
	else {
		dtl->msat = tal(dtl, struct amount_msat);
		*dtl->msat = db_col_amount_msat(stmt, "msatoshi");
	}
	dtl->expiry_time = db_col_u64(stmt, "expiry_time");

	if (dtl->state == PAID) {
		dtl->pay_index = db_col_u64(stmt, "pay_index");
		dtl->received = db_col_amount_msat(stmt, "msatoshi_received");
		dtl->paid_timestamp = db_col_u64(stmt, "paid_timestamp");
		if (!db_col_is_null(stmt, "paid_txid")) {
			paid_outpoint = tal(ctx, struct bitcoin_outpoint);
			db_col_txid(stmt, "paid_txid",
					&paid_outpoint->txid);
			paid_outpoint->n
				= db_col_int(stmt, "paid_outnum");
			dtl->paid_outpoint = paid_outpoint;
		} else {
			db_col_ignore(stmt, "paid_outnum");
			dtl->paid_outpoint = NULL;
		}
	} else {
		db_col_ignore(stmt, "pay_index");
		db_col_ignore(stmt, "msatoshi_received");
		db_col_ignore(stmt, "paid_timestamp");
		db_col_ignore(stmt, "paid_txid");
		db_col_ignore(stmt, "paid_outnum");
	}

	dtl->invstring = db_col_strdup(dtl, stmt, "bolt11");
	dtl->description = db_col_strdup_optional(dtl, stmt, "description");
	dtl->features = db_col_arr(dtl, stmt, "features", u8);
	dtl->local_offer_id = db_col_optional(dtl, stmt, "local_offer_id", sha256);
	dtl->created_index = db_col_u64(stmt, "id");
	dtl->updated_index = db_col_u64(stmt, "updated_index");
	return dtl;
}

static void install_expiration_timer(struct invoices *invoices);

struct invoices *invoices_new(const tal_t *ctx,
			      struct wallet *wallet,
			      struct timers *timers)
{
	struct invoices *invs = tal(ctx, struct invoices);

	invs->wallet = wallet;
	invs->timers = timers;

	list_head_init(&invs->waiters);

	invs->expiration_timer = NULL;
	return invs;
}

struct invoice_id_node {
	struct list_node list;
	u64 inv_dbid;
};

/* Get any invoice ids where invoice is >= expiry time and status */
static u64 *expired_ids(const tal_t *ctx,
			struct db *db,
			u64 expiry_time,
			enum invoice_status status)
{
	struct db_stmt *stmt;
	u64 *ids = tal_arr(ctx, u64, 0);

	stmt = db_prepare_v2(db, SQL("SELECT id"
				     "  FROM invoices"
				     " WHERE state = ?"
				     "   AND expiry_time <= ?"));
	db_bind_int(stmt, status);
	db_bind_u64(stmt, expiry_time);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		tal_arr_expand(&ids, db_col_u64(stmt, "id"));
	}
	tal_free(stmt);
	return ids;
}

static void trigger_expiration(struct invoices *invoices)
{
	u64 *inv_dbids;
	u64 now = time_now().ts.tv_sec;
	struct db_stmt *stmt;

	/* Free current expiration timer */
	invoices->expiration_timer = tal_free(invoices->expiration_timer);

	inv_dbids = expired_ids(tmpctx, invoices->wallet->db, now, UNPAID);

	/* Trigger expirations */
	for (size_t i = 0; i < tal_count(inv_dbids); i++) {
		stmt = db_prepare_v2(invoices->wallet->db, SQL("UPDATE invoices"
							       "   SET state = ?"
							       "      , updated_index = ?"
							       " WHERE id = ?"));
		db_bind_int(stmt, EXPIRED);
		db_bind_u64(stmt,
			    /* FIXME: details! */
			    invoice_index_update_status(invoices->wallet->ld,
							NULL, EXPIRED));
		db_bind_u64(stmt, inv_dbids[i]);
		db_exec_prepared_v2(take(stmt));

		/* Trigger expiration */
		trigger_invoice_waiter_expire_or_delete(invoices, inv_dbids[i], false);
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
	stmt = db_prepare_v2(invoices->wallet->db, SQL("SELECT MIN(expiry_time)"
					       "  FROM invoices"
					       " WHERE state = ?;"));
	db_bind_int(stmt, UNPAID);

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

	/* Hi!  On a 32 bit time_t platform with an expiry after 2038?  Let's
	 * not set a timer, assuming you'll upgrade before then! */
	if (expiry.ts.tv_sec != invoices->min_expiry_time)
		goto done;

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
		     u64 *inv_dbid,
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
	u64 expiry_time;
	u64 now = time_now().ts.tv_sec;

	if (invoices_find_by_label(invoices, inv_dbid, label)) {
		if (taken(msat))
			tal_free(msat);
		if (taken(label))
			tal_free(label);
		return false;
	}

	/* Compute expiration. */
	expiry_time = now + expiry;

	*inv_dbid = invoice_index_created(invoices->wallet->ld, UNPAID, label, b11enc);

	/* Save to database. */
	stmt = db_prepare_v2(
	    invoices->wallet->db,
	    SQL("INSERT INTO invoices"
		"            ( id, payment_hash, payment_key, state"
		"            , msatoshi, label, expiry_time"
		"            , pay_index, msatoshi_received"
		"            , paid_timestamp, bolt11, description, features, local_offer_id)"
		"     VALUES ( ?, ?, ?, ?"
		"            , ?, ?, ?"
		"            , NULL, NULL"
		"            , NULL, ?, ?, ?, ?);"));

	db_bind_u64(stmt, *inv_dbid);
	db_bind_sha256(stmt, rhash);
	db_bind_preimage(stmt, r);
	db_bind_int(stmt, UNPAID);
	if (msat)
		db_bind_amount_msat(stmt, msat);
	else
		db_bind_null(stmt);
	db_bind_json_escape(stmt, label);
	db_bind_u64(stmt, expiry_time);
	db_bind_text(stmt, b11enc);
	if (!description)
		db_bind_null(stmt);
	else
		db_bind_text(stmt, description);
	db_bind_talarr(stmt, features);
	if (local_offer_id)
		db_bind_sha256(stmt, local_offer_id);
	else
		db_bind_null(stmt);

	db_exec_prepared_v2(stmt);
	tal_free(stmt);

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
			    u64 *inv_dbid,
			    const struct json_escape *label)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(invoices->wallet->db, SQL("SELECT id"
					       "  FROM invoices"
					       " WHERE label = ?;"));
	db_bind_json_escape(stmt, label);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	}

	*inv_dbid = db_col_u64(stmt, "id");
	tal_free(stmt);
	return true;
}

bool invoices_find_by_rhash(struct invoices *invoices,
			    u64 *inv_dbid,
			    const struct sha256 *rhash)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(invoices->wallet->db, SQL("SELECT id"
					       "  FROM invoices"
					       " WHERE payment_hash = ?;"));
	db_bind_sha256(stmt, rhash);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	} else {
		*inv_dbid = db_col_u64(stmt, "id");
		tal_free(stmt);
		return true;
	}
}

void invoices_create_fallback(struct invoices *invoices,
			      u64 inv_dbid,
			      const u8 *scriptPubkey)
{
	struct db_stmt *stmt;

	/* Save to database. */
	stmt = db_prepare_v2(
	    invoices->wallet->db,
	    SQL("INSERT INTO invoice_fallbacks"
		"            ( invoice_id, scriptpubkey )"
		"     VALUES ( ?, ?);"));

	db_bind_u64(stmt, inv_dbid);
	db_bind_blob(stmt, scriptPubkey,
			  tal_bytelen(scriptPubkey));
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

bool invoices_find_by_fallback_script(struct invoices *invoices,
			    u64 *inv_dbid,
			    const u8 *scriptPubkey)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(invoices->wallet->db, SQL("SELECT invoice_id"
					       "  FROM invoice_fallbacks"
					       " WHERE scriptpubkey = ?;"));
	db_bind_talarr(stmt, scriptPubkey);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	} else {
		*inv_dbid = db_col_u64(stmt, "invoice_id");
		tal_free(stmt);
		return true;
	}
}

bool invoices_find_unpaid(struct invoices *invoices,
			  u64 *inv_dbid,
			  const struct sha256 *rhash)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(invoices->wallet->db, SQL("SELECT id"
					       "  FROM invoices"
					       " WHERE payment_hash = ?"
					       "   AND state = ?;"));
	db_bind_sha256(stmt, rhash);
	db_bind_int(stmt, UNPAID);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	} else  {
		*inv_dbid = db_col_u64(stmt, "id");
		tal_free(stmt);
		return true;
	}
}

bool invoices_delete(struct invoices *invoices, u64 inv_dbid,
		     enum invoice_status status,
		     const struct json_escape *label,
		     const char *invstring)
{
	struct db_stmt *stmt;
	int changes;
	/* Delete from database. */
	stmt = db_prepare_v2(invoices->wallet->db,
			     SQL("DELETE FROM invoices WHERE id=?;"));
	db_bind_u64(stmt, inv_dbid);
	db_exec_prepared_v2(stmt);

	changes = db_count_changes(stmt);
	tal_free(stmt);

	if (changes != 1) {
		return false;
	}
	/* Tell all the waiters about the fact that it was deleted. */
	invoice_index_deleted(invoices->wallet->ld, status, label, invstring);
	trigger_invoice_waiter_expire_or_delete(invoices, inv_dbid, true);
	return true;
}

bool invoices_delete_description(struct invoices *invoices, u64 inv_dbid,
				 const struct json_escape *label,
				 const char *description)
{
	struct db_stmt *stmt;
	int changes;

	stmt = db_prepare_v2(invoices->wallet->db,
			     SQL("UPDATE invoices"
				 "   SET description = NULL,"
				 "       updated_index = ?"
				 " WHERE ID = ?;"));
	db_bind_u64(stmt,
		    invoice_index_update_deldesc(invoices->wallet->ld,
						 label, description));
	db_bind_u64(stmt, inv_dbid);
	db_exec_prepared_v2(stmt);

	changes = db_count_changes(stmt);
	tal_free(stmt);

	return changes == 1;
}

struct db_stmt *invoices_first(struct invoices *invoices,
			       const enum wait_index *listindex,
			       u64 liststart,
			       const u32 *listlimit,
			       u64 *inv_dbid)
{
	struct db_stmt *stmt;

	if (listindex && *listindex == WAIT_INDEX_UPDATED) {
		stmt = db_prepare_v2(invoices->wallet->db,
				     SQL("SELECT id FROM invoices"
					 " WHERE updated_index >= ?"
					 " ORDER BY updated_index"
					 " LIMIT ?;"));
	} else {
		stmt = db_prepare_v2(invoices->wallet->db,
				     SQL("SELECT id FROM invoices"
					 " WHERE id >= ?"
					 " ORDER BY id"
					 " LIMIT ?;"));
	}
	db_bind_u64(stmt, liststart);
	if (listlimit)
		db_bind_int(stmt, *listlimit);
	else
		db_bind_int(stmt, INT_MAX);
	db_query_prepared(stmt);

	return invoices_next(invoices, stmt, inv_dbid);
}

struct db_stmt *invoices_next(struct invoices *invoices,
			      struct db_stmt *stmt,
			      u64 *inv_dbid)
{
	if (!db_step(stmt))
		return tal_free(stmt);

	*inv_dbid = db_col_u64(stmt, "id");
	return stmt;
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

static enum invoice_status invoice_get_status(struct invoices *invoices,
					      u64 inv_dbid)
{
	struct db_stmt *stmt;
	enum invoice_status state;
	bool res;

	stmt = db_prepare_v2(
	    invoices->wallet->db, SQL("SELECT state FROM invoices WHERE id = ?;"));
	db_bind_u64(stmt, inv_dbid);
	db_query_prepared(stmt);

	res = db_step(stmt);
	assert(res);
	state = db_col_int(stmt, "state");
	tal_free(stmt);
	return state;
}

/* If there's an associated offer, mark it used. */
static void maybe_mark_offer_used(struct db *db, u64 inv_dbid)
{
	struct db_stmt *stmt;
	struct sha256 local_offer_id;

	stmt = db_prepare_v2(
		db, SQL("SELECT local_offer_id FROM invoices WHERE id = ?;"));
	db_bind_u64(stmt, inv_dbid);
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
		      u64 inv_dbid,
		      struct amount_msat received,
		      const struct json_escape *label,
		      const struct bitcoin_outpoint *outpoint)
{
	struct db_stmt *stmt;
	s64 pay_index;
	u64 paid_timestamp;
	enum invoice_status state = invoice_get_status(invoices, inv_dbid);

	if (state != UNPAID)
		return false;

	/* Assign a pay-index. */
	pay_index = get_next_pay_index(invoices->wallet->db);
	paid_timestamp = time_now().ts.tv_sec;

	/* Update database. */
	stmt = db_prepare_v2(invoices->wallet->db, SQL("UPDATE invoices"
					       "   SET state=?"
					       "     , pay_index=?"
					       "     , msatoshi_received=?"
					       "     , paid_timestamp=?"
					       "     , paid_txid=?"
					       "     , paid_outnum=?"
					       "     , updated_index=?"
					       " WHERE id=?;"));
	db_bind_int(stmt, PAID);
	db_bind_u64(stmt, pay_index);
	db_bind_amount_msat(stmt, &received);
	db_bind_u64(stmt, paid_timestamp);
	if (outpoint) {
		db_bind_txid(stmt, &outpoint->txid);
		db_bind_int(stmt, outpoint->n);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
	}
	db_bind_u64(stmt,
		    invoice_index_update_status(invoices->wallet->ld,
						label, PAID));
	db_bind_u64(stmt, inv_dbid);
	db_exec_prepared_v2(take(stmt));

	maybe_mark_offer_used(invoices->wallet->db, inv_dbid);

	/* Tell all the waiters about the paid invoice. */
	trigger_invoice_waiter_resolve(invoices, inv_dbid);
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
			       u64 inv_dbid,
			       void (*cb)(const u64 *, void*),
			       void* cbarg)
{
	struct invoice_waiter *w = tal(ctx, struct invoice_waiter);
	w->triggered = false;
	w->any = any;
	w->inv_dbid = inv_dbid;
	list_add_tail(waiters, &w->list);
	w->cb = cb;
	w->cbarg = cbarg;
	tal_add_destructor(w, &destroy_invoice_waiter);
}


void invoices_waitany(const tal_t *ctx,
		      struct invoices *invoices,
		      u64 lastpay_index,
		      void (*cb)(const u64 *, void*),
		      void *cbarg)
{
	struct db_stmt *stmt;

	/* Look for an already-paid invoice. */
	stmt = db_prepare_v2(invoices->wallet->db,
			     SQL("SELECT id"
				 "  FROM invoices"
				 " WHERE pay_index IS NOT NULL"
				 "   AND pay_index > ?"
				 " ORDER BY pay_index ASC LIMIT 1;"));
	db_bind_u64(stmt, lastpay_index);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		u64 inv_dbid = db_col_u64(stmt, "id");

		cb(&inv_dbid, cbarg);
	} else {
		/* None found. */
		add_invoice_waiter(ctx, &invoices->waiters,
			   true, 0, cb, cbarg);
	}
	tal_free(stmt);
}


void invoices_waitone(const tal_t *ctx,
		      struct invoices *invoices,
		      u64 inv_dbid,
		      void (*cb)(const u64 *, void*),
		      void *cbarg)
{
	enum invoice_status state;

	state = invoice_get_status(invoices, inv_dbid);

	if (state == PAID || state == EXPIRED) {
		cb(&inv_dbid, cbarg);
		return;
	}

	/* Not yet paid. */
	add_invoice_waiter(ctx, &invoices->waiters,
			   false, inv_dbid, cb, cbarg);
}

struct invoice_details *invoices_get_details(const tal_t *ctx,
					     struct invoices *invoices,
					     u64 inv_dbid)
{
	struct db_stmt *stmt;
	bool res;
	struct invoice_details *details;

	stmt = db_prepare_v2(invoices->wallet->db, SQL("SELECT"
					       "  state"
					       ", payment_key"
					       ", payment_hash"
					       ", label"
					       ", msatoshi"
					       ", expiry_time"
					       ", pay_index"
					       ", msatoshi_received"
					       ", paid_timestamp"
					       ", paid_txid"
					       ", paid_outnum"
					       ", bolt11"
					       ", description"
					       ", features"
					       ", local_offer_id"
					       ", id"
					       ", updated_index"
					       " FROM invoices"
					       " WHERE id = ?;"));
	db_bind_u64(stmt, inv_dbid);
	db_query_prepared(stmt);
	res = db_step(stmt);
	assert(res);

	details = wallet_stmt2invoice_details(ctx, stmt);
	tal_free(stmt);
	return details;
}

static u64 invoice_index_inc(struct lightningd *ld,
			     const enum invoice_status *state,
			     const struct json_escape *label,
			     const char *invstring,
			     const char *description,
			     enum wait_index idx)
{
	const char *invstrname;

	if (invstring && strstarts(invstring, "lni"))
		invstrname = "bolt12";
	else
		invstrname = "bolt11";


	return wait_index_increment(ld, WAIT_SUBSYSTEM_INVOICE, idx,
				 "status", state ? invoice_status_str(*state) : NULL,
				 /* We don't want to add more JSON escapes here! */
				 "=label", label ? tal_fmt(tmpctx, "\"%s\"", label->s) : NULL,
				 invstrname, invstring,
				 "description", description,
				 NULL);
}

void invoice_index_deleted(struct lightningd *ld,
			   enum invoice_status state,
			   const struct json_escape *label,
			   const char *invstring)
{
	assert(label);
	assert(invstring);
	invoice_index_inc(ld, &state, label, invstring, NULL, WAIT_INDEX_DELETED);
}

/* Fortuntely, dbids start at 1, not 0! */
u64 invoice_index_created(struct lightningd *ld,
			  enum invoice_status state,
			  const struct json_escape *label,
			  const char *invstring)
{
	assert(label);
	assert(invstring);

	return invoice_index_inc(ld, &state, label, invstring, NULL,
				 WAIT_INDEX_CREATED);
}

/* FIXME: We allow missing label here! :( */
u64 invoice_index_update_status(struct lightningd *ld,
				const struct json_escape *label,
				enum invoice_status state)
{
	return invoice_index_inc(ld, &state, label, NULL, NULL,
				 WAIT_INDEX_UPDATED);
}

u64 invoice_index_update_deldesc(struct lightningd *ld,
				 const struct json_escape *label,
				 const char *description)
{
	assert(description);
	return invoice_index_inc(ld, NULL, label, NULL, description,
				 WAIT_INDEX_UPDATED);
}

void invoices_start_expiration(struct lightningd *ld)
{
	trigger_expiration(ld->wallet->invoices);
}
