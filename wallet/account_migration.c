/* All this code is to read the old accounts.db file from bookkeeper
 * and copy the moves table */
#include "config.h"
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/lightningd.h>
#include <unistd.h>
#include <wallet/account_migration.h>
#include <wallet/wallet.h>

/* These functions and definitions copied almost exactly from old
 * plugins/bkpr/{recorder.c,chain_event.h,channel_event.h}
 */
struct chain_event {

	/* Id of this chain event in the database */
	u64 db_id;

	/* db_id of account this event belongs to */
	u64 acct_db_id;

	/* Name of the account this belongs to */
	char *acct_name;

	/* Name of account this originated from */
	char *origin_acct;

	/* Tag describing the event */
	const char *tag;

	/* Is the node's wallet ignoring this? */
	bool ignored;

	/* Is this chain output stealable? If so
	 * we'll need to watch it for longer */
	bool stealable;

	/* Is this chain event because of a splice
	 * confirmation? */
	bool splice_close;

	/* Is this a rebalance event? */
	bool rebalance;

	/* Amount we received in this event */
	struct amount_msat credit;

	/* Amount we paid in this event */
	struct amount_msat debit;

	/* Total 'amount' of output on this chain event */
	struct amount_msat output_value;

	/* What token are the credit/debits? */
	const char *currency;

	/* What time did the event happen */
	u64 timestamp;

	/* What block did the event happen */
	u32 blockheight;

	/* What txo did this event concern */
	struct bitcoin_outpoint outpoint;

	/* What tx was the outpoint spent in (if spent) */
	struct bitcoin_txid *spending_txid;

	/* Sometimes chain events resolve payments */
	struct sha256 *payment_id;

	/* Desc of event (maybe useful for printing notes) */
	const char *desc;

	/* Added: close_count */
	u32 output_count;

	/* Added: peer_id */
	struct node_id *peer_id;

	/* Added: did we open this account? */
	bool we_opened;
};

static struct chain_event *stmt2chain_event(const tal_t *ctx, struct db_stmt *stmt)
{
	struct chain_event *e = tal(ctx, struct chain_event);
	e->db_id = db_col_u64(stmt, "e.id");
	e->acct_db_id = db_col_u64(stmt, "e.account_id");
	e->acct_name = db_col_strdup(e, stmt, "a.name");

	if (!db_col_is_null(stmt, "e.origin"))
		e->origin_acct = db_col_strdup(e, stmt, "e.origin");
	else
		e->origin_acct = NULL;

	e->tag = db_col_strdup(e, stmt, "e.tag");

	e->credit = db_col_amount_msat(stmt, "e.credit");
	e->debit = db_col_amount_msat(stmt, "e.debit");
	e->output_value = db_col_amount_msat(stmt, "e.output_value");

	e->currency = db_col_strdup_optional(e, stmt, "e.currency");
	e->timestamp = db_col_u64(stmt, "e.timestamp");
	e->blockheight = db_col_int(stmt, "e.blockheight");

	db_col_txid(stmt, "e.utxo_txid", &e->outpoint.txid);
	e->outpoint.n = db_col_int(stmt, "e.outnum");

	if (!db_col_is_null(stmt, "e.payment_id")) {
		e->payment_id = tal(e, struct sha256);
		db_col_sha256(stmt, "e.payment_id", e->payment_id);
	} else
		e->payment_id = NULL;

	if (!db_col_is_null(stmt, "e.spending_txid")) {
		e->spending_txid = tal(e, struct bitcoin_txid);
		db_col_txid(stmt, "e.spending_txid", e->spending_txid);
	} else
		e->spending_txid = NULL;

	/* If they ran master before this, ignored might be null! */
	if (db_col_is_null(stmt, "e.ignored"))
		e->ignored = false;
	else
		e->ignored = db_col_int(stmt, "e.ignored") == 1;
	e->stealable = db_col_int(stmt, "e.stealable") == 1;

	if (!db_col_is_null(stmt, "e.ev_desc"))
		e->desc = db_col_strdup(e, stmt, "e.ev_desc");
	else
		e->desc = NULL;

	e->splice_close = db_col_int(stmt, "e.spliced") == 1;
	e->output_count = db_col_int(stmt, "a.closed_count");
	if (!db_col_is_null(stmt, "a.peer_id")) {
		e->peer_id = tal(e, struct node_id);
		db_col_node_id(stmt, "a.peer_id", e->peer_id);
	} else
		e->peer_id = NULL;

	e->we_opened = db_col_int(stmt, "a.we_opened");

	/* Note that they would have never executed the final migration from
	 * "common: remove "ignored" tag", in this PR, so we do that now:
	 *	{SQL("UPDATE chain_events"
	 *	     " SET account_id = (SELECT id FROM accounts WHERE name = 'external')"
	 *	     " WHERE account_id = (SELECT id FROM accounts WHERE name = 'wallet')"
	 *	     " AND ignored = 1"), NULL},
	 */
	if (e->ignored && streq(e->acct_name, ACCOUNT_NAME_WALLET))
		e->acct_name = ACCOUNT_NAME_EXTERNAL;

	return e;
}

static struct chain_event **find_chain_events(const tal_t *ctx,
					      struct db_stmt *stmt TAKES)
{
	struct chain_event **results;

	db_query_prepared(stmt);
	if (stmt->error)
		db_fatal(stmt->db, "find_chain_events err: %s", stmt->error);
	results = tal_arr(ctx, struct chain_event *, 0);
	while (db_step(stmt)) {
		struct chain_event *e = stmt2chain_event(results, stmt);
		tal_arr_expand(&results, e);
	}

	if (taken(stmt))
		tal_free(stmt);

	return results;
}

static struct chain_event **list_chain_events(const tal_t *ctx, struct db *db)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.currency"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.ignored"
				     ", e.stealable"
				     ", e.ev_desc"
				     ", e.spliced"
				     ", a.closed_count"
				     ", a.peer_id"
				     ", a.we_opened"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " ORDER BY e.timestamp, e.id;"));

	return find_chain_events(ctx, take(stmt));
}

struct channel_event {

	/* Id of this chain event in the database */
	u64 db_id;

	/* db_id of account this event belongs to */
	u64 acct_db_id;

	/* Name of the account this belongs to */
	char *acct_name;

	/* Tag describing the event */
	const char *tag;

	/* Amount we received in this event */
	struct amount_msat credit;

	/* Amount we paid in this event */
	struct amount_msat debit;

	/* Total 'fees' related to this channel event */
	struct amount_msat fees;

	/* What token are the credit/debits? */
	const char *currency;

	/* Payment identifier (typically the preimage hash) */
	struct sha256 *payment_id;

	/* Some payments share a payment_id, and are differentiable via id */
	u32 part_id;

	/* What time did the event happen */
	u64 timestamp;

	/* Description, usually from invoice */
	const char *desc;

	/* ID of paired event, iff is a rebalance */
	u64 *rebalance_id;
};

static struct channel_event *stmt2channel_event(const tal_t *ctx, struct db_stmt *stmt)
{
	struct channel_event *e = tal(ctx, struct channel_event);

	e->db_id = db_col_u64(stmt, "e.id");
	e->acct_db_id = db_col_u64(stmt, "e.account_id");
	e->acct_name = db_col_strdup(e, stmt, "a.name");

	e->tag = db_col_strdup(e, stmt, "e.tag");

	e->credit = db_col_amount_msat(stmt, "e.credit");
	e->debit = db_col_amount_msat(stmt, "e.debit");
	e->fees = db_col_amount_msat(stmt, "e.fees");

	e->currency = db_col_strdup_optional(e, stmt, "e.currency");
	if (!db_col_is_null(stmt, "e.payment_id")) {
		e->payment_id = tal(e, struct sha256);
		db_col_sha256(stmt, "e.payment_id", e->payment_id);
	} else
		e->payment_id = NULL;
	e->part_id = db_col_int(stmt, "e.part_id");
	e->timestamp = db_col_u64(stmt, "e.timestamp");

	if (!db_col_is_null(stmt, "e.ev_desc"))
		e->desc = db_col_strdup(e, stmt, "e.ev_desc");
	else
		e->desc = NULL;

	if (!db_col_is_null(stmt, "e.rebalance_id")) {
		e->rebalance_id = tal(e, u64);
		*e->rebalance_id = db_col_u64(stmt, "e.rebalance_id");
	} else
		e->rebalance_id = NULL;

	return e;
}

static struct channel_event **list_channel_events(const tal_t *ctx,
						  struct db *db)

{
	struct db_stmt *stmt;
	struct channel_event **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.fees"
				     ", e.currency"
				     ", e.payment_id"
				     ", e.part_id"
				     ", e.timestamp"
				     ", e.ev_desc"
				     ", e.rebalance_id"
				     " FROM channel_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = e.account_id"
				     " ORDER BY e.timestamp, e.id;"));
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct channel_event *, 0);
	while (db_step(stmt)) {
		struct channel_event *e = stmt2channel_event(results, stmt);
		tal_arr_expand(&results, e);
	}
	tal_free(stmt);

	return results;
}
/* end stolen code */

static void acct_db_error(struct lightningd *ld, bool fatal, const char *fmt, va_list ap)
{
	va_list ap2;

	fmt = tal_fmt(tmpctx, "bookkeper migration: %s", fmt);
	va_copy(ap2, ap);
	logv(ld->log, LOG_BROKEN, NULL, true, fmt, ap);

	if (fatal)
		fatal_vfmt(fmt, ap2);
	va_end(ap2);
}

void migrate_from_account_db(struct lightningd *ld, struct db *db)
{
	const char *olddir = NULL;
	const char *db_dsn;
	struct db *account_db;
	struct chain_event **chain_events;
	struct channel_event **channel_events;
	size_t descriptions_migrated = 0;
	struct db_stmt *stmt;
	int version;

	/* Initialize wait indices: we're going to use it to generate ids. */
	load_indexes(db, ld->indexes);

	/* Switch to bookkeeper-dir, if specified */
	if (ld->old_bookkeeper_dir) {
		olddir = path_cwd(NULL);
		if (chdir(ld->old_bookkeeper_dir) != 0)
			fatal("Unable to switch to 'bookkeeper-dir'=%s",
			      ld->old_bookkeeper_dir);
	}

	/* No user suppled db_dsn, set one up here */
	db_dsn = ld->old_bookkeeper_db;
	if (!db_dsn)
		db_dsn = "sqlite3://accounts.sqlite3";

	/* If we can't open it, we ignore it */
	account_db = db_open(NULL, db_dsn, ld->developer, false, acct_db_error, ld);
	if (!account_db) {
		migrate_setup_coinmoves(ld, db);
		goto out;
	}

	/* Load events */
	db_begin_transaction(account_db);
	version = db_get_version(account_db);
	/* -1 means empty database (Postgres usually). */
	if (version == -1) {
		db_commit_transaction(account_db);
		tal_free(account_db);
		migrate_setup_coinmoves(ld, db);
		goto out;
	}
	/* Last migration was 24.08.  Migrate there first if this happens. */
	if (version != 17 && version != 18)
		fatal("Cannot migrate account database version %i", version);
	chain_events = list_chain_events(tmpctx, account_db);
	channel_events = list_channel_events(tmpctx, account_db);
	db_commit_transaction(account_db);
	tal_free(account_db);

	for (size_t i = 0; i < tal_count(chain_events); i++) {
		const struct chain_event *ev = chain_events[i];
		struct mvt_account_id *account = tal(ev, struct mvt_account_id);
		struct mvt_tags tags;
		enum mvt_tag tag;
		struct amount_sat output_sat;
		u64 id;

		/* We removed currency support, because the only way you could
		 * use it was to inject your own events, and nobody did that
		 * and it would be a nightmare to support */
		if (ev->currency
		    && !streq(ev->currency, chainparams->lightning_hrp)) {
			log_broken(ld->log, "IGNORING foreign currency chain event (%s, currency %s)",
				   ev->tag, ev->currency);
			continue;
		}

		stmt = db_prepare_v2(db,
			     SQL("INSERT INTO chain_moves ("
				 " id,"
				 " account_channel_id,"
				 " account_nonchannel_id,"
				 " tag_bitmap,"
				 " credit_or_debit,"
				 " timestamp,"
				 " utxo,"
				 " spending_txid,"
				 " peer_id,"
				 " payment_hash,"
				 " block_height,"
				 " output_sat,"
				 " originating_channel_id,"
				 " originating_nonchannel_id,"
				 " output_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
		set_mvt_account_id(account, NULL, ev->acct_name);
		id = chain_mvt_index_created(ld, db, account, ev->credit, ev->debit);
		db_bind_u64(stmt, id);
		if (!mvt_tag_parse(ev->tag, strlen(ev->tag), &tag))
			abort();
		tags = tag_to_mvt_tags(tag);
		if (tag == MVT_CHANNEL_OPEN && ev->we_opened)
			mvt_tag_set(&tags, MVT_OPENER);
		if (ev->splice_close)
			mvt_tag_set(&tags, MVT_SPLICE);
		if (ev->stealable)
			mvt_tag_set(&tags, MVT_STEALABLE);
		db_bind_mvt_account_id(stmt, db, account);
		db_bind_mvt_tags(stmt, tags);
		db_bind_credit_debit(stmt, ev->credit, ev->debit);
		db_bind_u64(stmt, ev->timestamp);
		db_bind_outpoint(stmt, &ev->outpoint);
		if (ev->spending_txid)
			db_bind_txid(stmt, ev->spending_txid);
		else
			db_bind_null(stmt);
		if (ev->peer_id)
			db_bind_node_id(stmt, ev->peer_id);
		else
			db_bind_null(stmt);
		if (ev->payment_id)
			db_bind_sha256(stmt, ev->payment_id);
		else
			db_bind_null(stmt);
		db_bind_int(stmt, ev->blockheight);
		if (!amount_msat_to_sat(&output_sat, ev->output_value))
			abort();
		db_bind_amount_sat(stmt, output_sat);
		if (ev->origin_acct) {
			struct mvt_account_id *orig_account = tal(ev, struct mvt_account_id);
			set_mvt_account_id(orig_account, NULL, ev->origin_acct);
			db_bind_mvt_account_id(stmt, db, orig_account);
		} else {
			db_bind_null(stmt);
			db_bind_null(stmt);
		}
		if (ev->output_count > 0)
			db_bind_int(stmt, ev->output_count);
		else
			db_bind_null(stmt);
		db_exec_prepared_v2(take(stmt));

		/* Put descriptions into datastore for bookkeeper */
		if (ev->desc) {
			log_debug(ld->log, "Adding utxo description '%s' to %s",
				  ev->desc, fmt_bitcoin_outpoint(tmpctx, &ev->outpoint));
			wallet_datastore_save_utxo_description(db, &ev->outpoint, ev->desc);
			descriptions_migrated++;
		}
	}

	for (size_t i = 0; i < tal_count(channel_events); i++) {
		const struct channel_event *ev = channel_events[i];
		struct mvt_account_id *account = tal(ev, struct mvt_account_id);
		enum mvt_tag tag;
		u64 id;

		/* We removed currency support, because the only way you could
		 * use it was to inject your own events, and nobody did that
		 * and it would be a nightmare to support */
		if (ev->currency
		    && !streq(ev->currency, chainparams->lightning_hrp)) {
			log_broken(ld->log, "IGNORING foreign currency channel event (%s, currency %s)",
				   ev->tag, ev->currency);
			continue;
		}

		stmt = db_prepare_v2(db,
			     SQL("INSERT INTO channel_moves ("
				 " id,"
				 " account_channel_id,"
				 " account_nonchannel_id,"
				 " credit_or_debit,"
				 " tag_bitmap,"
				 " timestamp,"
				 " payment_hash,"
				 " payment_part_id,"
				 " payment_group_id,"
				 " fees) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));
		set_mvt_account_id(account, NULL, ev->acct_name);
		id = channel_mvt_index_created(ld, db, account, ev->credit, ev->debit);
		db_bind_u64(stmt, id);
		db_bind_mvt_account_id(stmt, db, account);
		db_bind_credit_debit(stmt, ev->credit, ev->debit);
		if (!mvt_tag_parse(ev->tag, strlen(ev->tag), &tag))
			abort();
		db_bind_mvt_tags(stmt, tag_to_mvt_tags(tag));
		db_bind_u64(stmt, ev->timestamp);
		if (ev->payment_id)
			db_bind_sha256(stmt, ev->payment_id);
		else
			db_bind_null(stmt);
		if (ev->part_id) {
			db_bind_u64(stmt, ev->part_id);
			/* Unf. this was not recorded! */
			db_bind_u64(stmt, 0);
		} else {
			db_bind_null(stmt);
			db_bind_null(stmt);
		}
		db_bind_amount_msat(stmt, ev->fees);
		db_exec_prepared_v2(take(stmt));

		/* Put descriptions into datastore for bookkeeper */
		if (ev->desc && ev->payment_id) {
			wallet_datastore_save_payment_description(db, ev->payment_id, ev->desc);
			descriptions_migrated++;
		}
	}

	log_info(ld->log, "bookkeeper migration complete: migrated %zu chainmoves, %zu channelmoves, %zu descriptions",
		 tal_count(chain_events),
		 tal_count(channel_events),
		 descriptions_migrated);

out:
	if (olddir) {
		if (chdir(olddir) != 0)
			fatal("Unable to switch to back to %s",
			      olddir);
		tal_free(olddir);
	}
}
