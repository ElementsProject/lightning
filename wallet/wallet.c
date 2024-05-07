#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <common/blockheight_states.h>
#include <common/fee_states.h>
#include <common/onionreply.h>
#include <common/trace.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_gossip.h>
#include <lightningd/closed_channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/notification.h>
#include <lightningd/peer_control.h>
#include <lightningd/runes.h>
#include <onchaind/onchaind_wiregen.h>
#include <wallet/invoices.h>
#include <wallet/txfilter.h>
#include <wallet/wallet.h>
#include <wally_bip32.h>

#define SQLITE_MAX_UINT 0x7FFFFFFFFFFFFFFF
#define DIRECTION_INCOMING 0
#define DIRECTION_OUTGOING 1
/* How many blocks must a UTXO entry be buried under to be considered old enough
 * to prune? */
#define UTXO_PRUNE_DEPTH 144

/* 12 hours is usually enough reservation time */
#define RESERVATION_INC (6 * 12)

/* Possible channel state */
enum channel_state_bucket {
	IN_OFFERED = 0,
	IN_FULLFILLED = 1,
	OUT_OFFERED = 2,
	OUT_FULLFILLED = 3,
};

/* channel state identifier */
struct channel_state_param {
	const char *dir_key;
	const char *type_key;
	const enum channel_state_bucket state;
};

/* These go in db, so values cannot change (we can't put this into
 * lightningd/channel_state.h since it confuses cdump!) */
static enum state_change state_change_in_db(enum state_change s)
{
	switch (s) {
	case REASON_UNKNOWN:
		BUILD_ASSERT(REASON_UNKNOWN == 0);
		return s;
	case REASON_LOCAL:
		BUILD_ASSERT(REASON_LOCAL == 1);
		return s;
	case REASON_USER:
		BUILD_ASSERT(REASON_USER == 2);
		return s;
	case REASON_REMOTE:
		BUILD_ASSERT(REASON_REMOTE == 3);
		return s;
	case REASON_PROTOCOL:
		BUILD_ASSERT(REASON_PROTOCOL == 4);
		return s;
	case REASON_ONCHAIN:
		BUILD_ASSERT(REASON_ONCHAIN == 5);
		return s;
	}
	fatal("%s: %u is invalid", __func__, s);
}

static void outpointfilters_init(struct wallet *w)
{
	struct db_stmt *stmt;
	struct utxo **utxos = wallet_get_all_utxos(NULL, w);
	struct bitcoin_outpoint outpoint;

	w->owned_outpoints = outpointfilter_new(w);
	for (size_t i = 0; i < tal_count(utxos); i++)
		outpointfilter_add(w->owned_outpoints, &utxos[i]->outpoint);

	tal_free(utxos);

	w->utxoset_outpoints = outpointfilter_new(w);
	stmt = db_prepare_v2(
	    w->db,
	    SQL("SELECT txid, outnum FROM utxoset WHERE spendheight is NULL"));
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		db_col_txid(stmt, "txid", &outpoint.txid);
		outpoint.n = db_col_int(stmt, "outnum");
		outpointfilter_add(w->utxoset_outpoints, &outpoint);
	}
	tal_free(stmt);
}

struct wallet *wallet_new(struct lightningd *ld, struct timers *timers)
{
	struct wallet *wallet = tal(ld, struct wallet);
	wallet->ld = ld;
	wallet->log = new_logger(wallet, ld->log_book, NULL, "wallet");
	wallet->keyscan_gap = 50;
	trace_span_start("db_setup", wallet);
	wallet->db = db_setup(wallet, ld, ld->bip32_base);
	trace_span_end(wallet);

	db_begin_transaction(wallet->db);

	trace_span_start("load_indexes", wallet);
	load_indexes(wallet->db, ld->indexes);
	trace_span_end(wallet);

	trace_span_start("invoices_new", wallet);
	wallet->invoices = invoices_new(wallet, wallet, timers);
	trace_span_end(wallet);

	trace_span_start("outpointfilters_init", wallet);
	outpointfilters_init(wallet);
	trace_span_end(wallet);

	db_commit_transaction(wallet->db);
	return wallet;
}

/**
 * wallet_add_utxo - Register an UTXO which we (partially) own
 *
 * Add an UTXO to the set of outputs we care about.
 *
 * This can fail if we've already seen UTXO.
 */
static bool wallet_add_utxo(struct wallet *w,
			    const struct utxo *utxo,
			    enum wallet_output_type type)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT * from outputs WHERE "
					"prev_out_tx=? AND prev_out_index=?"));
	db_bind_txid(stmt, &utxo->outpoint.txid);
	db_bind_int(stmt, utxo->outpoint.n);
	db_query_prepared(stmt);

	/* If we get a result, that means a clash. */
	if (db_step(stmt)) {
		db_col_ignore(stmt, "*");
		tal_free(stmt);
		return false;
	}
	tal_free(stmt);

	stmt = db_prepare_v2(
	    w->db, SQL("INSERT INTO outputs ("
		       "  prev_out_tx"
		       ", prev_out_index"
		       ", value"
		       ", type"
		       ", status"
		       ", keyindex"
		       ", channel_id"
		       ", peer_id"
		       ", commitment_point"
		       ", option_anchor_outputs"
		       ", confirmation_height"
		       ", spend_height"
		       ", scriptpubkey"
		       ", is_in_coinbase"
		       ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));
	db_bind_txid(stmt, &utxo->outpoint.txid);
	db_bind_int(stmt, utxo->outpoint.n);
	db_bind_amount_sat(stmt, &utxo->amount);
	db_bind_int(stmt, wallet_output_type_in_db(type));
	db_bind_int(stmt, OUTPUT_STATE_AVAILABLE);
	db_bind_int(stmt, utxo->keyindex);
	if (utxo->close_info) {
		db_bind_u64(stmt, utxo->close_info->channel_id);
		db_bind_node_id(stmt, &utxo->close_info->peer_id);
		if (utxo->close_info->commitment_point)
			db_bind_pubkey(stmt, utxo->close_info->commitment_point);
		else
			db_bind_null(stmt);
		db_bind_int(stmt, utxo->close_info->option_anchors);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_null(stmt);
	}

	if (utxo->blockheight) {
		db_bind_int(stmt, *utxo->blockheight);
	} else
		db_bind_null(stmt);

	if (utxo->spendheight)
		db_bind_int(stmt, *utxo->spendheight);
	else
		db_bind_null(stmt);

	db_bind_blob(stmt, utxo->scriptPubkey,
			  tal_bytelen(utxo->scriptPubkey));

	db_bind_int(stmt, utxo->is_in_coinbase);
	db_exec_prepared_v2(take(stmt));
	return true;
}

/**
 * wallet_stmt2output - Extract data from stmt and fill an UTXO
 */
static struct utxo *wallet_stmt2output(const tal_t *ctx, struct db_stmt *stmt)
{
	struct utxo *utxo = tal(ctx, struct utxo);
	u32 *blockheight, *spendheight;
	db_col_txid(stmt, "prev_out_tx", &utxo->outpoint.txid);
	utxo->outpoint.n = db_col_int(stmt, "prev_out_index");
	utxo->amount = db_col_amount_sat(stmt, "value");
	utxo->is_p2sh = db_col_int(stmt, "type") == p2sh_wpkh;
	utxo->status = db_col_int(stmt, "status");
	utxo->keyindex = db_col_int(stmt, "keyindex");

	utxo->is_in_coinbase = db_col_int(stmt, "is_in_coinbase") == 1;

	if (!db_col_is_null(stmt, "channel_id")) {
		utxo->close_info = tal(utxo, struct unilateral_close_info);
		utxo->close_info->channel_id = db_col_u64(stmt, "channel_id");
		db_col_node_id(stmt, "peer_id", &utxo->close_info->peer_id);
		utxo->close_info->commitment_point
			= db_col_optional(utxo->close_info, stmt,
					  "commitment_point",
					  pubkey);
		utxo->close_info->option_anchors
			= db_col_int(stmt, "option_anchor_outputs");
		utxo->close_info->csv = db_col_int(stmt, "csv_lock");
	} else {
		utxo->close_info = NULL;
		db_col_ignore(stmt, "peer_id");
		db_col_ignore(stmt, "commitment_point");
		db_col_ignore(stmt, "option_anchor_outputs");
		db_col_ignore(stmt, "csv_lock");
	}

	utxo->scriptPubkey = db_col_arr(utxo, stmt, "scriptpubkey", u8);

	utxo->blockheight = NULL;
	utxo->spendheight = NULL;

	if (!db_col_is_null(stmt, "confirmation_height")) {
		blockheight = tal(utxo, u32);
		*blockheight = db_col_int(stmt, "confirmation_height");
		utxo->blockheight = blockheight;
	}

	if (!db_col_is_null(stmt, "spend_height")) {
		spendheight = tal(utxo, u32);
		*spendheight = db_col_int(stmt, "spend_height");
		utxo->spendheight = spendheight;
	}

	/* This column can be null if 0.9.1 db or below. */
	utxo->reserved_til = db_col_int_or_default(stmt, "reserved_til", 0);

	return utxo;
}

bool wallet_update_output_status(struct wallet *w,
				 const struct bitcoin_outpoint *outpoint,
				 enum output_status oldstatus,
				 enum output_status newstatus)
{
	struct db_stmt *stmt;
	size_t changes;

	/* FIXME(vincenzopalazzo): There are different nasty case at this point that are
	 *
	 * - moving from OUTPUT_STATE_SPENT -> OUTPUT_STATE_CONFIRMENT required
	 * to set the spendheight to null
	 * - moving from OUTPUT_STATE_CONFIRMED -> OUTPUT_STATE_SPENT required
	 * to set the spendheight.
	 *
	 * in both bases the following code do not do that. */
	if (oldstatus != OUTPUT_STATE_ANY) {
		stmt = db_prepare_v2(
		    w->db, SQL("UPDATE outputs SET status=? WHERE status=? AND "
			       "prev_out_tx=? AND prev_out_index=?"));
		db_bind_int(stmt, output_status_in_db(newstatus));
		db_bind_int(stmt, output_status_in_db(oldstatus));
		db_bind_txid(stmt, &outpoint->txid);
		db_bind_int(stmt, outpoint->n);
	} else {
		stmt = db_prepare_v2(w->db,
				     SQL("UPDATE outputs SET status=? WHERE "
					 "prev_out_tx=? AND prev_out_index=?"));
		db_bind_int(stmt, output_status_in_db(newstatus));
		db_bind_txid(stmt, &outpoint->txid);
		db_bind_int(stmt, outpoint->n);
	}
	db_exec_prepared_v2(stmt);
	changes = db_count_changes(stmt);
	tal_free(stmt);
	return changes > 0;
}

bool wallet_force_update_output_status(struct wallet *w,
				       const struct bitcoin_txid *prev_txid,
				       const u64 *prev_vout,
				       enum output_status status,
				       const u64 *spentheight)
{
	struct db_stmt *stmt;
	size_t changes;

	stmt = db_prepare_v2(
		w->db, SQL("UPDATE outputs SET status=?, spend_height=? WHERE "
			   "prev_out_tx=? AND prev_out_index=?"));
	db_bind_int(stmt, output_status_in_db(status));
	if (!spentheight)
		db_bind_null(stmt);
	else
		db_bind_u64(stmt, *spentheight);
	db_bind_txid(stmt, prev_txid);
	db_bind_int(stmt, *prev_vout);

	db_exec_prepared_v2(stmt);
	changes = db_count_changes(stmt);
	tal_free(stmt);
	return changes > 0;
}

static struct utxo **gather_utxos(const tal_t *ctx, struct db_stmt *stmt STEALS)
{
	struct utxo **results;

	db_query_prepared(stmt);
	results = tal_arr(ctx, struct utxo *, 0);
	while (db_step(stmt)) {
		struct utxo *u = wallet_stmt2output(results, stmt);
		tal_arr_expand(&results, u);
	}
	tal_free(stmt);

	return results;
}

struct utxo **wallet_get_all_utxos(const tal_t *ctx, struct wallet *w)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  prev_out_tx"
					", prev_out_index"
					", value"
					", type"
					", status"
					", keyindex"
					", channel_id"
					", peer_id"
					", commitment_point"
					", option_anchor_outputs"
					", confirmation_height"
					", spend_height"
					", scriptpubkey "
					", reserved_til "
					", csv_lock "
					", is_in_coinbase "
					"FROM outputs"));
	return gather_utxos(ctx, stmt);
}

/**
 * wallet_get_unspent_utxos - Return reserved and unreserved UTXOs.
 *
 * Returns a `tal_arr` of `utxo` structs. Double indirection in order
 * to be able to steal individual elements onto something else.
 *
 * Use utxo_is_reserved() to test if it's reserved.
 */
struct utxo **wallet_get_unspent_utxos(const tal_t *ctx, struct wallet *w)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  prev_out_tx"
					", prev_out_index"
					", value"
					", type"
					", status"
					", keyindex"
					", channel_id"
					", peer_id"
					", commitment_point"
					", option_anchor_outputs"
					", confirmation_height"
					", spend_height"
					", scriptpubkey "
					", reserved_til "
					", csv_lock "
					", is_in_coinbase "
					"FROM outputs "
					"WHERE status != ?"));
	db_bind_int(stmt, output_status_in_db(OUTPUT_STATE_SPENT));
	return gather_utxos(ctx, stmt);
}

struct utxo **wallet_get_unconfirmed_closeinfo_utxos(const tal_t *ctx,
						     struct wallet *w)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  prev_out_tx"
					", prev_out_index"
					", value"
					", type"
					", status"
					", keyindex"
					", channel_id"
					", peer_id"
					", commitment_point"
					", option_anchor_outputs"
					", confirmation_height"
					", spend_height"
					", scriptpubkey"
					", reserved_til"
					", csv_lock"
					", is_in_coinbase"
					" FROM outputs"
					" WHERE channel_id IS NOT NULL AND "
					"confirmation_height IS NULL"));

	return gather_utxos(ctx, stmt);
}

struct utxo *wallet_utxo_get(const tal_t *ctx, struct wallet *w,
			     const struct bitcoin_outpoint *outpoint)
{
	struct db_stmt *stmt;
	struct utxo *utxo;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  prev_out_tx"
					", prev_out_index"
					", value"
					", type"
					", status"
					", keyindex"
					", channel_id"
					", peer_id"
					", commitment_point"
					", option_anchor_outputs"
					", confirmation_height"
					", spend_height"
					", scriptpubkey"
					", reserved_til"
					", csv_lock"
					", is_in_coinbase"
					" FROM outputs"
					" WHERE prev_out_tx = ?"
					" AND prev_out_index = ?"));

	db_bind_txid(stmt, &outpoint->txid);
	db_bind_int(stmt, outpoint->n);

	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	utxo = wallet_stmt2output(ctx, stmt);
	tal_free(stmt);

	return utxo;
}

/* Gather enough utxos to meet feerate, otherwise all we can. */
struct utxo **wallet_utxo_boost(const tal_t *ctx,
				struct wallet *w,
				u32 blockheight,
				struct amount_sat fee_amount,
				u32 feerate_target,
				size_t *weight)
{
	struct utxo **all_utxos = wallet_get_unspent_utxos(tmpctx, w);
	struct utxo **utxos = tal_arr(ctx, struct utxo *, 0);
	u32 feerate;

	/* Select in random order */
	tal_arr_randomize(all_utxos, struct utxo *);

	/* Can't overflow, it's from our tx! */
	if (!amount_feerate(&feerate, fee_amount, *weight))
		abort();

	for (size_t i = 0; i < tal_count(all_utxos); i++) {
		u32 new_feerate;
		size_t new_weight;
		struct amount_sat new_fee_amount;
		/* Convenience var */
		struct utxo *utxo = all_utxos[i];

		/* Are we already happy? */
		if (feerate >= feerate_target)
			break;

		/* Don't add reserved ones */
		if (utxo_is_reserved(utxo, blockheight))
			continue;

		/* UTXOs must be sane amounts */
		if (!amount_sat_add(&new_fee_amount,
				    fee_amount, utxo->amount))
			abort();

		new_weight = *weight + utxo_spend_weight(utxo, 0);
		if (!amount_feerate(&new_feerate, new_fee_amount, new_weight))
			abort();

		/* Don't add uneconomic ones! */
		if (new_feerate < feerate)
			continue;

		feerate = new_feerate;
		*weight = new_weight;
		fee_amount = new_fee_amount;
		tal_arr_expand(&utxos, tal_steal(utxos, utxo));
	}

	return utxos;
}

static void db_set_utxo(struct db *db, const struct utxo *utxo)
{
	struct db_stmt *stmt;

	if (utxo->status == OUTPUT_STATE_RESERVED)
		assert(utxo->reserved_til);
	else
		assert(!utxo->reserved_til);

	stmt = db_prepare_v2(
		db, SQL("UPDATE outputs SET status=?, reserved_til=? "
			"WHERE prev_out_tx=? AND prev_out_index=?"));
	db_bind_int(stmt, output_status_in_db(utxo->status));
	db_bind_int(stmt, utxo->reserved_til);
	db_bind_txid(stmt, &utxo->outpoint.txid);
	db_bind_int(stmt, utxo->outpoint.n);
	db_exec_prepared_v2(take(stmt));
}

bool wallet_reserve_utxo(struct wallet *w, struct utxo *utxo,
			 u32 current_height,
			 u32 reserve)
{
	switch (utxo->status) {
	case OUTPUT_STATE_SPENT:
		return false;
	case OUTPUT_STATE_AVAILABLE:
	case OUTPUT_STATE_RESERVED:
		break;
	case OUTPUT_STATE_ANY:
		abort();
	}

	/* We simple increase existing reservations, which DTRT if we unreserve */
	if (utxo->reserved_til >= current_height)
		utxo->reserved_til += reserve;
	else
		utxo->reserved_til = current_height + reserve;

	utxo->status = OUTPUT_STATE_RESERVED;

	db_set_utxo(w->db, utxo);

	return true;
}

void wallet_unreserve_utxo(struct wallet *w, struct utxo *utxo,
			   u32 current_height,
			   u32 unreserve)
{
	if (utxo->status != OUTPUT_STATE_RESERVED)
		fatal("UTXO %s is not reserved",
		      fmt_bitcoin_outpoint(tmpctx,
				     &utxo->outpoint));

	if (utxo->reserved_til <= current_height + unreserve) {
		utxo->status = OUTPUT_STATE_AVAILABLE;
		utxo->reserved_til = 0;
	} else
		utxo->reserved_til -= unreserve;

	db_set_utxo(w->db, utxo);
}

static bool excluded(const struct utxo **excludes,
		     const struct utxo *utxo)
{
	for (size_t i = 0; i < tal_count(excludes); i++) {
		if (bitcoin_outpoint_eq(&excludes[i]->outpoint, &utxo->outpoint))
			return true;
	}
	return false;
}

static bool deep_enough(u32 maxheight, const struct utxo *utxo,
			u32 current_blockheight)
{
	if (utxo->close_info
	    && utxo->close_info->option_anchors) {
		/* BOLT #3:
		 * If `option_anchors` applies to the commitment transaction, the
		 * `to_remote` output is encumbered by a one block csv lock.
		 */
		if (!utxo->blockheight)
			return false;

		u32 csv_free = *utxo->blockheight + utxo->close_info->csv - 1;
		assert(csv_free >= *utxo->blockheight);

		if (csv_free > current_blockheight)
			return false;
	}

	bool immature = utxo_is_immature(utxo, current_blockheight);
	if (immature)
		return false;

	/* If we require confirmations check that we have a
	 * confirmation height and that it is below the required
	 * maxheight (current_height - minconf) */
	if (maxheight == 0)
		return true;
	if (!utxo->blockheight)
		return false;
	return *utxo->blockheight <= maxheight;
}

/* FIXME: Make this wallet_find_utxos, and branch and bound and I've
 * left that to @niftynei to do, who actually read the paper! */
struct utxo *wallet_find_utxo(const tal_t *ctx, struct wallet *w,
			      unsigned current_blockheight,
			      struct amount_sat *amount_hint,
			      unsigned feerate_per_kw,
			      u32 maxheight,
			      bool nonwrapped,
			      const struct utxo **excludes)
{
	struct db_stmt *stmt;
	struct utxo *utxo;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  prev_out_tx"
					", prev_out_index"
					", value"
					", type"
					", status"
					", keyindex"
					", channel_id"
					", peer_id"
					", commitment_point"
					", option_anchor_outputs"
					", confirmation_height"
					", spend_height"
					", scriptpubkey "
					", reserved_til"
					", csv_lock"
					", is_in_coinbase"
					" FROM outputs"
					" WHERE status = ?"
					" OR (status = ? AND reserved_til <= ?)"
					"ORDER BY RANDOM();"));
	db_bind_int(stmt, output_status_in_db(OUTPUT_STATE_AVAILABLE));
	db_bind_int(stmt, output_status_in_db(OUTPUT_STATE_RESERVED));
	db_bind_u64(stmt, current_blockheight);

	/* FIXME: Use feerate + estimate of input cost to establish
	 * range for amount_hint */

	db_query_prepared(stmt);

	utxo = NULL;
	while (!utxo && db_step(stmt)) {
		utxo = wallet_stmt2output(ctx, stmt);
		if (excluded(excludes, utxo)
		    || (nonwrapped && utxo->is_p2sh)
		    || !deep_enough(maxheight, utxo, current_blockheight))
			utxo = tal_free(utxo);

	}
	tal_free(stmt);
	return utxo;
}


bool wallet_has_funds(struct wallet *w,
		      const struct utxo **excludes,
		      u32 current_blockheight,
		      struct amount_sat *needed)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  prev_out_tx"
					", prev_out_index"
					", value"
					", type"
					", status"
					", keyindex"
					", channel_id"
					", peer_id"
					", commitment_point"
					", option_anchor_outputs"
					", confirmation_height"
					", spend_height"
					", scriptpubkey "
					", reserved_til"
					", csv_lock"
					", is_in_coinbase"
					" FROM outputs"
					" WHERE status = ?"
					" OR (status = ? AND reserved_til <= ?)"));
	db_bind_int(stmt, output_status_in_db(OUTPUT_STATE_AVAILABLE));
	db_bind_int(stmt, output_status_in_db(OUTPUT_STATE_RESERVED));
	db_bind_u64(stmt, current_blockheight);

	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct utxo *utxo = wallet_stmt2output(tmpctx, stmt);

		if (excluded(excludes, utxo)
 		    || !deep_enough(-1U, utxo, current_blockheight)) {
			continue;
		}

		/* If we've found enough, answer is yes. */
		if (!amount_sat_sub(needed, *needed, utxo->amount)) {
			*needed = AMOUNT_SAT(0);
			tal_free(stmt);
			return true;
		}
	}

	/* Insufficient funds! */
	tal_free(stmt);
	return false;
}

bool wallet_add_onchaind_utxo(struct wallet *w,
			      const struct bitcoin_outpoint *outpoint,
			      const u8 *scriptpubkey,
			      u32 blockheight,
			      struct amount_sat amount,
			      const struct channel *channel,
			      /* NULL if option_static_remotekey */
			      const struct pubkey *commitment_point,
			      u32 csv_lock)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT * from outputs WHERE "
					"prev_out_tx=? AND prev_out_index=?"));
	db_bind_txid(stmt, &outpoint->txid);
	db_bind_int(stmt, outpoint->n);
	db_query_prepared(stmt);

	/* If we get a result, that means a clash. */
	if (db_step(stmt)) {
		db_col_ignore(stmt, "*");
		tal_free(stmt);
		return false;
	}
	tal_free(stmt);

	stmt = db_prepare_v2(
	    w->db, SQL("INSERT INTO outputs ("
		       "  prev_out_tx"
		       ", prev_out_index"
		       ", value"
		       ", type"
		       ", status"
		       ", keyindex"
		       ", channel_id"
		       ", peer_id"
		       ", commitment_point"
		       ", option_anchor_outputs"
		       ", confirmation_height"
		       ", spend_height"
		       ", scriptpubkey"
		       ", csv_lock"
		       ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));
	db_bind_txid(stmt, &outpoint->txid);
	db_bind_int(stmt, outpoint->n);
	db_bind_amount_sat(stmt, &amount);
	db_bind_int(stmt, wallet_output_type_in_db(p2wpkh));
	db_bind_int(stmt, OUTPUT_STATE_AVAILABLE);
	db_bind_int(stmt, 0);
	db_bind_u64(stmt, channel->dbid);
	db_bind_node_id(stmt, &channel->peer->id);
	if (commitment_point)
		db_bind_pubkey(stmt, commitment_point);
	else
		db_bind_null(stmt);

	db_bind_int(stmt,
		    channel_type_has_anchors(channel->type));
	db_bind_int(stmt, blockheight);

	/* spendheight */
	db_bind_null(stmt);
	db_bind_blob(stmt, scriptpubkey, tal_bytelen(scriptpubkey));

	db_bind_int(stmt, csv_lock);

	db_exec_prepared_v2(take(stmt));
	return true;
}

bool wallet_can_spend(struct wallet *w, const u8 *script,
		      u32 *index)
{
	struct ext_key ext;
	u64 bip32_max_index;
	size_t script_len = tal_bytelen(script);
	u32 i;
	bool output_is_p2sh;

	/* If not one of these, can't be for us. */
	if (is_p2sh(script, script_len, NULL))
		output_is_p2sh = true;
	else if (is_p2wpkh(script, script_len, NULL))
		output_is_p2sh = false;
	else if (is_p2tr(script, script_len, NULL))
		output_is_p2sh = false;
	else
		return false;

	bip32_max_index = db_get_intvar(w->db, "bip32_max_index", 0);
	for (i = 0; i <= bip32_max_index + w->keyscan_gap; i++) {
		const u32 flags = BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH;
		u8 *s;

		if (bip32_key_from_parent(w->ld->bip32_base, i,
					  flags, &ext) != WALLY_OK) {
			abort();
		}
		s = scriptpubkey_p2wpkh_derkey(w, ext.pub_key);
		if (output_is_p2sh) {
			u8 *p2sh = scriptpubkey_p2sh(w, s);
			tal_free(s);
			s = p2sh;
		}
		if (!scripteq(s, script)) {
			/* Try taproot output now */
			tal_free(s);
			s = scriptpubkey_p2tr_derkey(w, ext.pub_key);
			if (!scripteq(s, script))
				s = tal_free(s);
		}
		tal_free(s);
		if (s) {
			/* If we found a used key in the keyscan_gap we should
			 * remember that. */
			if (i > bip32_max_index)
				db_set_intvar(w->db, "bip32_max_index", i);
			*index = i;
			return true;
		}
	}
	return false;
}

s64 wallet_get_newindex(struct lightningd *ld)
{
	u64 newidx = db_get_intvar(ld->wallet->db, "bip32_max_index", 0) + 1;

	if (newidx == BIP32_INITIAL_HARDENED_CHILD)
		return -1;

	db_set_intvar(ld->wallet->db, "bip32_max_index", newidx);
	return newidx;
}

static void wallet_shachain_init(struct wallet *wallet,
				 struct wallet_shachain *chain)
{
	struct db_stmt *stmt;

	assert(chain->id == 0);

	/* Create shachain */
	shachain_init(&chain->chain);
	stmt = db_prepare_v2(
	    wallet->db,
	    SQL("INSERT INTO shachains (min_index, num_valid) VALUES (?, 0);"));
	db_bind_u64(stmt, chain->chain.min_index);
	db_exec_prepared_v2(stmt);

	chain->id = db_last_insert_id_v2(stmt);
	tal_free(stmt);
}

/* TODO(cdecker) Stolen from shachain, move to some appropriate location */
static unsigned int count_trailing_zeroes(uint64_t index)
{
#if HAVE_BUILTIN_CTZLL
	return index ? (unsigned int)__builtin_ctzll(index) : SHACHAIN_BITS;
#else
	unsigned int i;

	for (i = 0; i < SHACHAIN_BITS; i++) {
		if (index & (1ULL << i))
			break;
	}
	return i;
#endif
}

bool wallet_shachain_add_hash(struct wallet *wallet,
			      struct wallet_shachain *chain,
			      uint64_t index,
			      const struct secret *hash)
{
	struct db_stmt *stmt;
	u32 pos = count_trailing_zeroes(index);
	struct sha256 s;
	bool updated;

	BUILD_ASSERT(sizeof(s) == sizeof(*hash));
	memcpy(&s, hash, sizeof(s));

	assert(index < SQLITE_MAX_UINT);
	if (!shachain_add_hash(&chain->chain, index, &s)) {
		return false;
	}

	stmt = db_prepare_v2(
	    wallet->db,
	    SQL("UPDATE shachains SET num_valid=?, min_index=? WHERE id=?"));
	db_bind_int(stmt, chain->chain.num_valid);
	db_bind_u64(stmt, index);
	db_bind_u64(stmt, chain->id);
	db_exec_prepared_v2(take(stmt));

	stmt = db_prepare_v2(wallet->db,
			     SQL("UPDATE shachain_known SET idx=?, hash=? "
				 "WHERE shachain_id=? AND pos=?"));
	db_bind_u64(stmt, index);
	db_bind_secret(stmt, hash);
	db_bind_u64(stmt, chain->id);
	db_bind_int(stmt, pos);
	db_exec_prepared_v2(stmt);
	updated = db_count_changes(stmt) == 1;
	tal_free(stmt);

	if (!updated) {
		stmt = db_prepare_v2(
		    wallet->db, SQL("INSERT INTO shachain_known (shachain_id, "
				    "pos, idx, hash) VALUES (?, ?, ?, ?);"));
		db_bind_u64(stmt, chain->id);
		db_bind_int(stmt, pos);
		db_bind_u64(stmt, index);
		db_bind_secret(stmt, hash);
		db_exec_prepared_v2(take(stmt));
	}

	return true;
}

static bool wallet_shachain_load(struct wallet *wallet, u64 id,
				 struct wallet_shachain *chain)
{
	struct db_stmt *stmt;
	chain->id = id;
	shachain_init(&chain->chain);

	/* Load shachain metadata */
	stmt = db_prepare_v2(
	    wallet->db,
	    SQL("SELECT min_index, num_valid FROM shachains WHERE id=?"));
	db_bind_u64(stmt, id);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return false;
	}

	chain->chain.min_index = db_col_u64(stmt, "min_index");
	chain->chain.num_valid = db_col_u64(stmt, "num_valid");
	tal_free(stmt);

	/* Load shachain known entries */
	stmt = db_prepare_v2(wallet->db,
			     SQL("SELECT idx, hash, pos FROM shachain_known "
				 "WHERE shachain_id=?"));
	db_bind_u64(stmt, id);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		int pos = db_col_int(stmt, "pos");
		chain->chain.known[pos].index = db_col_u64(stmt, "idx");
		db_col_sha256(stmt, "hash", &chain->chain.known[pos].hash);
	}
	tal_free(stmt);
	return true;
}

static struct peer *wallet_peer_load(struct wallet *w, const u64 dbid)
{
	const char *addrstr, *err;
	struct peer *peer = NULL;
	struct node_id id;
	struct wireaddr_internal addr;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(
	    w->db, SQL("SELECT id, node_id, address, feature_bits FROM peers WHERE id=?;"));
	db_bind_u64(stmt, dbid);
	db_query_prepared(stmt);

	if (!db_step(stmt))
		goto done;

	if (db_col_is_null(stmt, "node_id")) {
		db_col_ignore(stmt, "address");
		db_col_ignore(stmt, "id");
		db_col_ignore(stmt, "feature_bits");
		goto done;
	}

	db_col_node_id(stmt, "node_id", &id);

	/* This can happen for peers last seen on Torv2! */
	addrstr = db_col_strdup(tmpctx, stmt, "address");
	err = parse_wireaddr_internal(tmpctx, addrstr, chainparams_get_ln_port(chainparams), true, &addr);
	if (err) {
		log_unusual(w->log, "Unparsable peer address %s (%s): replacing",
			    addrstr, err);
		err = parse_wireaddr_internal(tmpctx, "127.0.0.1:1", chainparams_get_ln_port(chainparams),
					      false, &addr);
		assert(!err);
	}

	/* FIXME: save incoming in db! */
	peer = new_peer(w->ld, db_col_u64(stmt, "id"), &id, &addr, db_col_arr(stmt, stmt, "feature_bits", u8), false);

done:
	tal_free(stmt);
	return peer;
}

static struct bitcoin_signature *
wallet_htlc_sigs_load(const tal_t *ctx, struct wallet *w, u64 channelid,
		      bool option_anchors)
{
	struct db_stmt *stmt;
	struct bitcoin_signature *htlc_sigs = tal_arr(ctx, struct bitcoin_signature, 0);

	stmt = db_prepare_v2(
	    w->db, SQL("SELECT signature FROM htlc_sigs WHERE channelid = ?"
	    	       " AND inflight_tx_id is NULL"));
	db_bind_u64(stmt, channelid);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct bitcoin_signature sig;
		db_col_signature(stmt, "signature", &sig.s);
		/* BOLT #3:
		 * ## HTLC-Timeout and HTLC-Success Transactions
		 *...
		 * * if `option_anchors` applies to this commitment
		 *   transaction, `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` is
		 *   used as described in [BOLT #5]
		 */
		if (option_anchors)
			sig.sighash_type = SIGHASH_SINGLE|SIGHASH_ANYONECANPAY;
		else
			sig.sighash_type = SIGHASH_ALL;
		tal_arr_expand(&htlc_sigs, sig);
	}
	tal_free(stmt);

	log_debug(w->log, "Loaded %zu HTLC signatures from DB",
		  tal_count(htlc_sigs));
	return htlc_sigs;
}

bool wallet_remote_ann_sigs_load(struct wallet *w,
				 const struct channel *chan,
				 secp256k1_ecdsa_signature *remote_ann_node_sig,
				 secp256k1_ecdsa_signature *remote_ann_bitcoin_sig)
{
	struct db_stmt *stmt;
	bool res;
	stmt = db_prepare_v2(
	    w->db, SQL("SELECT remote_ann_node_sig, remote_ann_bitcoin_sig"
		       " FROM channels WHERE id = ?"));
	db_bind_u64(stmt, chan->dbid);
	db_query_prepared(stmt);

	res = db_step(stmt);

	/* This must succeed, since we know the channel exists */
	assert(res);

	/* if only one sig exists, forget the sig and hope peer send new ones*/
	if (db_col_is_null(stmt, "remote_ann_node_sig")
	    || db_col_is_null(stmt, "remote_ann_bitcoin_sig")) {
		db_col_ignore(stmt, "remote_ann_bitcoin_sig");
		tal_free(stmt);
		return false;
	}

	if (!db_col_signature(stmt, "remote_ann_node_sig", remote_ann_node_sig))
		db_fatal(w->db, "Failed to decode remote_ann_node_sig for id %"PRIu64, chan->dbid);

	if (!db_col_signature(stmt, "remote_ann_bitcoin_sig", remote_ann_bitcoin_sig))
		db_fatal(w->db, "Failed to decode remote_ann_bitcoin_sig for id %"PRIu64, chan->dbid);

	tal_free(stmt);
	return true;
}

void wallet_remote_ann_sigs_clear(struct wallet *w, const struct channel *chan)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db,
			     SQL("UPDATE channels"
				 " SET remote_ann_node_sig=?, remote_ann_bitcoin_sig=?"
				 " WHERE id = ?"));
	db_bind_null(stmt);
	db_bind_null(stmt);
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));
}

static struct fee_states *wallet_channel_fee_states_load(struct wallet *w,
							 const u64 id,
							 enum side opener)
{
	struct fee_states *fee_states;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT hstate, feerate_per_kw FROM channel_feerates WHERE channel_id = ?"));
	db_bind_u64(stmt, id);
	db_query_prepared(stmt);

	/* Start with blank slate. */
	fee_states = new_fee_states(w, opener, NULL);
	while (db_step(stmt)) {
		enum htlc_state hstate = htlc_state_in_db(db_col_int(stmt, "hstate"));
		u32 feerate = db_col_int(stmt, "feerate_per_kw");

		if (fee_states->feerate[hstate] != NULL) {
			log_broken(w->log,
				   "duplicate channel_feerates for %s id %"PRIu64,
				   htlc_state_name(hstate), id);
			fee_states = tal_free(fee_states);
			break;
		}
		fee_states->feerate[hstate] = tal_dup(fee_states, u32, &feerate);
	}
	tal_free(stmt);

	if (fee_states && !fee_states_valid(fee_states, opener)) {
		log_broken(w->log,
			   "invalid channel_feerates for id %"PRIu64, id);
		fee_states = tal_free(fee_states);
	}
	return fee_states;
}

static struct height_states *wallet_channel_height_states_load(struct wallet *w,
							       const u64 id,
							       enum side opener)
{
	struct height_states *states;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT hstate, blockheight FROM channel_blockheights WHERE channel_id = ?"));
	db_bind_u64(stmt, id);
	db_query_prepared(stmt);

	/* Start with blank slate. */
	states = new_height_states(w, opener, NULL);
	while (db_step(stmt)) {
		enum htlc_state hstate = htlc_state_in_db(db_col_int(stmt, "hstate"));
		u32 blockheight = db_col_int(stmt, "blockheight");

		if (states->height[hstate] != NULL) {
			log_broken(w->log,
				   "duplicate channel_blockheights for %s id %"PRIu64,
				   htlc_state_name(hstate), id);
			states = tal_free(states);
			break;
		}
		states->height[hstate] = tal_dup(states, u32, &blockheight);
	}
	tal_free(stmt);

	if (states && !height_states_valid(states, opener)) {
		log_broken(w->log,
			   "invalid channel_blockheight for id %"PRIu64, id);
		states = tal_free(states);
	}
	return states;
}

void wallet_inflight_add(struct wallet *w, struct channel_inflight *inflight)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO channel_funding_inflights ("
				 "  channel_id"
				 ", funding_tx_id"
				 ", funding_tx_outnum"
				 ", funding_feerate"
				 ", funding_satoshi"
				 ", our_funding_satoshi"
				 ", funding_psbt"
				 ", funding_tx_remote_sigs_received"
				 ", last_tx"
				 ", last_sig"
				 ", lease_commit_sig"
				 ", lease_chan_max_msat"
				 ", lease_chan_max_ppt"
				 ", lease_expiry"
				 ", lease_blockheight_start"
				 ", lease_fee"
				 ", lease_satoshi"
				 ", splice_amnt"
				 ", i_am_initiator"
				 ", force_sign_first"
				 ") VALUES ("
				 "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, inflight->channel->dbid);
	db_bind_txid(stmt, &inflight->funding->outpoint.txid);
	db_bind_int(stmt, inflight->funding->outpoint.n);
	db_bind_int(stmt, inflight->funding->feerate);
	db_bind_amount_sat(stmt, &inflight->funding->total_funds);
	db_bind_amount_sat(stmt, &inflight->funding->our_funds);
	db_bind_psbt(stmt, inflight->funding_psbt);
	db_bind_int(stmt, inflight->remote_tx_sigs ? 1 : 0);
	if (inflight->last_tx) {
		db_bind_psbt(stmt, inflight->last_tx->psbt);
		db_bind_signature(stmt, &inflight->last_sig.s);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
	}

	if (inflight->lease_expiry != 0) {
		db_bind_signature(stmt, inflight->lease_commit_sig);
		db_bind_int(stmt, inflight->lease_chan_max_msat);
		db_bind_int(stmt, inflight->lease_chan_max_ppt);
		db_bind_int(stmt, inflight->lease_expiry);
		db_bind_int(stmt, inflight->lease_blockheight_start);
		db_bind_amount_msat(stmt, &inflight->lease_fee);
		db_bind_amount_sat(stmt, &inflight->lease_amt);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_int(stmt, 0);
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_int(stmt, 0);
	}

	db_bind_s64(stmt, inflight->funding->splice_amnt);
	db_bind_int(stmt, inflight->i_am_initiator);
	db_bind_int(stmt, inflight->force_sign_first);

	db_exec_prepared_v2(stmt);
	assert(!stmt->error);
	tal_free(stmt);
}

void wallet_inflight_del(struct wallet *w, const struct channel *chan,
			 const struct channel_inflight *inflight)
{
	struct db_stmt *stmt;

	/* Remove inflight from the channel */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM channel_funding_inflights"
					" WHERE channel_id = ?"
					"   AND funding_tx_id = ?"
					"   AND funding_tx_outnum = ?"));
	db_bind_u64(stmt, chan->dbid);
	db_bind_txid(stmt, &inflight->funding->outpoint.txid);
	db_bind_int(stmt, inflight->funding->outpoint.n);
	db_exec_prepared_v2(take(stmt));
}

void wallet_inflight_save(struct wallet *w,
			  struct channel_inflight *inflight)
{
	struct db_stmt *stmt;
	/* The *only* thing you can update on an
	 * inflight is the funding PSBT (to add sigs)
	 * and the last_tx/last_sig if this is for a splice */
	stmt = db_prepare_v2(w->db,
			     SQL("UPDATE channel_funding_inflights SET"
				 "  funding_psbt=?" // 0
				 ", funding_tx_remote_sigs_received=?" // 1
				 ", last_tx=?" // 2
				 ", last_sig=?" // 3
				 " WHERE"
				 "  channel_id=?" // 4
				 " AND funding_tx_id=?" // 5
				 " AND funding_tx_outnum=?")); // 6
	db_bind_psbt(stmt, inflight->funding_psbt);
	db_bind_int(stmt, inflight->remote_tx_sigs);
	if (inflight->last_tx) {
		db_bind_psbt(stmt, inflight->last_tx->psbt);
		db_bind_signature(stmt, &inflight->last_sig.s);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
	}
	db_bind_u64(stmt, inflight->channel->dbid);
	db_bind_txid(stmt, &inflight->funding->outpoint.txid);
	db_bind_int(stmt, inflight->funding->outpoint.n);

	db_exec_prepared_v2(take(stmt));
}

void wallet_channel_clear_inflights(struct wallet *w,
				    struct channel *chan)
{
	struct db_stmt *stmt;
	struct channel_inflight *inflight;

	/* Remove all the inflights for the channel */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM channel_funding_inflights"
					" WHERE channel_id = ?"));
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));

	/* Empty out the list too */
	while ((inflight = list_tail(&chan->inflights,
				     struct channel_inflight, list)))
		tal_free(inflight);
}

static struct channel_inflight *
wallet_stmt2inflight(struct wallet *w, struct db_stmt *stmt,
		     struct channel *chan)
{
	struct amount_sat funding_sat, our_funding_sat;
	struct amount_msat lease_fee;
	struct bitcoin_outpoint funding;
	struct bitcoin_signature last_sig;
	struct bitcoin_tx *last_tx;
	struct channel_inflight *inflight;
	s64 splice_amnt;
	bool i_am_initiator, force_sign_first;

	secp256k1_ecdsa_signature *lease_commit_sig;
	u32 lease_blockheight_start;
	u64 lease_chan_max_msat;
	u16 lease_chan_max_ppt;
	struct amount_sat lease_amt;

	db_col_txid(stmt, "funding_tx_id", &funding.txid);
	funding.n = db_col_int(stmt, "funding_tx_outnum"),
	funding_sat = db_col_amount_sat(stmt, "funding_satoshi");
	our_funding_sat = db_col_amount_sat(stmt, "our_funding_satoshi");

	if (!db_col_is_null(stmt, "lease_commit_sig")) {
		lease_commit_sig = tal(tmpctx, secp256k1_ecdsa_signature);
		db_col_signature(stmt, "lease_commit_sig", lease_commit_sig);
		lease_chan_max_msat = db_col_u64(stmt, "lease_chan_max_msat");
		lease_chan_max_ppt = db_col_int(stmt, "lease_chan_max_ppt");
		lease_blockheight_start = db_col_int(stmt, "lease_blockheight_start");
		lease_fee = db_col_amount_msat(stmt, "lease_fee");
		lease_amt = db_col_amount_sat(stmt, "lease_satoshi");
	} else {
		lease_commit_sig = NULL;
		lease_chan_max_msat = 0;
		lease_chan_max_ppt = 0;
		lease_blockheight_start = 0;
		lease_fee = AMOUNT_MSAT(0);
		lease_amt = AMOUNT_SAT(0);

		db_col_ignore(stmt, "lease_chan_max_msat");
		db_col_ignore(stmt, "lease_chan_max_ppt");
		db_col_ignore(stmt, "lease_blockheight_start");
		db_col_ignore(stmt, "lease_fee");
		db_col_ignore(stmt, "lease_satoshi");
	}

	splice_amnt = db_col_s64(stmt, "splice_amnt");
	i_am_initiator = db_col_int(stmt, "i_am_initiator");
	force_sign_first = db_col_int(stmt, "force_sign_first");

	inflight = new_inflight(chan, &funding,
				db_col_int(stmt, "funding_feerate"),
				funding_sat,
				our_funding_sat,
				db_col_psbt(tmpctx, stmt, "funding_psbt"),
				db_col_int(stmt, "lease_expiry"),
				lease_commit_sig,
				lease_chan_max_msat,
				lease_chan_max_ppt,
				lease_blockheight_start,
				lease_fee,
				lease_amt,
				splice_amnt,
				i_am_initiator,
				force_sign_first);

	/* last_tx is null for not yet committed
	 * channels + static channel backup recoveries */
	if (!db_col_is_null(stmt, "last_tx")) {
		last_tx = db_col_psbt_to_tx(tmpctx, stmt, "last_tx");
		if (!last_tx)
			db_fatal(w->db, "Failed to decode inflight psbt %s",
				 tal_hex(tmpctx, db_col_arr(tmpctx, stmt,
							    "last_tx", u8)));

		if (!db_col_signature(stmt, "last_sig", &last_sig.s))
			db_fatal(w->db, "Failed to decode inflight signature %s",
				 tal_hex(tmpctx, db_col_arr(tmpctx, stmt,
							    "last_sig", u8)));

		last_sig.sighash_type = SIGHASH_ALL;
		inflight_set_last_tx(inflight, last_tx, last_sig);
	} else
		db_col_ignore(stmt, "last_sig");

	/* Pull out the serialized tx-sigs-received-ness */
	inflight->remote_tx_sigs = db_col_int(stmt, "funding_tx_remote_sigs_received");
	return inflight;
}

static bool wallet_channel_load_inflights(struct wallet *w,
					  struct channel *chan)
{
	bool ok = true;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  funding_tx_id"
					", funding_tx_outnum"
					", funding_feerate"
					", funding_satoshi"
					", our_funding_satoshi"
					", funding_psbt"
					", last_tx"
					", last_sig"
					", funding_tx_remote_sigs_received"
					", lease_expiry"
					", lease_commit_sig"
					", lease_chan_max_msat"
					", lease_chan_max_ppt"
					", lease_blockheight_start"
					", lease_fee"
					", lease_satoshi"
					", splice_amnt"
					", i_am_initiator"
					", force_sign_first"
					" FROM channel_funding_inflights"
					" WHERE channel_id = ?"
					" ORDER BY funding_feerate"));

	db_bind_u64(stmt, chan->dbid);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct channel_inflight *inflight;
		inflight = wallet_stmt2inflight(w, stmt, chan);
		if (!inflight) {
			ok = false;
			break;
		}

	}
	tal_free(stmt);
	return ok;
}

static bool wallet_channel_config_load(struct wallet *w, const u64 id,
				       struct channel_config *cc)
{
	bool ok = true;
	const char *query = SQL(
	    "SELECT dust_limit_satoshis, max_htlc_value_in_flight_msat, "
	    "channel_reserve_satoshis, htlc_minimum_msat, to_self_delay, "
	    "max_accepted_htlcs, max_dust_htlc_exposure_msat"
	    " FROM channel_configs WHERE id= ? ;");
	struct db_stmt *stmt = db_prepare_v2(w->db, query);
	db_bind_u64(stmt, id);
	db_query_prepared(stmt);

	if (!db_step(stmt))
		return false;

	cc->id = id;
	cc->dust_limit = db_col_amount_sat(stmt, "dust_limit_satoshis");
	cc->max_htlc_value_in_flight = db_col_amount_msat(stmt, "max_htlc_value_in_flight_msat");
	cc->channel_reserve = db_col_amount_sat(stmt, "channel_reserve_satoshis");
	cc->htlc_minimum = db_col_amount_msat(stmt, "htlc_minimum_msat");
	cc->to_self_delay = db_col_int(stmt, "to_self_delay");
	cc->max_accepted_htlcs = db_col_int(stmt, "max_accepted_htlcs");
	cc->max_dust_htlc_exposure_msat = db_col_amount_msat(stmt, "max_dust_htlc_exposure_msat");
	tal_free(stmt);
	return ok;
}

static struct short_channel_id *db_col_optional_scid(const tal_t *ctx,
						     struct db_stmt *stmt,
						     const char *colname)
{
	struct short_channel_id *scid;

	if (db_col_is_null(stmt, colname))
		return NULL;

	scid = tal(tmpctx, struct short_channel_id);
	*scid = db_col_short_channel_id(stmt, colname);
	return scid;
}

/**
 * wallet_stmt2channel - Helper to populate a wallet_channel from a `db_stmt`
 */
static struct channel *wallet_stmt2channel(struct wallet *w, struct db_stmt *stmt)
{
	bool ok = true;
	struct channel_info channel_info;
	struct fee_states *fee_states;
	struct height_states *height_states;
	struct short_channel_id *scid, *alias[NUM_SIDES];
	struct channel_id cid;
	struct channel *chan;
	u64 peer_dbid;
	struct peer *peer;
	struct wallet_shachain wshachain;
	struct channel_config our_config;
	struct bitcoin_outpoint funding;
	struct bitcoin_outpoint *shutdown_wrong_funding;
	struct bitcoin_signature *last_sig;
	struct bitcoin_tx *last_tx;
	u8 *remote_shutdown_scriptpubkey;
	u8 *local_shutdown_scriptpubkey;
	struct changed_htlc *last_sent_commit;
	s64 final_key_idx, channel_config_id;
	struct basepoints local_basepoints;
	struct pubkey local_funding_pubkey;
	struct pubkey *future_per_commitment_point;
	struct amount_sat funding_sat, our_funding_sat;
	struct amount_msat push_msat, our_msat, msat_to_us_min, msat_to_us_max, htlc_minimum_msat, htlc_maximum_msat;
	struct channel_type *type;
	secp256k1_ecdsa_signature *lease_commit_sig;
	u32 lease_chan_max_msat;
	u16 lease_chan_max_ppt;
	bool ignore_fee_limits;
	struct peer_update *remote_update;

	peer_dbid = db_col_u64(stmt, "peer_id");
	peer = find_peer_by_dbid(w->ld, peer_dbid);
	if (!peer) {
		peer = wallet_peer_load(w, peer_dbid);
		if (!peer) {
			return NULL;
		}
	}

	scid = db_col_optional_scid(tmpctx, stmt, "scid");
	alias[LOCAL] = db_col_optional_scid(tmpctx, stmt, "alias_local");
	alias[REMOTE] = db_col_optional_scid(tmpctx, stmt, "alias_remote");

	ok &= wallet_shachain_load(w, db_col_u64(stmt, "shachain_remote_id"),
				   &wshachain);

	remote_shutdown_scriptpubkey = db_col_arr(tmpctx, stmt,
						  "shutdown_scriptpubkey_remote", u8);
	local_shutdown_scriptpubkey = db_col_arr(tmpctx, stmt,
						 "shutdown_scriptpubkey_local", u8);

	/* Do we have a last_sent_commit, if yes, populate */
	if (!db_col_is_null(stmt, "last_sent_commit")) {
		const u8 *cursor = db_col_blob(stmt, "last_sent_commit");
		size_t len = db_col_bytes(stmt, "last_sent_commit");
		size_t n = 0;
		last_sent_commit = tal_arr(tmpctx, struct changed_htlc, n);
		while (len) {
			tal_resize(&last_sent_commit, n+1);
			fromwire_changed_htlc(&cursor, &len,
					      &last_sent_commit[n++]);
		}
	} else
		last_sent_commit = NULL;

#ifdef COMPAT_V060
	if (!last_sent_commit && !db_col_is_null(stmt, "last_sent_commit_state")) {
		last_sent_commit = tal(tmpctx, struct changed_htlc);
		last_sent_commit->newstate = db_col_u64(stmt, "last_sent_commit_state");
		last_sent_commit->id = db_col_u64(stmt, "last_sent_commit_id");
	}
#endif
	db_col_ignore(stmt, "last_sent_commit_state");
	db_col_ignore(stmt, "last_sent_commit_id");

	future_per_commitment_point = db_col_optional(tmpctx, stmt,
						      "future_per_commitment_point",
						      pubkey);

	db_col_channel_id(stmt, "full_channel_id", &cid);
	channel_config_id = db_col_u64(stmt, "channel_config_local");
	ok &= wallet_channel_config_load(w, channel_config_id, &our_config);
	db_col_sha256d(stmt, "funding_tx_id", &funding.txid.shad);
	funding.n = db_col_int(stmt, "funding_tx_outnum"),

	/* Populate channel_info */
	db_col_pubkey(stmt, "fundingkey_remote", &channel_info.remote_fundingkey);
	db_col_pubkey(stmt, "revocation_basepoint_remote", &channel_info.theirbase.revocation);
	db_col_pubkey(stmt, "payment_basepoint_remote", &channel_info.theirbase.payment);
	db_col_pubkey(stmt, "htlc_basepoint_remote", &channel_info.theirbase.htlc);
	db_col_pubkey(stmt, "delayed_payment_basepoint_remote", &channel_info.theirbase.delayed_payment);
	db_col_pubkey(stmt, "per_commit_remote", &channel_info.remote_per_commit);
	db_col_pubkey(stmt, "old_per_commit_remote", &channel_info.old_remote_per_commit);

	wallet_channel_config_load(w, db_col_u64(stmt, "channel_config_remote"),
				   &channel_info.their_config);

	fee_states
		= wallet_channel_fee_states_load(w,
						 db_col_u64(stmt, "id"),
						 db_col_int(stmt, "funder"));
	if (!fee_states)
		ok = false;

	if (!ok) {
		tal_free(fee_states);
		return NULL;
	}

	/* Blockheight states for the channel! */
	height_states
		= wallet_channel_height_states_load(w,
						    db_col_u64(stmt, "id"),
						    db_col_int(stmt, "funder"));
	if (!height_states)
		ok = false;

	if (!ok) {
		tal_free(height_states);
		return NULL;
	}

	final_key_idx = db_col_u64(stmt, "shutdown_keyidx_local");
	if (final_key_idx < 0) {
		tal_free(fee_states);
		log_broken(w->log, "%s: Final key < 0", __func__);
		return NULL;
	}

	db_col_pubkey(stmt, "revocation_basepoint_local",
		      &local_basepoints.revocation);
	db_col_pubkey(stmt, "payment_basepoint_local",
		      &local_basepoints.payment);
	db_col_pubkey(stmt, "htlc_basepoint_local",
		      &local_basepoints.htlc);
	db_col_pubkey(stmt, "delayed_payment_basepoint_local",
		      &local_basepoints.delayed_payment);
	db_col_pubkey(stmt, "funding_pubkey_local", &local_funding_pubkey);
	if (db_col_is_null(stmt, "shutdown_wrong_txid")) {
		db_col_ignore(stmt, "shutdown_wrong_outnum");
		shutdown_wrong_funding = NULL;
	} else {
		shutdown_wrong_funding = tal(tmpctx, struct bitcoin_outpoint);
		db_col_txid(stmt, "shutdown_wrong_txid",
			    &shutdown_wrong_funding->txid);
		shutdown_wrong_funding->n
			= db_col_int(stmt, "shutdown_wrong_outnum");
	}

	funding_sat = db_col_amount_sat(stmt, "funding_satoshi");
	our_funding_sat = db_col_amount_sat(stmt, "our_funding_satoshi");
	push_msat = db_col_amount_msat(stmt, "push_msatoshi");
	our_msat = db_col_amount_msat(stmt, "msatoshi_local");
	msat_to_us_min = db_col_amount_msat(stmt, "msatoshi_to_us_min");
	msat_to_us_max = db_col_amount_msat(stmt, "msatoshi_to_us_max");
	htlc_minimum_msat = db_col_amount_msat(stmt, "htlc_minimum_msat");
	htlc_maximum_msat = db_col_amount_msat(stmt, "htlc_maximum_msat");
	ignore_fee_limits = db_col_int(stmt, "ignore_fee_limits");

	if (!db_col_is_null(stmt, "lease_commit_sig")) {
		lease_commit_sig = tal(w, secp256k1_ecdsa_signature);
		db_col_signature(stmt, "lease_commit_sig", lease_commit_sig);
		lease_chan_max_msat = db_col_int(stmt, "lease_chan_max_msat");
		lease_chan_max_ppt = db_col_int(stmt, "lease_chan_max_ppt");
	} else {
		db_col_ignore(stmt, "lease_chan_max_msat");
		db_col_ignore(stmt, "lease_chan_max_ppt");
		lease_commit_sig = NULL;
		lease_chan_max_msat = 0;
		lease_chan_max_ppt = 0;
	}

	type = db_col_channel_type(NULL, stmt, "channel_type");

	/* last_tx is null for stub channels used for recovering funds through
	 * Static channel backups. */
	if (!db_col_is_null(stmt, "last_tx")) {
		last_tx = db_col_psbt_to_tx(tmpctx, stmt, "last_tx");
		if (!last_tx)
			db_fatal(w->db, "Failed to decode channel %s psbt %s",
				 fmt_channel_id(tmpctx, &cid),
				 tal_hex(tmpctx, db_col_arr(tmpctx, stmt,
							    "last_tx", u8)));
		last_sig = tal(tmpctx, struct bitcoin_signature);
		db_col_signature(stmt, "last_sig", &last_sig->s);
		last_sig->sighash_type = SIGHASH_ALL;
	} else {
		last_tx = NULL;
		last_sig = NULL;
	}

	if (!db_col_is_null(stmt, "remote_cltv_expiry_delta")) {
		remote_update = tal(NULL, struct peer_update);
		if (scid)
			remote_update->scid = *scid;
		else
			remote_update->scid = *alias[LOCAL];
		remote_update->fee_base = db_col_int(stmt, "remote_feerate_base");
		remote_update->fee_ppm = db_col_int(stmt, "remote_feerate_ppm");
		remote_update->cltv_delta = db_col_int(stmt, "remote_cltv_expiry_delta");
		remote_update->htlc_minimum_msat = db_col_amount_msat(stmt, "remote_htlc_minimum_msat");
		remote_update->htlc_maximum_msat = db_col_amount_msat(stmt, "remote_htlc_maximum_msat");
	} else {
		remote_update = NULL;
		db_col_ignore(stmt, "remote_feerate_base");
		db_col_ignore(stmt, "remote_feerate_ppm");
		db_col_ignore(stmt, "remote_cltv_expiry_delta");
		db_col_ignore(stmt, "remote_htlc_minimum_msat");
		db_col_ignore(stmt, "remote_htlc_maximum_msat");
	}

	chan = new_channel(peer, db_col_u64(stmt, "id"),
			   &wshachain,
			   channel_state_in_db(db_col_int(stmt, "state")),
			   db_col_int(stmt, "funder"),
			   NULL, /* Set up fresh log */
			   "Loaded from database",
			   db_col_int(stmt, "channel_flags"),
			   db_col_int(stmt, "require_confirm_inputs_local") != 0,
			   db_col_int(stmt, "require_confirm_inputs_remote") != 0,
			   &our_config,
			   db_col_int(stmt, "minimum_depth"),
			   db_col_u64(stmt, "next_index_local"),
			   db_col_u64(stmt, "next_index_remote"),
			   db_col_u64(stmt, "next_htlc_id"),
			   &funding,
			   funding_sat,
			   push_msat,
			   our_funding_sat,
			   db_col_int(stmt, "funding_locked_remote") != 0,
			   scid,
			   alias[LOCAL],
			   alias[REMOTE],
			   &cid,
			   our_msat,
			   msat_to_us_min, /* msatoshi_to_us_min */
			   msat_to_us_max, /* msatoshi_to_us_max */
			   last_tx,
			   last_sig,
			   wallet_htlc_sigs_load(tmpctx, w,
						 db_col_u64(stmt, "id"),
						 channel_type_has_anchors(type)),
			   &channel_info,
			   take(fee_states),
			   remote_shutdown_scriptpubkey,
			   local_shutdown_scriptpubkey,
			   final_key_idx,
			   db_col_int(stmt, "last_was_revoke") != 0,
			   last_sent_commit,
			   db_col_u64(stmt, "first_blocknum"),
			   db_col_int(stmt, "min_possible_feerate"),
			   db_col_int(stmt, "max_possible_feerate"),
			   &local_basepoints, &local_funding_pubkey,
			   future_per_commitment_point,
			   db_col_int(stmt, "feerate_base"),
			   db_col_int(stmt, "feerate_ppm"),
			   db_col_arr(tmpctx, stmt, "remote_upfront_shutdown_script", u8),
			   db_col_u64(stmt, "local_static_remotekey_start"),
			   db_col_u64(stmt, "remote_static_remotekey_start"),
			   type,
			   db_col_int(stmt, "closer"),
			   state_change_in_db(db_col_int(stmt, "state_change_reason")),
			   shutdown_wrong_funding,
			   take(height_states),
			   db_col_int(stmt, "lease_expiry"),
			   lease_commit_sig,
			   lease_chan_max_msat,
			   lease_chan_max_ppt,
			   htlc_minimum_msat,
			   htlc_maximum_msat,
			   ignore_fee_limits,
			   remote_update,
			   db_col_u64(stmt, "last_stable_connection"));

	if (!wallet_channel_load_inflights(w, chan)) {
		tal_free(chan);
		return NULL;
	}

	return chan;
}

static struct closed_channel *wallet_stmt2closed_channel(const tal_t *ctx,
							 struct wallet *w,
							 struct db_stmt *stmt)
{
	struct closed_channel *cc = tal(ctx, struct closed_channel);

	/* Can be missing in older dbs! */
	cc->peer_id = db_col_optional(cc, stmt, "p.node_id", node_id);
	db_col_channel_id(stmt, "full_channel_id", &cc->cid);
	cc->scid = db_col_optional_scid(cc, stmt, "scid");
	cc->alias[LOCAL] = db_col_optional_scid(cc, stmt, "alias_local");
	cc->alias[REMOTE] = db_col_optional_scid(cc, stmt, "alias_remote");
	cc->opener = db_col_int(stmt, "funder");
	cc->closer = db_col_int(stmt, "closer");
	cc->channel_flags = db_col_int(stmt, "channel_flags");
	cc->next_index[LOCAL] = db_col_u64(stmt, "next_index_local");
	cc->next_index[REMOTE] = db_col_u64(stmt, "next_index_remote");
	cc->next_htlc_id = db_col_u64(stmt, "next_htlc_id");
	db_col_sha256d(stmt, "funding_tx_id", &cc->funding.txid.shad);
	cc->funding.n = db_col_int(stmt, "funding_tx_outnum");
	cc->funding_sats = db_col_amount_sat(stmt, "funding_satoshi");
	cc->push = db_col_amount_msat(stmt, "push_msatoshi");
	cc->our_msat = db_col_amount_msat(stmt, "msatoshi_local");
	cc->msat_to_us_min = db_col_amount_msat(stmt, "msatoshi_to_us_min");
	cc->msat_to_us_max = db_col_amount_msat(stmt, "msatoshi_to_us_max");
	cc->last_stable_connection = db_col_u64(stmt, "last_stable_connection");
	/* last_tx is null for stub channels used for recovering funds through
	 * Static channel backups. */
	if (!db_col_is_null(stmt, "last_tx"))
		cc->last_tx = db_col_psbt_to_tx(cc, stmt, "last_tx");
	else
		cc->last_tx = NULL;

	cc->type = db_col_channel_type(cc, stmt, "channel_type");
	cc->state_change_cause
		= state_change_in_db(db_col_int(stmt, "state_change_reason"));
	cc->leased = !db_col_is_null(stmt, "lease_commit_sig");

	return cc;
}

struct closed_channel **wallet_load_closed_channels(const tal_t *ctx,
						    struct wallet *w)
{
	struct db_stmt *stmt;
	struct closed_channel **chans = tal_arr(ctx, struct closed_channel *, 0);

	/* We load all channels */
	stmt = db_prepare_v2(w->db, SQL("SELECT "
					" p.node_id"
					", full_channel_id"
					", scid"
					", alias_local"
					", alias_remote"
					", funder"
					", closer"
					", channel_flags"
					", next_index_local"
					", next_index_remote"
					", next_htlc_id"
					", funding_tx_id"
					", funding_tx_outnum"
					", funding_satoshi"
					", push_msatoshi"
					", msatoshi_local"
					", msatoshi_to_us_min"
					", msatoshi_to_us_max"
					", last_tx"
					", channel_type"
					", state_change_reason"
					", lease_commit_sig"
					", last_stable_connection"
					" FROM channels"
					" LEFT JOIN peers p ON p.id = peer_id"
                                        " WHERE state = ?;"));
	db_bind_int(stmt, CLOSED);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct closed_channel *cc = wallet_stmt2closed_channel(chans,
								       w, stmt);
		tal_arr_expand(&chans, cc);
	}
	tal_free(stmt);
	return chans;
}

static void set_max_channel_dbid(struct wallet *w)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT id FROM channels ORDER BY id DESC LIMIT 1;"));
	db_query_prepared(stmt);
	w->max_channel_dbid = 0;

	if (db_step(stmt))
		w->max_channel_dbid = db_col_u64(stmt, "id");

	tal_free(stmt);
}

static bool wallet_channels_load_active(struct wallet *w)
{
	bool ok = true;
	struct db_stmt *stmt;
	int count = 0;

	/* We load all channels */
	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  id"
					", peer_id"
					", scid"
					", full_channel_id"
					", channel_config_local"
					", channel_config_remote"
					", state"
					", funder"
					", channel_flags"
					", require_confirm_inputs_local"
					", require_confirm_inputs_remote"
					", minimum_depth"
					", next_index_local"
					", next_index_remote"
					", next_htlc_id"
					", funding_tx_id"
					", funding_tx_outnum"
					", funding_satoshi"
					", our_funding_satoshi"
					", funding_locked_remote"
					", push_msatoshi"
					", msatoshi_local"
					", fundingkey_remote"
					", revocation_basepoint_remote"
					", payment_basepoint_remote"
					", htlc_basepoint_remote"
					", delayed_payment_basepoint_remote"
					", per_commit_remote"
					", old_per_commit_remote"
					", shachain_remote_id"
					", shutdown_scriptpubkey_remote"
					", shutdown_keyidx_local"
					", last_sent_commit_state"
					", last_sent_commit_id"
					", last_tx"
					", last_sig"
					", last_was_revoke"
					", first_blocknum"
					", min_possible_feerate"
					", max_possible_feerate"
					", msatoshi_to_us_min"
					", msatoshi_to_us_max"
					", future_per_commitment_point"
					", last_sent_commit"
					", feerate_base"
					", feerate_ppm"
					", remote_upfront_shutdown_script"
					", local_static_remotekey_start"
					", remote_static_remotekey_start"
					", channel_type"
					", shutdown_scriptpubkey_local"
					", closer"
					", state_change_reason"
					", revocation_basepoint_local"
					", payment_basepoint_local"
					", htlc_basepoint_local"
					", delayed_payment_basepoint_local"
					", funding_pubkey_local"
					", shutdown_wrong_txid"
					", shutdown_wrong_outnum"
					", lease_expiry"
					", lease_commit_sig"
					", lease_chan_max_msat"
					", lease_chan_max_ppt"
					", htlc_minimum_msat"
					", htlc_maximum_msat"
					", alias_local"
					", alias_remote"
					", ignore_fee_limits"
					", remote_feerate_base"
					", remote_feerate_ppm"
					", remote_cltv_expiry_delta"
					", remote_htlc_minimum_msat"
					", remote_htlc_maximum_msat"
					", last_stable_connection"
					" FROM channels"
                                        " WHERE state != ?;")); //? 0
	db_bind_int(stmt, CLOSED);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct channel *c = wallet_stmt2channel(w, stmt);
		if (!c) {
			ok = false;
			break;
		}
		count++;
	}
	log_debug(w->log, "Loaded %d channels from DB", count);
	tal_free(stmt);
	return ok;
}

bool wallet_init_channels(struct wallet *w)
{
	/* We set the max channel database id separately */
	set_max_channel_dbid(w);
	return wallet_channels_load_active(w);
}

static enum channel_state_bucket get_state_channel_db(const char *dir, const char *typ)
{
	enum channel_state_bucket channel_state = IN_OFFERED;
	if (streq(dir, "out"))
		channel_state += 2;
	if (streq(typ, "fulfilled"))
		channel_state += 1;
	return channel_state;
}

static
void wallet_channel_stats_incr_x(struct wallet *w,
				 char const *dir,
				 char const *typ,
				 u64 cdbid,
				 struct amount_msat msat)
{
	struct db_stmt *stmt;
	const char *query = NULL;

	switch (get_state_channel_db(dir, typ)) {
	case IN_OFFERED:
		query = SQL("UPDATE channels"
			    "   SET in_payments_offered = COALESCE(in_payments_offered, 0) + 1"
			    "     , in_msatoshi_offered = COALESCE(in_msatoshi_offered, 0) + ?"
			    " WHERE id = ?;");
		break;
	case IN_FULLFILLED:
		query = SQL("UPDATE channels"
			    "   SET in_payments_fulfilled = COALESCE(in_payments_fulfilled, 0) + 1"
			    "     , in_msatoshi_fulfilled = COALESCE(in_msatoshi_fulfilled, 0) + ?"
			    " WHERE id = ?;");
		break;
	case OUT_OFFERED:
		query = SQL("UPDATE channels"
			    "   SET out_payments_offered = COALESCE(out_payments_offered, 0) + 1"
			    "     , out_msatoshi_offered = COALESCE(out_msatoshi_offered, 0) + ?"
			    " WHERE id = ?;");
		break;
	case OUT_FULLFILLED:
		query = SQL("UPDATE channels"
			    "   SET out_payments_fulfilled = COALESCE(out_payments_fulfilled, 0) + 1"
			    "     , out_msatoshi_fulfilled = COALESCE(out_msatoshi_fulfilled, 0) + ?"
			    " WHERE id = ?;");
		break;
	}

	// Sanity check!
	if (!query)
		fatal("Unknown channel state key (direction %s, type %s)", dir, typ);

	stmt = db_prepare_v2(w->db, query);
	db_bind_amount_msat(stmt, &msat);
	db_bind_u64(stmt, cdbid);

	db_exec_prepared_v2(take(stmt));
}
void wallet_channel_stats_incr_in_offered(struct wallet *w, u64 id,
					  struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "in", "offered", id, m);
}
void wallet_channel_stats_incr_in_fulfilled(struct wallet *w, u64 id,
					    struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "in", "fulfilled", id, m);
}
void wallet_channel_stats_incr_out_offered(struct wallet *w, u64 id,
					    struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "out", "offered", id, m);
}
void wallet_channel_stats_incr_out_fulfilled(struct wallet *w, u64 id,
					    struct amount_msat m)
{
	wallet_channel_stats_incr_x(w, "out", "fulfilled", id, m);
}

void wallet_channel_stats_load(struct wallet *w,
			       u64 id,
			       struct channel_stats *stats)
{
	struct db_stmt *stmt;
	int res;
	stmt = db_prepare_v2(w->db, SQL(
				     "SELECT"
				     "   in_payments_offered,  in_payments_fulfilled"
				     ",  in_msatoshi_offered,  in_msatoshi_fulfilled"
				     ", out_payments_offered, out_payments_fulfilled"
				     ", out_msatoshi_offered, out_msatoshi_fulfilled"
				     "  FROM channels"
				     " WHERE id = ?"));
	db_bind_u64(stmt, id);
	db_query_prepared(stmt);

	res = db_step(stmt);

	/* This must succeed, since we know the channel exists */
	assert(res);

	stats->in_payments_offered
		= db_col_int_or_default(stmt, "in_payments_offered", 0);
	stats->in_payments_fulfilled
		= db_col_int_or_default(stmt, "in_payments_fulfilled", 0);
	db_col_amount_msat_or_default(stmt, "in_msatoshi_offered",
				      &stats->in_msatoshi_offered,
				      AMOUNT_MSAT(0));
	db_col_amount_msat_or_default(stmt, "in_msatoshi_fulfilled",
				      &stats->in_msatoshi_fulfilled,
				      AMOUNT_MSAT(0));
	stats->out_payments_offered
		= db_col_int_or_default(stmt, "out_payments_offered", 0);
	stats->out_payments_fulfilled
		= db_col_int_or_default(stmt, "out_payments_fulfilled", 0);
	db_col_amount_msat_or_default(stmt, "out_msatoshi_offered",
				      &stats->out_msatoshi_offered,
				      AMOUNT_MSAT(0));
	db_col_amount_msat_or_default(stmt, "out_msatoshi_fulfilled",
				      &stats->out_msatoshi_fulfilled,
				      AMOUNT_MSAT(0));
	tal_free(stmt);
}

void wallet_blocks_heights(struct wallet *w, u32 def, u32 *min, u32 *max)
{
	assert(min != NULL && max != NULL);
	struct db_stmt *stmt = db_prepare_v2(w->db, SQL("SELECT MIN(height), MAX(height) FROM blocks;"));
	db_query_prepared(stmt);
	*min = def;
	*max = def;

	/* If we ever processed a block we'll get the latest block in the chain */
	if (db_step(stmt)) {
		if (!db_col_is_null(stmt, "MIN(height)")) {
			*min = db_col_int(stmt, "MIN(height)");
			*max = db_col_int(stmt, "MAX(height)");
		} else {
			db_col_ignore(stmt, "MAX(height)");
		}
	}
	tal_free(stmt);
}

static void wallet_channel_config_insert(struct wallet *w,
					 struct channel_config *cc)
{
	struct db_stmt *stmt;

	assert(cc->id == 0);

	stmt = db_prepare_v2(w->db, SQL("INSERT INTO channel_configs DEFAULT VALUES;"));
	db_exec_prepared_v2(stmt);
	cc->id = db_last_insert_id_v2(stmt);
	tal_free(stmt);
}

static void wallet_channel_config_save(struct wallet *w,
				       const struct channel_config *cc)
{
	struct db_stmt *stmt;

	assert(cc->id != 0);
	stmt = db_prepare_v2(w->db, SQL("UPDATE channel_configs SET"
					"  dust_limit_satoshis=?,"
					"  max_htlc_value_in_flight_msat=?,"
					"  channel_reserve_satoshis=?,"
					"  htlc_minimum_msat=?,"
					"  to_self_delay=?,"
					"  max_accepted_htlcs=?,"
					"  max_dust_htlc_exposure_msat=?"
					" WHERE id=?;"));
	db_bind_amount_sat(stmt, &cc->dust_limit);
	db_bind_amount_msat(stmt, &cc->max_htlc_value_in_flight);
	db_bind_amount_sat(stmt, &cc->channel_reserve);
	db_bind_amount_msat(stmt, &cc->htlc_minimum);
	db_bind_int(stmt, cc->to_self_delay);
	db_bind_int(stmt, cc->max_accepted_htlcs);
	db_bind_amount_msat(stmt, &cc->max_dust_htlc_exposure_msat);
	db_bind_u64(stmt, cc->id);
	db_exec_prepared_v2(take(stmt));
}

u64 wallet_get_channel_dbid(struct wallet *wallet)
{
	return ++wallet->max_channel_dbid;
}

/* When we receive the remote announcement message, we will also call this function */
void wallet_announcement_save(struct wallet *w, u64 id,
			      secp256k1_ecdsa_signature *remote_ann_node_sig,
			      secp256k1_ecdsa_signature *remote_ann_bitcoin_sig)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("UPDATE channels SET"
					"  remote_ann_node_sig=?,"
					"  remote_ann_bitcoin_sig=?"
					" WHERE id=?"));

	db_bind_signature(stmt, remote_ann_node_sig);
	db_bind_signature(stmt, remote_ann_bitcoin_sig);
	db_bind_u64(stmt, id);
	db_exec_prepared_v2(take(stmt));
}


void wallet_htlcsigs_confirm_inflight(struct wallet *w, struct channel *chan,
				      const struct bitcoin_outpoint *confirmed_outpoint)
{
	struct db_stmt *stmt;

	/* A NULL inflight_tx_id means these htlc_sigs apply to the currently
	 * active channel */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM htlc_sigs"
					" WHERE channelid=?"
					" AND (inflight_tx_id is NULL"
					     " OR ("
						 " inflight_tx_id!=?"
						 " AND "
						 " inflight_tx_outnum!=?"
						 ")"
					     ")"));
	db_bind_u64(stmt, chan->dbid);
	db_bind_txid(stmt, &confirmed_outpoint->txid);
	db_bind_int(stmt, confirmed_outpoint->n);
	db_exec_prepared_v2(take(stmt));

	stmt = db_prepare_v2(w->db, SQL("UPDATE htlc_sigs"
					" SET inflight_tx_id=NULL"
					" WHERE channelid=?"));
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));
}

void wallet_channel_save(struct wallet *w, struct channel *chan)
{
	struct db_stmt *stmt;
	u8 *last_sent_commit;
	const struct peer_update *peer_update;
	assert(chan->first_blocknum);

	wallet_channel_config_save(w, &chan->our_config);

	stmt = db_prepare_v2(w->db, SQL("UPDATE channels SET"
					"  shachain_remote_id=?," // 0
					"  scid=?," // 1
					"  full_channel_id=?," // 2
					"  state=?," // 3
					"  funder=?," // 4
					"  channel_flags=?," // 5
					"  minimum_depth=?," // 6
					"  next_index_local=?," // 7
					"  next_index_remote=?," // 8
					"  next_htlc_id=?," // 9
					"  funding_tx_id=?," // 10
					"  funding_tx_outnum=?," // 11
					"  funding_satoshi=?," // 12
					"  our_funding_satoshi=?," // 13
					"  funding_locked_remote=?," // 14
					"  push_msatoshi=?," // 15
					"  msatoshi_local=?," // 16
					"  shutdown_scriptpubkey_remote=?,"
					"  shutdown_keyidx_local=?," // 18
					"  channel_config_local=?," // 19
					"  last_tx=?, last_sig=?," // 20 + 21
					"  last_was_revoke=?," // 22
					"  min_possible_feerate=?," // 23
					"  max_possible_feerate=?," // 24
					"  msatoshi_to_us_min=?," // 25
					"  msatoshi_to_us_max=?," // 26
					"  feerate_base=?," // 27
					"  feerate_ppm=?," // 28
					"  remote_upfront_shutdown_script=?," // 29
					"  local_static_remotekey_start=?," // 30
					"  remote_static_remotekey_start=?," // 31
					"  channel_type=?," // 32
					"  shutdown_scriptpubkey_local=?," // 33
					"  closer=?," // 34
					"  state_change_reason=?," // 35
					"  shutdown_wrong_txid=?," // 36
					"  shutdown_wrong_outnum=?," // 37
					"  lease_expiry=?," // 38
					"  lease_commit_sig=?," // 39
					"  lease_chan_max_msat=?," // 40
					"  lease_chan_max_ppt=?," // 41
					"  htlc_minimum_msat=?," // 42
					"  htlc_maximum_msat=?," // 43
					"  alias_local=?," // 44
					"  alias_remote=?," // 45
					"  ignore_fee_limits=?," // 46
					"  remote_feerate_base=?," // 47
					"  remote_feerate_ppm=?," // 48
					"  remote_cltv_expiry_delta=?," // 49
					"  remote_htlc_minimum_msat=?," // 50
					"  remote_htlc_maximum_msat=?," // 51
					"  last_stable_connection=?," // 52
					"  require_confirm_inputs_remote=?" // 53
					" WHERE id=?")); // 54
	db_bind_u64(stmt, chan->their_shachain.id);
	if (chan->scid)
		db_bind_short_channel_id(stmt, *chan->scid);
	else
		db_bind_null(stmt);

	db_bind_channel_id(stmt, &chan->cid);
	db_bind_int(stmt, channel_state_in_db(chan->state));
	db_bind_int(stmt, chan->opener);
	db_bind_int(stmt, chan->channel_flags);
	db_bind_int(stmt, chan->minimum_depth);

	db_bind_u64(stmt, chan->next_index[LOCAL]);
	db_bind_u64(stmt, chan->next_index[REMOTE]);
	db_bind_u64(stmt, chan->next_htlc_id);

	db_bind_sha256d(stmt, &chan->funding.txid.shad);

	db_bind_int(stmt, chan->funding.n);
	db_bind_amount_sat(stmt, &chan->funding_sats);
	db_bind_amount_sat(stmt, &chan->our_funds);
	db_bind_int(stmt, chan->remote_channel_ready);
	db_bind_amount_msat(stmt, &chan->push);
	db_bind_amount_msat(stmt, &chan->our_msat);

	db_bind_talarr(stmt, chan->shutdown_scriptpubkey[REMOTE]);
	db_bind_u64(stmt, chan->final_key_idx);
	db_bind_u64(stmt, chan->our_config.id);
	if (chan->last_tx) {
		db_bind_psbt(stmt, chan->last_tx->psbt);
		db_bind_signature(stmt, &chan->last_sig.s);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
	}
	db_bind_int(stmt, chan->last_was_revoke);
	db_bind_int(stmt, chan->min_possible_feerate);
	db_bind_int(stmt, chan->max_possible_feerate);
	db_bind_amount_msat(stmt, &chan->msat_to_us_min);
	db_bind_amount_msat(stmt, &chan->msat_to_us_max);
	db_bind_int(stmt, chan->feerate_base);
	db_bind_int(stmt, chan->feerate_ppm);
	db_bind_talarr(stmt, chan->remote_upfront_shutdown_script);
	db_bind_u64(stmt, chan->static_remotekey_start[LOCAL]);
	db_bind_u64(stmt, chan->static_remotekey_start[REMOTE]);
	db_bind_channel_type(stmt, chan->type);
	db_bind_talarr(stmt, chan->shutdown_scriptpubkey[LOCAL]);
	db_bind_int(stmt, chan->closer);
	db_bind_int(stmt, state_change_in_db(chan->state_change_cause));
	if (chan->shutdown_wrong_funding) {
		db_bind_txid(stmt, &chan->shutdown_wrong_funding->txid);
		db_bind_int(stmt, chan->shutdown_wrong_funding->n);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
	}

	db_bind_int(stmt, chan->lease_expiry);
	if (chan->lease_commit_sig) {
		db_bind_signature(stmt, chan->lease_commit_sig);
		db_bind_int(stmt, chan->lease_chan_max_msat);
		db_bind_int(stmt, chan->lease_chan_max_ppt);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_null(stmt);
	}
	db_bind_amount_msat(stmt, &chan->htlc_minimum_msat);
	db_bind_amount_msat(stmt, &chan->htlc_maximum_msat);

	if (chan->alias[LOCAL] != NULL)
		db_bind_short_channel_id(stmt, *chan->alias[LOCAL]);
	else
		db_bind_null(stmt);

	if (chan->alias[REMOTE] != NULL)
		db_bind_short_channel_id(stmt, *chan->alias[REMOTE]);
	else
		db_bind_null(stmt);

	db_bind_int(stmt, chan->ignore_fee_limits);
	peer_update = channel_gossip_get_remote_update(chan);
	if (peer_update) {
		db_bind_int(stmt, peer_update->fee_base);
		db_bind_int(stmt, peer_update->fee_ppm);
		db_bind_int(stmt, peer_update->cltv_delta);
		db_bind_amount_msat(stmt, &peer_update->htlc_minimum_msat);
		db_bind_amount_msat(stmt, &peer_update->htlc_maximum_msat);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_null(stmt);
		db_bind_null(stmt);
	}
	db_bind_u64(stmt, chan->last_stable_connection);

	db_bind_int(stmt, chan->req_confirmed_ins[REMOTE]);
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));

	wallet_channel_config_save(w, &chan->channel_info.their_config);
	stmt = db_prepare_v2(w->db, SQL("UPDATE channels SET"
					"  fundingkey_remote=?,"
					"  revocation_basepoint_remote=?,"
					"  payment_basepoint_remote=?,"
					"  htlc_basepoint_remote=?,"
					"  delayed_payment_basepoint_remote=?,"
					"  per_commit_remote=?,"
					"  old_per_commit_remote=?,"
					"  channel_config_remote=?,"
					"  future_per_commitment_point=?"
					" WHERE id=?"));
	db_bind_pubkey(stmt,  &chan->channel_info.remote_fundingkey);
	db_bind_pubkey(stmt,  &chan->channel_info.theirbase.revocation);
	db_bind_pubkey(stmt,  &chan->channel_info.theirbase.payment);
	db_bind_pubkey(stmt,  &chan->channel_info.theirbase.htlc);
	db_bind_pubkey(stmt,  &chan->channel_info.theirbase.delayed_payment);
	db_bind_pubkey(stmt,  &chan->channel_info.remote_per_commit);
	db_bind_pubkey(stmt,  &chan->channel_info.old_remote_per_commit);
	db_bind_u64(stmt, chan->channel_info.their_config.id);
	if (chan->future_per_commitment_point)
		db_bind_pubkey(stmt, chan->future_per_commitment_point);
	else
		db_bind_null(stmt);
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));

	/* FIXME: Updates channel_feerates by discarding and rewriting. */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM channel_feerates "
					"WHERE channel_id=?"));
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));

	for (enum htlc_state i = 0;
	     i < ARRAY_SIZE(chan->fee_states->feerate);
	     i++) {
		if (!chan->fee_states->feerate[i])
			continue;
		stmt = db_prepare_v2(w->db, SQL("INSERT INTO channel_feerates "
						" VALUES(?, ?, ?)"));
		db_bind_u64(stmt, chan->dbid);
		db_bind_int(stmt, htlc_state_in_db(i));
		db_bind_int(stmt, *chan->fee_states->feerate[i]);
		db_exec_prepared_v2(take(stmt));
	}

	/* FIXME: Updates channel_blockheights by discarding and rewriting. */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM channel_blockheights "
					"WHERE channel_id=?"));
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));

	for (enum htlc_state i = 0;
	     i < ARRAY_SIZE(chan->blockheight_states->height);
	     i++) {
		if (!chan->blockheight_states->height[i])
			continue;
		stmt = db_prepare_v2(w->db, SQL("INSERT INTO channel_blockheights "
						" VALUES(?, ?, ?)"));
		db_bind_u64(stmt, chan->dbid);
		db_bind_int(stmt, htlc_state_in_db(i));
		db_bind_int(stmt, *chan->blockheight_states->height[i]);
		db_exec_prepared_v2(take(stmt));
	}

	/* If we have a last_sent_commit, store it */
	last_sent_commit = tal_arr(tmpctx, u8, 0);
	for (size_t i = 0; i < tal_count(chan->last_sent_commit); i++)
		towire_changed_htlc(&last_sent_commit,
				    &chan->last_sent_commit[i]);
	/* Make it null in db if it's empty */
	if (tal_count(last_sent_commit) == 0)
		last_sent_commit = tal_free(last_sent_commit);

	stmt = db_prepare_v2(w->db, SQL("UPDATE channels SET"
					"  last_sent_commit=?"
					" WHERE id=?"));
	/* Update the inflights also */
	struct channel_inflight *inflight;
	list_for_each(&chan->inflights, inflight, list)
		if (!inflight->splice_locked_memonly)
			wallet_inflight_save(w, inflight);

	db_bind_talarr(stmt, last_sent_commit);
	db_bind_u64(stmt, chan->dbid);
	db_exec_prepared_v2(take(stmt));

	channel_gossip_update(chan);
}

void wallet_state_change_add(struct wallet *w,
			     const u64 channel_id,
			     struct timeabs timestamp,
			     enum channel_state old_state,
			     enum channel_state new_state,
			     enum state_change cause,
			     const char *message)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO channel_state_changes ("
				 "  channel_id"
				 ", timestamp"
				 ", old_state"
				 ", new_state"
				 ", cause"
				 ", message"
				 ") VALUES (?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, channel_id);
	db_bind_timeabs(stmt, timestamp);
	db_bind_int(stmt, channel_state_in_db(old_state));
	db_bind_int(stmt, channel_state_in_db(new_state));
	db_bind_int(stmt, state_change_in_db(cause));
	db_bind_text(stmt, message);

	db_exec_prepared_v2(take(stmt));
}

struct state_change_entry *wallet_state_change_get(const tal_t *ctx,
						   struct wallet *w,
						   u64 channel_id)
{
	struct db_stmt *stmt;
	struct state_change_entry tmp;
	struct state_change_entry *res = tal_arr(ctx,
						 struct state_change_entry, 0);
	stmt = db_prepare_v2(
	    w->db, SQL("SELECT"
		       " timestamp,"
		       " old_state,"
		       " new_state,"
		       " cause,"
		       " message "
		       "FROM channel_state_changes "
		       "WHERE channel_id = ? "
		       "ORDER BY timestamp ASC;"));
	db_bind_int(stmt, channel_id);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		tmp.timestamp = db_col_timeabs(stmt, "timestamp");
		tmp.old_state = db_col_int(stmt, "old_state");
		tmp.new_state = db_col_int(stmt, "new_state");
		tmp.cause = state_change_in_db(db_col_int(stmt, "cause"));
		tmp.message = db_col_strdup(res, stmt, "message");
		tal_arr_expand(&res, tmp);
	}
	tal_free(stmt);
	return res;
}

static void wallet_peer_save(struct wallet *w, struct peer *peer)
{
	const char *addr =
	    fmt_wireaddr_internal(tmpctx, &peer->addr);
	struct db_stmt *stmt =
	    db_prepare_v2(w->db, SQL("SELECT id FROM peers WHERE node_id = ?"));

	db_bind_node_id(stmt, &peer->id);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		/* So we already knew this peer, just return its dbid */
		peer_set_dbid(peer, db_col_u64(stmt, "id"));
		tal_free(stmt);

		/* Since we're at it update the wireaddr, feature bits */
		stmt = db_prepare_v2(
		    w->db, SQL("UPDATE peers SET address = ?, feature_bits = ? WHERE id = ?"));
		db_bind_text(stmt, addr);
		db_bind_talarr(stmt, peer->their_features);
		db_bind_u64(stmt, peer->dbid);
		db_exec_prepared_v2(take(stmt));

	} else {
		/* Unknown peer, create it from scratch */
		tal_free(stmt);
		stmt = db_prepare_v2(w->db,
				     SQL("INSERT INTO peers (node_id, address, feature_bits) VALUES (?, ?, ?);")
			);
		db_bind_node_id(stmt, &peer->id);
		db_bind_text(stmt, addr);
		db_bind_talarr(stmt, peer->their_features);
		db_exec_prepared_v2(stmt);
		peer_set_dbid(peer, db_last_insert_id_v2(take(stmt)));
	}
}

bool channel_exists_by_id(struct wallet *w, u64 dbid) {
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db, SQL("SELECT *"
					" FROM channels"
					" WHERE id = ?"));

	db_bind_u64(stmt, dbid);
	db_query_prepared(stmt);

	/* If we found a result it means channel exists at that place. */
	if (db_step(stmt)) {
		db_col_ignore(stmt, "*");
		tal_free(stmt);
		return true;
	}

	tal_free(stmt);
	return false;
}

void wallet_channel_insert(struct wallet *w, struct channel *chan)
{
	struct db_stmt *stmt;

	assert(chan->dbid != 0);
	assert(chan->unsaved_dbid == 0);

	if (chan->peer->dbid == 0)
		wallet_peer_save(w, chan->peer);

	/* Insert a stub, that we update, unifies INSERT and UPDATE paths */
	stmt = db_prepare_v2(
	    w->db, SQL("INSERT INTO channels ("
		       "  peer_id"
		       ", first_blocknum"
		       ", id"
		       ", revocation_basepoint_local"
		       ", payment_basepoint_local"
		       ", htlc_basepoint_local"
		       ", delayed_payment_basepoint_local"
		       ", funding_pubkey_local"
		       ", require_confirm_inputs_remote"
		       ", require_confirm_inputs_local"
		       ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));
	db_bind_u64(stmt, chan->peer->dbid);
	db_bind_int(stmt, chan->first_blocknum);
	db_bind_int(stmt, chan->dbid);

	db_bind_pubkey(stmt, &chan->local_basepoints.revocation);
	db_bind_pubkey(stmt, &chan->local_basepoints.payment);
	db_bind_pubkey(stmt, &chan->local_basepoints.htlc);
	db_bind_pubkey(stmt, &chan->local_basepoints.delayed_payment);
	db_bind_pubkey(stmt, &chan->local_funding_pubkey);
	db_bind_int(stmt, chan->req_confirmed_ins[REMOTE]);
	db_bind_int(stmt, chan->req_confirmed_ins[LOCAL]);

	db_exec_prepared_v2(take(stmt));

	wallet_channel_config_insert(w, &chan->our_config);
	wallet_channel_config_insert(w, &chan->channel_info.their_config);
	wallet_shachain_init(w, &chan->their_shachain);

	/* Now save path as normal */
	wallet_channel_save(w, chan);
}

void wallet_channel_close(struct wallet *w, u64 wallet_id)
{
	/* We keep a couple of dependent tables around as well, such as the
	 * channel_configs table, since that might help us debug some issues,
	 * and it is rather limited in size. Tables that can grow quite
	 * considerably and that are of limited use after channel closure will
	 * be pruned as well. */

	struct db_stmt *stmt;

	/* Delete entries from `channel_htlcs` */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM channel_htlcs "
					"WHERE channel_id=?"));
	db_bind_u64(stmt, wallet_id);
	db_exec_prepared_v2(take(stmt));

	/* Delete entries from `htlc_sigs` */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM htlc_sigs "
					"WHERE channelid=?"));
	db_bind_u64(stmt, wallet_id);
	db_exec_prepared_v2(take(stmt));

	/* Delete entries from `htlc_sigs` */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM channeltxs "
					"WHERE channel_id=?"));
	db_bind_u64(stmt, wallet_id);
	db_exec_prepared_v2(take(stmt));

	/* Delete any entries from 'inflights' */
	stmt = db_prepare_v2(w->db,
			     SQL("DELETE FROM channel_funding_inflights "
				 " WHERE channel_id=?"));
	db_bind_u64(stmt, wallet_id);
	db_exec_prepared_v2(take(stmt));

	/* Delete shachains */
	stmt = db_prepare_v2(w->db, SQL("DELETE FROM shachains "
					"WHERE id IN ("
					"  SELECT shachain_remote_id "
					"  FROM channels "
					"  WHERE channels.id=?"
					")"));
	db_bind_u64(stmt, wallet_id);
	db_exec_prepared_v2(take(stmt));

	/* Set the channel to closed */
	stmt = db_prepare_v2(w->db, SQL("UPDATE channels "
					"SET state=? "
					"WHERE channels.id=?"));
	db_bind_u64(stmt, channel_state_in_db(CLOSED));
	db_bind_u64(stmt, wallet_id);
	db_exec_prepared_v2(take(stmt));
}

void wallet_channel_inflight_cleanup_incomplete(struct wallet *w, u64 wallet_id)
{
	struct db_stmt *stmt;

	/* Delete any incomplete entries from 'inflights' */
	stmt = db_prepare_v2(w->db,
			     SQL("DELETE FROM channel_funding_inflights "
				 " WHERE channel_id=? AND last_tx IS NULL"));
	db_bind_u64(stmt, wallet_id);
	db_exec_prepared_v2(take(stmt));
}

void wallet_delete_peer_if_unused(struct wallet *w, u64 peer_dbid)
{
	struct db_stmt *stmt;

	/* Must not have any channels still using this peer */
	stmt = db_prepare_v2(w->db, SQL("SELECT * FROM channels WHERE peer_id = ?;"));
	db_bind_u64(stmt, peer_dbid);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		db_col_ignore(stmt, "*");
		tal_free(stmt);
		return;
	}
	tal_free(stmt);

	stmt = db_prepare_v2(w->db, SQL("DELETE FROM peers WHERE id=?"));
	db_bind_u64(stmt, peer_dbid);
	db_exec_prepared_v2(take(stmt));
}

void wallet_confirm_tx(struct wallet *w,
		       const struct bitcoin_txid *txid,
		       const u32 confirmation_height)
{
	struct db_stmt *stmt;
	assert(confirmation_height > 0);
	stmt = db_prepare_v2(w->db, SQL("UPDATE outputs "
					"SET confirmation_height = ? "
					"WHERE prev_out_tx = ?"));
	db_bind_int(stmt, confirmation_height);
	db_bind_sha256d(stmt, &txid->shad);

	db_exec_prepared_v2(take(stmt));
}

int wallet_extract_owned_outputs(struct wallet *w, const struct wally_tx *wtx,
				 bool is_coinbase,
				 const u32 *blockheight,
				 struct amount_sat *total)
{
	int num_utxos = 0;

	if (total)
		*total = AMOUNT_SAT(0);
	for (size_t i = 0; i < wtx->num_outputs; i++) {
		const struct wally_tx_output *txout = &wtx->outputs[i];
		struct utxo *utxo;
		u32 index;
		struct amount_asset asset = wally_tx_output_get_amount(txout);
		struct chain_coin_mvt *mvt;

		if (!amount_asset_is_main(&asset))
			continue;

		if (!wallet_can_spend(w, txout->script, &index))
			continue;

		utxo = tal(w, struct utxo);
		utxo->keyindex = index;
		utxo->is_p2sh = is_p2sh(txout->script, txout->script_len, NULL);
		utxo->amount = amount_asset_to_sat(&asset);
		utxo->status = OUTPUT_STATE_AVAILABLE;
		wally_txid(wtx, &utxo->outpoint.txid);
		utxo->outpoint.n = i;
		utxo->close_info = NULL;
		utxo->is_in_coinbase = is_coinbase;

		utxo->blockheight = blockheight ? blockheight : NULL;
		utxo->spendheight = NULL;
		utxo->scriptPubkey = tal_dup_arr(utxo, u8, txout->script, txout->script_len, 0);
		log_debug(w->log, "Owning output %zu %s (%s) txid %s%s%s",
			  i,
			  fmt_amount_sat(tmpctx, utxo->amount),
			  utxo->is_p2sh ? "P2SH" : "SEGWIT",
			  fmt_bitcoin_txid(tmpctx, &utxo->outpoint.txid),
			  blockheight ? " CONFIRMED" : "",
			  is_coinbase ? " COINBASE" : "");

		/* We only record final ledger movements */
		if (blockheight) {
			mvt = new_coin_wallet_deposit(tmpctx, &utxo->outpoint,
						      *blockheight,
						      utxo->amount,
						      DEPOSIT);
			notify_chain_mvt(w->ld, mvt);
		}

		if (!wallet_add_utxo(w, utxo, utxo->is_p2sh ? p2sh_wpkh : our_change)) {
			/* In case we already know the output, make
			 * sure we actually track its
			 * blockheight. This can happen when we grab
			 * the output from a transaction we created
			 * ourselves. */
			if (blockheight)
				wallet_confirm_tx(w, &utxo->outpoint.txid,
						  *blockheight);
			tal_free(utxo);
			continue;
		}

		/* This is an unconfirmed change output, we should track it */
		if (!utxo->is_p2sh && !blockheight)
			txfilter_add_scriptpubkey(w->ld->owned_txfilter, txout->script);

		outpointfilter_add(w->owned_outpoints, &utxo->outpoint);

		if (total && !amount_sat_add(total, *total, utxo->amount))
			fatal("Cannot add utxo output %zu/%zu %s + %s",
			      i, wtx->num_outputs,
			      fmt_amount_sat(tmpctx, *total),
			      fmt_amount_sat(tmpctx, utxo->amount));

		wallet_annotate_txout(w, &utxo->outpoint, TX_WALLET_DEPOSIT, 0);
		tal_free(utxo);
		num_utxos++;
	}
	return num_utxos;
}

void wallet_htlc_save_in(struct wallet *wallet,
			 const struct channel *chan, struct htlc_in *in)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(wallet->db,
			     SQL("INSERT INTO channel_htlcs ("
				 " channel_id,"
				 " channel_htlc_id, "
				 " direction,"
				 " msatoshi,"
				 " cltv_expiry,"
				 " payment_hash, "
				 " payment_key,"
				 " hstate,"
				 " shared_secret,"
				 " routing_onion,"
				 " received_time,"
				 " min_commit_num, "
				 " fail_immediate) VALUES "
				 "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, chan->dbid);
	db_bind_u64(stmt, in->key.id);
	db_bind_int(stmt, DIRECTION_INCOMING);
	db_bind_amount_msat(stmt, &in->msat);
	db_bind_int(stmt, in->cltv_expiry);
	db_bind_sha256(stmt, &in->payment_hash);

	if (in->preimage)
		db_bind_preimage(stmt, in->preimage);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, in->hstate);

	if (!in->shared_secret)
		db_bind_null(stmt);
	else
		db_bind_secret(stmt, in->shared_secret);

	db_bind_blob(stmt, in->onion_routing_packet,
		     sizeof(in->onion_routing_packet));

	db_bind_timeabs(stmt, in->received_time);
	db_bind_u64(stmt, min_unsigned(chan->next_index[LOCAL]-1,
					   chan->next_index[REMOTE]-1));

	db_bind_int(stmt, in->fail_immediate);

	db_exec_prepared_v2(stmt);
	in->dbid = db_last_insert_id_v2(take(stmt));
}

void wallet_htlc_save_out(struct wallet *wallet,
			  const struct channel *chan,
			  struct htlc_out *out)
{
	struct db_stmt *stmt;

	/* We absolutely need the incoming HTLC to be persisted before
	 * we can persist it's dependent */
	assert(out->in == NULL || out->in->dbid != 0);

	stmt = db_prepare_v2(
	    wallet->db,
	    SQL("INSERT INTO channel_htlcs ("
		" channel_id,"
		" channel_htlc_id,"
		" direction,"
		" origin_htlc,"
		" msatoshi,"
		" cltv_expiry,"
		" payment_hash,"
		" payment_key,"
		" hstate,"
		" routing_onion,"
		" malformed_onion,"
		" partid,"
		" groupid,"
		" fees_msat,"
		" min_commit_num"
		") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?);"));

	db_bind_u64(stmt, chan->dbid);
	db_bind_u64(stmt, out->key.id);
	db_bind_int(stmt, DIRECTION_OUTGOING);
	if (out->in)
		db_bind_u64(stmt, out->in->dbid);
	else
		db_bind_null(stmt);
	db_bind_amount_msat(stmt, &out->msat);
	db_bind_int(stmt, out->cltv_expiry);
	db_bind_sha256(stmt, &out->payment_hash);

	if (out->preimage)
		db_bind_preimage(stmt, out->preimage);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, out->hstate);

	db_bind_blob(stmt, out->onion_routing_packet,
		     sizeof(out->onion_routing_packet));

	/* groupid and partid are only relevant when we are the origin */
	if (!out->am_origin) {
		db_bind_null(stmt);
		db_bind_null(stmt);
	} else {
		db_bind_u64(stmt, out->partid);
		db_bind_u64(stmt, out->groupid);
	}

	db_bind_amount_msat(stmt, &out->fees);
	db_bind_u64(stmt, min_u64(chan->next_index[LOCAL]-1,
					     chan->next_index[REMOTE]-1));

	db_exec_prepared_v2(stmt);
	out->dbid = db_last_insert_id_v2(stmt);
	tal_free(stmt);
}

/* input htlcs use failcode & failonion & we_filled, output htlcs use failmsg & failonion */
void wallet_htlc_update(struct wallet *wallet, const u64 htlc_dbid,
			const enum htlc_state new_state,
			const struct preimage *payment_key,
			u64 max_commit_num,
			enum onion_wire badonion,
			const struct onionreply *failonion,
			const u8 *failmsg,
			bool *we_filled)
{
	struct db_stmt *stmt;
	bool terminal = (new_state == RCVD_REMOVE_ACK_REVOCATION
			 || new_state == SENT_REMOVE_ACK_REVOCATION);

	/* We should only use this for badonion codes */
	assert(!badonion || (badonion & BADONION));

	/* The database ID must be set by a previous call to
	 * `wallet_htlc_save_*` */
	assert(htlc_dbid);
	stmt = db_prepare_v2(
	    wallet->db, SQL("UPDATE channel_htlcs SET hstate=?, payment_key=?, "
			    "malformed_onion=?, failuremsg=?, localfailmsg=?, "
			    "we_filled=?, max_commit_num=?"
			    " WHERE id=?"));

	db_bind_int(stmt, htlc_state_in_db(new_state));

	if (payment_key)
		db_bind_preimage(stmt, payment_key);
	else
		db_bind_null(stmt);

	db_bind_int(stmt, badonion);

	if (failonion)
		db_bind_onionreply(stmt, failonion);
	else
		db_bind_null(stmt);

	db_bind_talarr(stmt, failmsg);

	if (we_filled)
		db_bind_int(stmt, *we_filled);
	else
		db_bind_null(stmt);

	/* Set max_commit_num iff we're in final state. */
	if (terminal)
		db_bind_u64(stmt, max_commit_num);
	else
		db_bind_null(stmt);
	db_bind_u64(stmt, htlc_dbid);

	db_exec_prepared_v2(take(stmt));

	if (terminal) {
		/* If it's terminal, remove the data we needed for re-xmission. */
		stmt = db_prepare_v2(
			wallet->db,
			SQL("UPDATE channel_htlcs SET payment_key=NULL, routing_onion=NULL, failuremsg=NULL, shared_secret=NULL, localfailmsg=NULL "
			    " WHERE id=?"));
		db_bind_u64(stmt, htlc_dbid);
		db_exec_prepared_v2(take(stmt));
	}
}

static bool wallet_stmt2htlc_in(struct channel *channel,
				struct db_stmt *stmt, struct htlc_in *in)
{
	bool ok = true;
	in->dbid = db_col_u64(stmt, "id");
	in->key.id = db_col_u64(stmt, "channel_htlc_id");
	in->key.channel = channel;
	in->msat = db_col_amount_msat(stmt, "msatoshi");
	in->cltv_expiry = db_col_int(stmt, "cltv_expiry");
	in->hstate = db_col_int(stmt, "hstate");
	in->status = NULL;
	/* FIXME: save blinding in db !*/
	in->blinding = NULL;
	in->payload = NULL;

	db_col_sha256(stmt, "payment_hash", &in->payment_hash);

	in->preimage = db_col_optional(in, stmt, "payment_key", preimage);

	assert(db_col_bytes(stmt, "routing_onion")
	       == sizeof(in->onion_routing_packet));
	memcpy(&in->onion_routing_packet, db_col_blob(stmt, "routing_onion"),
	       sizeof(in->onion_routing_packet));

	if (db_col_is_null(stmt, "failuremsg"))
		in->failonion = NULL;
	else
		in->failonion = db_col_onionreply(in, stmt, "failuremsg");
	in->badonion = db_col_int(stmt, "malformed_onion");
	in->shared_secret = db_col_optional(in, stmt, "shared_secret", secret);
#ifdef COMPAT_V062
	if (in->shared_secret
	    && memeqzero(in->shared_secret, sizeof(*in->shared_secret)))
		in->shared_secret = tal_free(in->shared_secret);
#endif

#ifdef COMPAT_V072
	if (db_col_is_null(stmt, "received_time")) {
		in->received_time.ts.tv_sec = 0;
		in->received_time.ts.tv_nsec = 0;
	} else
#endif /* COMPAT_V072 */
	in->received_time = db_col_timeabs(stmt, "received_time");

#ifdef COMPAT_V080
	/* This field is now reserved for badonion codes: the rest should
	 * use the failonion field. */
	if (in->badonion && !(in->badonion & BADONION)) {
		log_broken(channel->log,
			   "Replacing incoming HTLC %"PRIu64" error "
			   "%s with WIRE_TEMPORARY_NODE_FAILURE",
			   in->key.id, onion_wire_name(in->badonion));
		in->badonion = 0;
		in->failonion = create_onionreply(in,
						  in->shared_secret,
						  towire_temporary_node_failure(tmpctx));
	}
#endif

	if (!db_col_is_null(stmt, "we_filled")) {
		in->we_filled = tal(in, bool);
		*in->we_filled = db_col_int(stmt, "we_filled");
	} else
		in->we_filled = NULL;

	in->fail_immediate = db_col_int(stmt, "fail_immediate");

	return ok;
}

/* Removes matching htlc from unconnected_htlcs_in */
static bool wallet_stmt2htlc_out(struct wallet *wallet,
				 struct channel *channel,
				 struct db_stmt *stmt, struct htlc_out *out,
				 struct htlc_in_map *unconnected_htlcs_in)
{
	bool ok = true;
	out->dbid = db_col_u64(stmt, "id");
	out->key.id = db_col_u64(stmt, "channel_htlc_id");
	out->key.channel = channel;
	out->msat = db_col_amount_msat(stmt, "msatoshi");
	out->cltv_expiry = db_col_int(stmt, "cltv_expiry");
	out->hstate = db_col_int(stmt, "hstate");
	db_col_sha256(stmt, "payment_hash", &out->payment_hash);
	/* FIXME: save blinding in db !*/
	out->blinding = NULL;

	out->preimage = db_col_optional(out, stmt, "payment_key", preimage);

	assert(db_col_bytes(stmt, "routing_onion")
	       == sizeof(out->onion_routing_packet));
	memcpy(&out->onion_routing_packet, db_col_blob(stmt, "routing_onion"),
	       sizeof(out->onion_routing_packet));

	if (db_col_is_null(stmt, "failuremsg"))
		out->failonion = NULL;
	else
		out->failonion = db_col_onionreply(out, stmt, "failuremsg");

	if (db_col_is_null(stmt, "localfailmsg"))
		out->failmsg = NULL;
	else
		out->failmsg = db_col_arr(out, stmt, "localfailmsg", u8);

	out->in = NULL;
	out->fees = db_col_amount_msat(stmt, "fees_msat");

	if (!db_col_is_null(stmt, "origin_htlc")) {
		u64 in_id = db_col_u64(stmt, "origin_htlc");
		struct htlc_in *hin;

		/* If it failed / succeeded already, we could have
		 * closed incoming htlc */
		hin = remove_htlc_in_by_dbid(unconnected_htlcs_in, in_id);
		if (hin)
			htlc_out_connect_htlc_in(out, hin);
		out->am_origin = false;
		db_col_ignore(stmt, "partid");
		db_col_ignore(stmt, "groupid");
	} else {
		out->partid = db_col_u64(stmt, "partid");
		out->groupid = db_col_u64(stmt, "groupid");
		out->am_origin = true;
	}

	return ok;
}

static void fixup_hin(struct wallet *wallet, struct htlc_in *hin)
{
	/* We didn't used to save failcore, failonion... */
#ifdef COMPAT_V061
	/* We care about HTLCs being removed only, not those being added. */
	if (hin->hstate < SENT_REMOVE_HTLC)
		return;

	/* Successful ones are fine. */
	if (hin->preimage)
		return;

	/* Failed ones (only happens after db fixed!) OK. */
	if (hin->badonion || hin->failonion)
		return;

	hin->failonion = create_onionreply(hin,
					   hin->shared_secret,
					   towire_temporary_node_failure(tmpctx));

	log_broken(wallet->log, "HTLC #%"PRIu64" (%s) "
		   " for amount %s"
		   " from %s"
		   " is missing a resolution:"
		   " subsituting temporary node failure",
		   hin->key.id, htlc_state_name(hin->hstate),
		   fmt_amount_msat(tmpctx, hin->msat),
		   fmt_node_id(tmpctx,
				  &hin->key.channel->peer->id));
#endif
}

bool wallet_htlcs_load_in_for_channel(struct wallet *wallet,
				      struct channel *chan,
				      struct htlc_in_map *htlcs_in)
{
	struct db_stmt *stmt;
	bool ok = true;
	int incount = 0;

	log_debug(wallet->log, "Loading in HTLCs for channel %"PRIu64, chan->dbid);
	stmt = db_prepare_v2(wallet->db, SQL("SELECT"
					     "  id"
					     ", channel_htlc_id"
					     ", msatoshi"
					     ", cltv_expiry"
					     ", hstate"
					     ", payment_hash"
					     ", payment_key"
					     ", routing_onion"
					     ", failuremsg"
					     ", malformed_onion"
					     ", shared_secret"
					     ", received_time"
					     ", we_filled"
					     ", fail_immediate"
					     " FROM channel_htlcs"
					     " WHERE direction= ?"
					     " AND channel_id= ?"
					     " AND hstate NOT IN (?, ?)"));
	db_bind_int(stmt, DIRECTION_INCOMING);
	db_bind_u64(stmt, chan->dbid);
	/* We need to generate `hstate NOT IN (9, 19)` in order to match
	 * the `WHERE` clause of the database index; incoming HTLCs will
	 * never actually get the state `RCVD_REMOVE_ACK_REVOCATION`.
	 * See https://sqlite.org/partialindex.html#queries_using_partial_indexes
	 */
	db_bind_int(stmt, RCVD_REMOVE_ACK_REVOCATION); /* Not gonna happen.  */
	db_bind_int(stmt, SENT_REMOVE_ACK_REVOCATION);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct htlc_in *in = tal(chan, struct htlc_in);
		ok &= wallet_stmt2htlc_in(chan, stmt, in);
		connect_htlc_in(htlcs_in, in);
		fixup_hin(wallet, in);
		ok &= htlc_in_check(in, NULL) != NULL;
		incount++;
	}
	tal_free(stmt);

	log_debug(wallet->log, "Restored %d incoming HTLCS", incount);
	return ok;
}

bool wallet_htlcs_load_out_for_channel(struct wallet *wallet,
				       struct channel *chan,
				       struct htlc_out_map *htlcs_out,
				       struct htlc_in_map *unconnected_htlcs_in)
{
	struct db_stmt *stmt;
	bool ok = true;
	int outcount = 0;

	stmt = db_prepare_v2(wallet->db, SQL("SELECT"
					     "  id"
					     ", channel_htlc_id"
					     ", msatoshi"
					     ", cltv_expiry"
					     ", hstate"
					     ", payment_hash"
					     ", payment_key"
					     ", routing_onion"
					     ", failuremsg"
					     ", origin_htlc"
					     ", partid"
					     ", localfailmsg"
					     ", groupid"
					     ", fees_msat"
					     " FROM channel_htlcs"
					     " WHERE direction = ?"
					     " AND channel_id = ?"
					     " AND hstate NOT IN (?, ?)"));
	db_bind_int(stmt, DIRECTION_OUTGOING);
	db_bind_u64(stmt, chan->dbid);
	/* We need to generate `hstate NOT IN (9, 19)` in order to match
	 * the `WHERE` clause of the database index; outgoing HTLCs will
	 * never actually get the state `SENT_REMOVE_ACK_REVOCATION`.
	 * See https://sqlite.org/partialindex.html#queries_using_partial_indexes
	 */
	db_bind_int(stmt, RCVD_REMOVE_ACK_REVOCATION);
	db_bind_int(stmt, SENT_REMOVE_ACK_REVOCATION); /* Not gonna happen.  */
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct htlc_out *out = tal(chan, struct htlc_out);
		ok &= wallet_stmt2htlc_out(wallet, chan, stmt, out,
					   unconnected_htlcs_in);
		connect_htlc_out(htlcs_out, out);
		/* Cannot htlc_out_check because we haven't wired the
		 * dependencies in yet */
		outcount++;
	}
	tal_free(stmt);

	log_debug(wallet->log, "Restored %d outgoing HTLCS", outcount);

	return ok;
}

struct htlc_stub *wallet_htlc_stubs(const tal_t *ctx, struct wallet *wallet,
				    struct channel *chan, u64 commit_num)
{
	struct htlc_stub *stubs;
	struct sha256 payment_hash;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(wallet->db,
			     SQL("SELECT channel_id, direction, cltv_expiry, "
				 "channel_htlc_id, payment_hash "
				 "FROM channel_htlcs WHERE channel_id = ? AND min_commit_num <= ? AND ((max_commit_num IS NULL) OR max_commit_num >= ?);"));

	db_bind_u64(stmt, chan->dbid);
	db_bind_u64(stmt, commit_num);
	db_bind_u64(stmt, commit_num);
	db_query_prepared(stmt);

	stubs = tal_arr(ctx, struct htlc_stub, 0);

	while (db_step(stmt)) {
		struct htlc_stub stub;

		assert(db_col_u64(stmt, "channel_id") == chan->dbid);

		/* FIXME: merge these two enums */
		stub.owner = db_col_int(stmt, "direction")==DIRECTION_INCOMING?REMOTE:LOCAL;
		stub.cltv_expiry = db_col_int(stmt, "cltv_expiry");
		stub.id = db_col_u64(stmt, "channel_htlc_id");

		db_col_sha256(stmt, "payment_hash", &payment_hash);
		ripemd160(&stub.ripemd, payment_hash.u.u8, sizeof(payment_hash.u));
		tal_arr_expand(&stubs, stub);
	}
	tal_free(stmt);
	return stubs;
}

void wallet_local_htlc_out_delete(struct wallet *wallet,
				  struct channel *chan,
				  const struct sha256 *payment_hash,
				  u64 partid)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(wallet->db, SQL("DELETE FROM channel_htlcs"
					     " WHERE direction = ?"
					     " AND origin_htlc = ?"
					     " AND payment_hash = ?"
					     " AND partid = ?;"));
	db_bind_int(stmt, DIRECTION_OUTGOING);
	db_bind_int(stmt, 0);
	db_bind_sha256(stmt, payment_hash);
	db_bind_u64(stmt, partid);
	db_exec_prepared_v2(take(stmt));
}

/* FIXME: reorder! */
static
struct wallet_payment *wallet_payment_new(const tal_t *ctx,
					  u64 dbid,
					  u64 updated_index,
					  u32 timestamp,
					  const u32 *completed_at,
					  const struct sha256 *payment_hash,
					  u64 partid,
					  u64 groupid,
					  enum payment_status status,
					  /* The destination may not be known if we used `sendonion` */
					  const struct node_id *destination,
					  struct amount_msat msatoshi,
					  struct amount_msat msatoshi_sent,
					  struct amount_msat total_msat,
					  /* If and only if PAYMENT_COMPLETE */
					  const struct preimage *payment_preimage,
					  const struct secret *path_secrets,
					  const struct node_id *route_nodes,
					  const struct short_channel_id *route_channels,
					  const char *invstring,
					  const char *label,
					  const char *description,
					  const u8 *failonion,
					  const struct sha256 *local_invreq_id);

struct wallet_payment *wallet_add_payment(const tal_t *ctx,
					  struct wallet *wallet,
					  u32 timestamp,
					  const u32 *completed_at,
					  const struct sha256 *payment_hash,
					  u64 partid,
					  u64 groupid,
					  enum payment_status status,
					  /* The destination may not be known if we used `sendonion` */
					  const struct node_id *destination TAKES,
					  struct amount_msat msatoshi,
					  struct amount_msat msatoshi_sent,
					  struct amount_msat total_msat,
					  /* If and only if PAYMENT_COMPLETE */
					  const struct preimage *payment_preimage TAKES,
					  const struct secret *path_secrets TAKES,
					  const struct node_id *route_nodes TAKES,
					  const struct short_channel_id *route_channels TAKES,
					  const char *invstring TAKES,
					  const char *label TAKES,
					  const char *description TAKES,
					  const u8 *failonion TAKES,
					  const struct sha256 *local_invreq_id)
{
	struct db_stmt *stmt;
	struct wallet_payment *payment;
	u64 id;

	id = sendpay_index_created(wallet->ld,
				   payment_hash,
				   partid, groupid, status);

	payment = wallet_payment_new(ctx, id, 0,
				     timestamp,
				     completed_at,
				     payment_hash,
				     partid,
				     groupid,
				     status,
				     destination,
				     msatoshi,
				     msatoshi_sent,
				     total_msat,
				     payment_preimage,
				     path_secrets,
				     route_nodes,
				     route_channels,
				     invstring,
				     label,
				     description,
				     failonion,
				     local_invreq_id);
	stmt = db_prepare_v2(
		wallet->db,
		SQL("INSERT INTO payments ("
		    "  id,"
		    "  status,"
		    "  payment_hash,"
		    "  destination,"
		    "  msatoshi,"
		    "  timestamp,"
		    "  path_secrets,"
		    "  route_nodes,"
		    "  route_channels,"
		    "  msatoshi_sent,"
		    "  description,"
		    "  bolt11,"
		    "  total_msat,"
		    "  partid,"
		    "  local_invreq_id,"
		    "  groupid,"
		    "  paydescription"
		    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	assert(payment->id > 0);

	db_bind_u64(stmt, payment->id);
	db_bind_int(stmt, payment->status);
	db_bind_sha256(stmt, &payment->payment_hash);

	if (payment->destination != NULL)
		db_bind_node_id(stmt, payment->destination);
	else
		db_bind_null(stmt);

	db_bind_amount_msat(stmt, &payment->msatoshi);
	db_bind_int(stmt, payment->timestamp);

	if (payment->path_secrets != NULL)
		db_bind_secret_arr(stmt, payment->path_secrets);
	else
		db_bind_null(stmt);

	assert((payment->route_channels == NULL) == (payment->route_nodes == NULL));
	if (payment->route_nodes) {
		db_bind_node_id_arr(stmt, payment->route_nodes);
		db_bind_short_channel_id_arr(stmt, payment->route_channels);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
	}

	db_bind_amount_msat(stmt, &payment->msatoshi_sent);

	if (payment->label != NULL)
		db_bind_text(stmt, payment->label);
	else
		db_bind_null(stmt);

	if (payment->invstring != NULL)
		db_bind_text(stmt, payment->invstring);
	else
		db_bind_null(stmt);

	db_bind_amount_msat(stmt, &payment->total_msat);
	db_bind_u64(stmt, payment->partid);

	if (payment->local_invreq_id != NULL)
		db_bind_sha256(stmt, payment->local_invreq_id);
	else
		db_bind_null(stmt);

	db_bind_u64(stmt, payment->groupid);

	if (payment->description != NULL)
		db_bind_text(stmt, payment->description);
	else
		db_bind_null(stmt);

	db_exec_prepared_v2(stmt);
	tal_free(stmt);

	return payment;
}

u64 wallet_payment_get_groupid(struct wallet *wallet,
			       const struct sha256 *payment_hash)
{
	struct db_stmt *stmt;
	u64 groupid = 0;
	stmt = db_prepare_v2(
		wallet->db, SQL("SELECT MAX(groupid) FROM payments WHERE payment_hash = ?"));

	db_bind_sha256(stmt, payment_hash);
	db_query_prepared(stmt);
	if (db_step(stmt) && !db_col_is_null(stmt, "MAX(groupid)")) {
		groupid = db_col_u64(stmt, "MAX(groupid)");
	}
	tal_free(stmt);
	return groupid;
}

void wallet_payment_delete(struct wallet *wallet,
			   const struct sha256 *payment_hash,
			   const u64 *groupid, const u64 *partid,
			   const enum payment_status *status)
{
	struct db_stmt *stmt;

	assert(status);
	if (groupid) {
		assert(partid);
		stmt = db_prepare_v2(wallet->db,
				     SQL("DELETE FROM payments"
					 " WHERE payment_hash = ?"
					 "   AND groupid = ?"
					 "   AND partid = ?"
					 "   AND status = ?"));
		db_bind_sha256(stmt, payment_hash);
		db_bind_u64(stmt, *groupid);
		db_bind_u64(stmt, *partid);
		db_bind_u64(stmt, *status);
		sendpay_index_deleted(wallet->ld, payment_hash, *partid, *groupid,
				      *status);
	} else {
		assert(!partid);
		stmt = db_prepare_v2(wallet->db,
				     SQL("DELETE FROM payments"
					 " WHERE payment_hash = ?"
					 "     AND status = ?"));
		db_bind_sha256(stmt, payment_hash);
		db_bind_u64(stmt, *status);
		/* FIXME: Increment deleted appropriately! */
	}
	db_exec_prepared_v2(take(stmt));
}

static
struct wallet_payment *wallet_payment_new(const tal_t *ctx,
					  u64 dbid,
					  u64 updated_index,
					  u32 timestamp,
					  const u32 *completed_at,
					  const struct sha256 *payment_hash,
					  u64 partid,
					  u64 groupid,
					  enum payment_status status,
					  /* The destination may not be known if we used `sendonion` */
					  const struct node_id *destination,
					  struct amount_msat msatoshi,
					  struct amount_msat msatoshi_sent,
					  struct amount_msat total_msat,
					  /* If and only if PAYMENT_COMPLETE */
					  const struct preimage *payment_preimage,
					  const struct secret *path_secrets,
					  const struct node_id *route_nodes,
					  const struct short_channel_id *route_channels,
					  const char *invstring,
					  const char *label,
					  const char *description,
					  const u8 *failonion,
					  const struct sha256 *local_invreq_id)
{
	struct wallet_payment *payment = tal(ctx, struct wallet_payment);

	payment->id = dbid;
	payment->updated_index = updated_index;
	payment->status = status;
	payment->timestamp = timestamp;
	payment->payment_hash = *payment_hash;
	payment->partid = partid;
	payment->groupid = groupid;
	payment->status = status;
	payment->msatoshi = msatoshi;
	payment->msatoshi_sent = msatoshi_sent;
	payment->total_msat = total_msat;

	/* Optional fields */
	payment->completed_at = tal_dup_or_null(payment, u32, completed_at);
	payment->destination = tal_dup_or_null(payment, struct node_id, destination);
	payment->payment_preimage = tal_dup_or_null(payment, struct preimage, payment_preimage);
	payment->path_secrets = tal_dup_talarr(payment, struct secret, path_secrets);
	payment->route_nodes = tal_dup_talarr(payment, struct node_id, route_nodes);
	payment->route_channels = tal_dup_talarr(payment, struct short_channel_id, route_channels);
	payment->invstring = tal_strdup_or_null(payment, invstring);
	payment->label = tal_strdup_or_null(payment, label);
	payment->description = tal_strdup_or_null(payment, description);
	payment->failonion = tal_dup_talarr(payment, u8, failonion);
	payment->local_invreq_id = tal_dup_or_null(payment, struct sha256, local_invreq_id);

	return payment;
}

struct wallet_payment *payment_get_details(const tal_t *ctx,
					   struct db_stmt *stmt)
{
	struct wallet_payment *payment;
	u32 *completed_at;
	struct sha256 payment_hash;

	db_col_sha256(stmt, "payment_hash", &payment_hash);

	if (!db_col_is_null(stmt, "completed_at")) {
		completed_at = tal(tmpctx, u32);
		*completed_at = db_col_int(stmt, "completed_at");
	} else
		completed_at = NULL;

	payment = wallet_payment_new(ctx,
				     db_col_u64(stmt, "id"),
				     db_col_u64(stmt, "updated_index"),
				     db_col_int(stmt, "timestamp"),
				     completed_at,
				     &payment_hash,
				     db_col_is_null(stmt, "partid") ? 0 : db_col_u64(stmt, "partid"),
				     db_col_u64(stmt, "groupid"),
				     payment_status_in_db(db_col_int(stmt, "status")),
				     take(db_col_optional(NULL, stmt, "destination", node_id)),
				     db_col_amount_msat(stmt, "msatoshi"),
				     db_col_amount_msat(stmt, "msatoshi_sent"),
				     db_col_is_null(stmt, "total_msat") ? AMOUNT_MSAT(0) : db_col_amount_msat(stmt, "total_msat"),
				     take(db_col_optional(NULL, stmt, "payment_preimage", preimage)),
				     take(db_col_secret_arr(NULL, stmt, "path_secrets")),
				     take(db_col_node_id_arr(NULL, stmt, "route_nodes")),
				     take(db_col_short_channel_id_arr(NULL, stmt, "route_channels")),
				     take(db_col_strdup_optional(NULL, stmt, "bolt11")),
				     take(db_col_strdup_optional(NULL, stmt, "description")),
				     take(db_col_strdup_optional(NULL, stmt, "paydescription")),
				     take(db_col_arr(NULL, stmt, "failonionreply", u8)),
				     take(db_col_optional(NULL, stmt, "local_invreq_id", sha256)));

	/* Either none, or both are set */
	assert(db_col_is_null(stmt, "route_nodes")
	       == db_col_is_null(stmt, "route_channels"));
	return payment;
}

struct wallet_payment *
wallet_payment_by_hash(const tal_t *ctx, struct wallet *wallet,
		       const struct sha256 *payment_hash,
		       u64 partid, u64 groupid)
{
	struct db_stmt *stmt;
	struct wallet_payment *payment;

	stmt = db_prepare_v2(wallet->db, SQL("SELECT"
					     "  id"
					     ", updated_index"
					     ", status"
					     ", destination"
					     ", msatoshi"
					     ", payment_hash"
					     ", timestamp"
					     ", payment_preimage"
					     ", path_secrets"
					     ", route_nodes"
					     ", route_channels"
					     ", msatoshi_sent"
					     ", description"
					     ", bolt11"
					     ", paydescription"
					     ", failonionreply"
					     ", total_msat"
					     ", partid"
					     ", local_invreq_id"
					     ", groupid"
					     ", completed_at"
					     " FROM payments"
					     " WHERE payment_hash = ?"
					     " AND partid = ? AND groupid=?"));

	db_bind_sha256(stmt, payment_hash);
	db_bind_u64(stmt, partid);
	db_bind_u64(stmt, groupid);
	db_query_prepared(stmt);
	if (db_step(stmt)) {
		payment = payment_get_details(ctx, stmt);
	} else {
		payment = NULL;
	}
	tal_free(stmt);
	return payment;
}

void wallet_payment_set_status(struct wallet *wallet,
			       const struct sha256 *payment_hash,
			       u64 partid, u64 groupid,
			       const enum payment_status newstatus,
			       const struct preimage *preimage)
{
	struct db_stmt *stmt;
	u32 completed_at = 0;

	if (newstatus != PAYMENT_PENDING)
		completed_at = time_now().ts.tv_sec;

	stmt = db_prepare_v2(wallet->db,
			     SQL("UPDATE payments SET status=?, completed_at=?, updated_index=? "
				 "WHERE payment_hash=? AND partid=? AND groupid=?"));

	db_bind_int(stmt, payment_status_in_db(newstatus));
	if (completed_at != 0) {
		db_bind_u64(stmt, completed_at);
	} else {
		db_bind_null(stmt);
	}
	db_bind_u64(stmt, sendpay_index_update_status(wallet->ld, payment_hash,
						      partid, groupid, newstatus));
	db_bind_sha256(stmt, payment_hash);
	db_bind_u64(stmt, partid);
	db_bind_u64(stmt, groupid);
	db_exec_prepared_v2(take(stmt));

	if (preimage) {
		stmt = db_prepare_v2(wallet->db,
				     SQL("UPDATE payments SET payment_preimage=? "
					 "WHERE payment_hash=? AND partid=? AND groupid=?"));

		db_bind_preimage(stmt, preimage);
		db_bind_sha256(stmt, payment_hash);
		db_bind_u64(stmt, partid);
		db_bind_u64(stmt, groupid);
		db_exec_prepared_v2(take(stmt));
	}
	if (newstatus != PAYMENT_PENDING) {
		stmt =
		    db_prepare_v2(wallet->db, SQL("UPDATE payments"
						  "   SET path_secrets = NULL"
						  "     , route_nodes = NULL"
						  "     , route_channels = NULL"
						  " WHERE payment_hash = ?"
						  " AND partid = ? AND groupid=?;"));
		db_bind_sha256(stmt, payment_hash);
		db_bind_u64(stmt, partid);
		db_bind_u64(stmt, groupid);
		db_exec_prepared_v2(take(stmt));
	}
}

void wallet_payment_get_failinfo(const tal_t *ctx,
				 struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 u64 partid,
				 u64 groupid,
				 /* outputs */
				 struct onionreply **failonionreply,
				 bool *faildestperm,
				 int *failindex,
				 enum onion_wire *failcode,
				 struct node_id **failnode,
				 struct short_channel_id **failchannel,
				 u8 **failupdate,
				 char **faildetail,
				 int *faildirection)
{
	struct db_stmt *stmt;
	bool resb;

	stmt = db_prepare_v2(wallet->db,
			     SQL("SELECT failonionreply, faildestperm"
				 ", failindex, failcode"
				 ", failnode, failscid"
				 ", failupdate, faildetail, faildirection"
				 "  FROM payments"
				 " WHERE payment_hash=? AND partid=? AND groupid=?;"));
	db_bind_sha256(stmt, payment_hash);
	db_bind_u64(stmt, partid);
	db_bind_u64(stmt, groupid);
	db_query_prepared(stmt);
	resb = db_step(stmt);
	assert(resb);

	if (db_col_is_null(stmt, "failonionreply"))
		*failonionreply = NULL;
	else {
		*failonionreply = db_col_onionreply(ctx, stmt, "failonionreply");
	}
	*faildestperm = db_col_int(stmt, "faildestperm") != 0;
	*failindex = db_col_int(stmt, "failindex");
	*failcode = (enum onion_wire) db_col_int(stmt, "failcode");
	*failnode = db_col_optional(ctx, stmt, "failnode", node_id);
	*failchannel = db_col_optional_scid(ctx, stmt, "failscid");
	if (*failchannel) {
		/* For pre-0.6.2 dbs, direction will be 0 */
		*faildirection = db_col_int(stmt, "faildirection");
	} else {
		db_col_ignore(stmt, "faildirection");
	}
	if (db_col_is_null(stmt, "failupdate"))
		*failupdate = NULL;
	else {
		*failupdate = db_col_arr(ctx, stmt, "failupdate", u8);
	}
	if (!db_col_is_null(stmt, "faildetail"))
		*faildetail = db_col_strdup(ctx, stmt, "faildetail");
	else
		*faildetail = NULL;

	tal_free(stmt);
}

void wallet_payment_set_failinfo(struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 u64 partid,
				 const struct onionreply *failonionreply,
				 bool faildestperm,
				 int failindex,
				 enum onion_wire failcode,
				 const struct node_id *failnode,
				 const struct short_channel_id *failchannel,
				 const u8 *failupdate /*tal_arr*/,
				 const char *faildetail,
				 int faildirection)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(wallet->db, SQL("UPDATE payments"
					     "   SET failonionreply=?"
					     "     , faildestperm=?"
					     "     , failindex=?"
					     "     , failcode=?"
					     "     , failnode=?"
					     "     , failscid=?"
					     "     , faildirection=?"
					     "     , failupdate=?"
					     "     , faildetail=?"
					     " WHERE payment_hash=?"
					     " AND partid=?;"));
	if (failonionreply)
		db_bind_talarr(stmt, failonionreply->contents);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, faildestperm ? 1 : 0);
	db_bind_int(stmt, failindex);
	db_bind_int(stmt, (int) failcode);

	if (failnode)
		db_bind_node_id(stmt, failnode);
	else
		db_bind_null(stmt);

	if (failchannel) {
		db_bind_short_channel_id(stmt, *failchannel);
		db_bind_int(stmt, faildirection);
	} else {
		db_bind_null(stmt);
		db_bind_null(stmt);
	}

	db_bind_talarr(stmt, failupdate);

	if (faildetail != NULL)
		db_bind_text(stmt, faildetail);
	else
		db_bind_null(stmt);

	db_bind_sha256(stmt, payment_hash);
	db_bind_u64(stmt, partid);

	db_exec_prepared_v2(take(stmt));
}

struct db_stmt *payments_first(struct wallet *wallet,
			       const enum wait_index *listindex,
			       u64 liststart,
			       const u32 *listlimit)
{
	struct db_stmt *stmt;

	if (listindex && *listindex == WAIT_INDEX_UPDATED) {
		stmt = db_prepare_v2(wallet->db, SQL("SELECT"
						     "  id"
						     ", updated_index"
						     ", status"
						     ", destination"
						     ", msatoshi"
						     ", payment_hash"
						     ", timestamp"
						     ", payment_preimage"
						     ", path_secrets"
						     ", route_nodes"
						     ", route_channels"
						     ", msatoshi_sent"
						     ", description"
						     ", bolt11"
						     ", paydescription"
						     ", failonionreply"
						     ", total_msat"
						     ", partid"
						     ", local_invreq_id"
						     ", groupid"
						     ", completed_at"
						     " FROM payments"
						     " WHERE updated_index >= ?"
						     " ORDER BY updated_index"
						     " LIMIT ?;"));
	} else {
		stmt = db_prepare_v2(wallet->db, SQL("SELECT"
						     "  id"
						     ", updated_index"
						     ", status"
						     ", destination"
						     ", msatoshi"
						     ", payment_hash"
						     ", timestamp"
						     ", payment_preimage"
						     ", path_secrets"
						     ", route_nodes"
						     ", route_channels"
						     ", msatoshi_sent"
						     ", description"
						     ", bolt11"
						     ", paydescription"
						     ", failonionreply"
						     ", total_msat"
						     ", partid"
						     ", local_invreq_id"
						     ", groupid"
						     ", completed_at"
						     " FROM payments"
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
	return payments_next(wallet, stmt);
}

struct db_stmt *payments_by_hash(struct wallet *wallet,
				 const struct sha256 *payment_hash)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(wallet->db, SQL("SELECT"
					     "  id"
					     ", updated_index"
					     ", status"
					     ", destination"
					     ", msatoshi"
					     ", payment_hash"
					     ", timestamp"
					     ", payment_preimage"
					     ", path_secrets"
					     ", route_nodes"
					     ", route_channels"
					     ", msatoshi_sent"
					     ", description"
					     ", bolt11"
					     ", paydescription"
					     ", failonionreply"
					     ", total_msat"
					     ", partid"
					     ", local_invreq_id"
					     ", groupid"
					     ", completed_at"
					     " FROM payments"
					     " WHERE"
					     "  payment_hash = ?"
					     " ORDER BY id;"));
	db_bind_sha256(stmt, payment_hash);
	db_query_prepared(stmt);
	return payments_next(wallet, stmt);
}

struct db_stmt *payments_by_label(struct wallet *wallet,
				  const struct json_escape *label)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(wallet->db, SQL("SELECT"
					     "  id"
					     ", updated_index"
					     ", status"
					     ", destination"
					     ", msatoshi"
					     ", payment_hash"
					     ", timestamp"
					     ", payment_preimage"
					     ", path_secrets"
					     ", route_nodes"
					     ", route_channels"
					     ", msatoshi_sent"
					     ", description"
					     ", bolt11"
					     ", paydescription"
					     ", failonionreply"
					     ", total_msat"
					     ", partid"
					     ", local_invreq_id"
					     ", groupid"
					     ", completed_at"
					     " FROM payments"
					     " WHERE"
					     /* label is called "description" in db */
					     "  description = ?;"));
	db_bind_json_escape(stmt, label);
	db_query_prepared(stmt);
	return payments_next(wallet, stmt);
}

struct db_stmt *payments_by_status(struct wallet *wallet,
				   enum payment_status status,
				   const enum wait_index *listindex,
				   u64 liststart,
				   const u32 *listlimit)
{
	struct db_stmt *stmt;

	if (listindex && *listindex == WAIT_INDEX_UPDATED) {
		stmt = db_prepare_v2(wallet->db, SQL("SELECT"
						     "  id"
						     ", updated_index"
						     ", status"
						     ", destination"
						     ", msatoshi"
						     ", payment_hash"
						     ", timestamp"
						     ", payment_preimage"
						     ", path_secrets"
						     ", route_nodes"
						     ", route_channels"
						     ", msatoshi_sent"
						     ", description"
						     ", bolt11"
						     ", paydescription"
						     ", failonionreply"
						     ", total_msat"
						     ", partid"
						     ", local_invreq_id"
						     ", groupid"
						     ", completed_at"
						     " FROM payments"
						     " WHERE"
						     "  status = ?"
						     " AND"
						     "  updated_index >= ?"
						     " ORDER BY updated_index"
						     " LIMIT ?;"));
	} else {
		stmt = db_prepare_v2(wallet->db, SQL("SELECT"
						     "  id"
						     ", updated_index"
						     ", status"
						     ", destination"
						     ", msatoshi"
						     ", payment_hash"
						     ", timestamp"
						     ", payment_preimage"
						     ", path_secrets"
						     ", route_nodes"
						     ", route_channels"
						     ", msatoshi_sent"
						     ", description"
						     ", bolt11"
						     ", paydescription"
						     ", failonionreply"
						     ", total_msat"
						     ", partid"
						     ", local_invreq_id"
						     ", groupid"
						     ", completed_at"
						     " FROM payments"
						     " WHERE"
						     "  status = ?"
						     " AND"
						     "  id >= ?"
						     " ORDER BY id"
						     " LIMIT ?;"));
	}

	db_bind_int(stmt, payment_status_in_db(status));
	db_bind_u64(stmt, liststart);
	if (listlimit)
		db_bind_int(stmt, *listlimit);
	else
		db_bind_int(stmt, INT_MAX);
	db_query_prepared(stmt);
	return payments_next(wallet, stmt);
}

struct db_stmt *payments_by_invoice_request(struct wallet *wallet,
					    const struct sha256 *local_invreq_id)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(wallet->db, SQL("SELECT"
					     "  id"
					     ", updated_index"
					     ", status"
					     ", destination"
					     ", msatoshi"
					     ", payment_hash"
					     ", timestamp"
					     ", payment_preimage"
					     ", path_secrets"
					     ", route_nodes"
					     ", route_channels"
					     ", msatoshi_sent"
					     ", description"
					     ", bolt11"
					     ", paydescription"
					     ", failonionreply"
					     ", total_msat"
					     ", partid"
					     ", local_invreq_id"
					     ", groupid"
					     ", completed_at"
					     " FROM payments"
					     " WHERE local_invreq_id = ?;"));
	db_bind_sha256(stmt, local_invreq_id);
	db_query_prepared(stmt);

	return payments_next(wallet, stmt);
}

struct db_stmt *payments_next(struct wallet *w,
			      struct db_stmt *stmt)
{
	if (!db_step(stmt))
		return tal_free(stmt);

	return stmt;
}

void wallet_htlc_sigs_save(struct wallet *w, u64 channel_id,
			   const struct bitcoin_signature *htlc_sigs)
{
	/* Clear any existing HTLC sigs for this channel */
	struct db_stmt *stmt = db_prepare_v2(
	    w->db, SQL("DELETE FROM htlc_sigs WHERE channelid = ?"));
	db_bind_u64(stmt, channel_id);
	db_exec_prepared_v2(take(stmt));

	/* Now insert the new ones */
	for (size_t i=0; i<tal_count(htlc_sigs); i++) {
		stmt = db_prepare_v2(w->db,
				     SQL("INSERT INTO htlc_sigs (channelid, "
					 "signature) VALUES (?, ?)"));
		db_bind_u64(stmt, channel_id);
		db_bind_signature(stmt, &htlc_sigs[i].s);
		db_exec_prepared_v2(take(stmt));
	}
}

void wallet_htlc_sigs_add(struct wallet *w, u64 channel_id,
			  struct bitcoin_outpoint inflight_outpoint,
			  const struct bitcoin_signature *htlc_sigs)
{
	struct db_stmt *stmt;

	/* Now insert the new ones */
	for (size_t i=0; i<tal_count(htlc_sigs); i++) {
		stmt = db_prepare_v2(w->db,
				     SQL("INSERT INTO htlc_sigs (channelid,"
					 " inflight_tx_id, inflight_tx_outnum,"
					 " signature) VALUES (?, ?, ?, ?)"));
		db_bind_u64(stmt, channel_id);
		db_bind_txid(stmt, &inflight_outpoint.txid);
		db_bind_int(stmt, inflight_outpoint.n);
		db_bind_signature(stmt, &htlc_sigs[i].s);
		db_exec_prepared_v2(take(stmt));
	}
}

bool wallet_sanity_check(struct wallet *w)
{
	struct bitcoin_blkid chainhash;
	struct db_stmt *stmt = db_prepare_v2(
	    w->db, SQL("SELECT blobval FROM vars WHERE name='genesis_hash'"));
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		db_col_sha256d(stmt, "blobval", &chainhash.shad);
		tal_free(stmt);
		if (!bitcoin_blkid_eq(&chainhash,
				      &chainparams->genesis_blockhash)) {
			log_broken(w->log, "Wallet blockchain hash does not "
					   "match network blockchain hash: %s "
					   "!= %s. "
					   "Are you on the right network? "
					   "(--network={one of %s})",
				   fmt_bitcoin_blkid(w,
						  &chainhash),
				   fmt_bitcoin_blkid(w,
						  &chainparams->genesis_blockhash),
				   chainparams_get_network_names(tmpctx));
			return false;
		}
	} else {
		tal_free(stmt);
		/* Still a pristine wallet, claim it for the chain
		 * that we are running */
		stmt = db_prepare_v2(w->db, SQL("INSERT INTO vars (name, blobval) "
						"VALUES ('genesis_hash', ?);"));
		db_bind_sha256d(stmt, &chainparams->genesis_blockhash.shad);
		db_exec_prepared_v2(take(stmt));
	}

	stmt = db_prepare_v2(w->db,
			     SQL("SELECT blobval FROM vars WHERE name='node_id'"));
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		struct node_id id;
		db_col_node_id(stmt, "blobval", &id);
		tal_free(stmt);

		if (!node_id_eq(&id, &w->ld->id)) {
			log_broken(w->log, "Wallet node_id does not "
					   "match HSM: %s "
					   "!= %s. "
					   "Did your hsm_secret change?",
				   fmt_node_id(tmpctx, &id),
				   fmt_node_id(tmpctx,
						  &w->ld->id));
			return false;
		}
	} else {
		tal_free(stmt);
		/* Still a pristine wallet, claim it for the node_id we are now */
		stmt = db_prepare_v2(w->db, SQL("INSERT INTO vars (name, blobval) "
						"VALUES ('node_id', ?);"));
		db_bind_node_id(stmt, &w->ld->id);
		db_exec_prepared_v2(take(stmt));
	}
	return true;
}

/**
 * wallet_utxoset_prune -- Remove spent UTXO entries that are old
 */
static void wallet_utxoset_prune(struct wallet *w, const u32 blockheight)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(
	    w->db,
	    SQL("SELECT txid, outnum FROM utxoset WHERE spendheight < ?"));
	db_bind_int(stmt, blockheight - UTXO_PRUNE_DEPTH);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct bitcoin_outpoint outpoint;
		db_col_txid(stmt, "txid", &outpoint.txid);
		outpoint.n = db_col_int(stmt, "outnum");
		outpointfilter_remove(w->utxoset_outpoints, &outpoint);
	}
	tal_free(stmt);

	stmt = db_prepare_v2(w->db,
			     SQL("DELETE FROM utxoset WHERE spendheight < ?"));
	db_bind_int(stmt, blockheight - UTXO_PRUNE_DEPTH);
	db_exec_prepared_v2(take(stmt));
}

void wallet_block_add(struct wallet *w, struct block *b)
{
	struct db_stmt *stmt =
	    db_prepare_v2(w->db, SQL("INSERT INTO blocks "
				     "(height, hash, prev_hash) "
				     "VALUES (?, ?, ?);"));
	db_bind_int(stmt, b->height);
	db_bind_sha256d(stmt, &b->blkid.shad);
	if (b->prev) {
		db_bind_sha256d(stmt, &b->prev->blkid.shad);
	} else {
		db_bind_null(stmt);
	}
	db_exec_prepared_v2(take(stmt));

	/* Now cleanup UTXOs that we don't care about anymore */
	wallet_utxoset_prune(w, b->height);
}

void wallet_block_remove(struct wallet *w, struct block *b)
{
	struct db_stmt *stmt =
		db_prepare_v2(w->db, SQL("DELETE FROM blocks WHERE hash = ?"));
	db_bind_sha256d(stmt, &b->blkid.shad);
	db_exec_prepared_v2(take(stmt));

	/* Make sure that all descendants of the block are also deleted */
	stmt = db_prepare_v2(w->db,
			     SQL("SELECT * FROM blocks WHERE height >= ?;"));
	db_bind_int(stmt, b->height);
	db_query_prepared(stmt);
	assert(!db_step(stmt));
	tal_free(stmt);
}

void wallet_blocks_rollback(struct wallet *w, u32 height)
{
	struct db_stmt *stmt = db_prepare_v2(w->db, SQL("DELETE FROM blocks "
							"WHERE height > ?"));
	db_bind_int(stmt, height);
	db_exec_prepared_v2(take(stmt));
}

bool wallet_outpoint_spend(const tal_t *ctx, struct wallet *w, const u32 blockheight,
			   const struct bitcoin_outpoint *outpoint)
{
	struct db_stmt *stmt;
	bool our_spend;
	if (outpointfilter_matches(w->owned_outpoints, outpoint)) {
		stmt = db_prepare_v2(w->db, SQL("UPDATE outputs "
						"SET spend_height = ?, "
						" status = ? "
						"WHERE prev_out_tx = ?"
						" AND prev_out_index = ?"));

		db_bind_int(stmt, blockheight);
		db_bind_int(stmt, output_status_in_db(OUTPUT_STATE_SPENT));
		db_bind_txid(stmt, &outpoint->txid);
		db_bind_int(stmt, outpoint->n);

		db_exec_prepared_v2(take(stmt));

		our_spend = true;
	} else
		our_spend = false;

	if (outpointfilter_matches(w->utxoset_outpoints, outpoint)) {
		stmt = db_prepare_v2(w->db, SQL("UPDATE utxoset "
						"SET spendheight = ? "
						"WHERE txid = ?"
						" AND outnum = ?"));

		db_bind_int(stmt, blockheight);
		db_bind_txid(stmt, &outpoint->txid);
		db_bind_int(stmt, outpoint->n);
		db_exec_prepared_v2(stmt);
		tal_free(stmt);
	}
	return our_spend;
}

void wallet_utxoset_add(struct wallet *w,
			const struct bitcoin_outpoint *outpoint,
			const u32 blockheight, const u32 txindex,
			const u8 *scriptpubkey, size_t scriptpubkey_len,
			struct amount_sat sat)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("INSERT INTO utxoset ("
					" txid,"
					" outnum,"
					" blockheight,"
					" spendheight,"
					" txindex,"
					" scriptpubkey,"
					" satoshis"
					") VALUES(?, ?, ?, ?, ?, ?, ?);"));
	db_bind_txid(stmt, &outpoint->txid);
	db_bind_int(stmt, outpoint->n);
	db_bind_int(stmt, blockheight);
	db_bind_null(stmt);
	db_bind_int(stmt, txindex);
	db_bind_blob(stmt, scriptpubkey, scriptpubkey_len);
	db_bind_amount_sat(stmt, &sat);
	db_exec_prepared_v2(take(stmt));

	outpointfilter_add(w->utxoset_outpoints, outpoint);
}

void wallet_filteredblock_add(struct wallet *w, const struct filteredblock *fb)
{
	struct db_stmt *stmt;
	if (wallet_have_block(w, fb->height))
		return;

	stmt = db_prepare_v2(w->db, SQL("INSERT INTO blocks "
					"(height, hash, prev_hash) "
					"VALUES (?, ?, ?);"));
	db_bind_int(stmt, fb->height);
	db_bind_sha256d(stmt, &fb->id.shad);
	db_bind_sha256d(stmt, &fb->prev_hash.shad);
	db_exec_prepared_v2(take(stmt));

	for (size_t i = 0; i < tal_count(fb->outpoints); i++) {
		struct filteredblock_outpoint *o = fb->outpoints[i];
		stmt =
		    db_prepare_v2(w->db, SQL("INSERT INTO utxoset ("
					     " txid,"
					     " outnum,"
					     " blockheight,"
					     " spendheight,"
					     " txindex,"
					     " scriptpubkey,"
					     " satoshis"
					     ") VALUES(?, ?, ?, ?, ?, ?, ?);"));
		db_bind_txid(stmt, &o->outpoint.txid);
		db_bind_int(stmt, o->outpoint.n);
		db_bind_int(stmt, fb->height);
		db_bind_null(stmt);
		db_bind_int(stmt, o->txindex);
		db_bind_talarr(stmt, o->scriptPubKey);
		db_bind_amount_sat(stmt, &o->amount);
		db_exec_prepared_v2(take(stmt));

		outpointfilter_add(w->utxoset_outpoints, &o->outpoint);
	}
}

bool wallet_have_block(struct wallet *w, u32 blockheight)
{
	bool result;
	struct db_stmt *stmt = db_prepare_v2(
	    w->db, SQL("SELECT height FROM blocks WHERE height = ?"));
	db_bind_int(stmt, blockheight);
	db_query_prepared(stmt);
	result = db_step(stmt);
	if (result)
		db_col_ignore(stmt, "height");
	tal_free(stmt);
	return result;
}

struct outpoint *wallet_outpoint_for_scid(const tal_t *ctx, struct wallet *w,
					  struct short_channel_id scid)
{
	struct db_stmt *stmt;
	struct outpoint *op;
	stmt = db_prepare_v2(w->db, SQL("SELECT"
					" txid,"
					" spendheight,"
					" scriptpubkey,"
					" satoshis "
					"FROM utxoset "
					"WHERE blockheight = ?"
					" AND txindex = ?"
					" AND outnum = ?"
					" AND spendheight IS NULL"));
	db_bind_int(stmt, short_channel_id_blocknum(scid));
	db_bind_int(stmt, short_channel_id_txnum(scid));
	db_bind_int(stmt, short_channel_id_outnum(scid));
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	op = tal(ctx, struct outpoint);
	op->blockheight = short_channel_id_blocknum(scid);
	op->txindex = short_channel_id_txnum(scid);
	op->outpoint.n = short_channel_id_outnum(scid);
	db_col_txid(stmt, "txid", &op->outpoint.txid);
	if (db_col_is_null(stmt, "spendheight"))
		op->spendheight = 0;
	else
		op->spendheight = db_col_int(stmt, "spendheight");
	op->scriptpubkey = db_col_arr(op, stmt, "scriptpubkey", u8);
	op->sat = db_col_amount_sat(stmt, "satoshis");
	tal_free(stmt);

	return op;
}

/* Turns "SELECT blockheight, txindex, outnum" into scids */
static const struct short_channel_id *db_scids(const tal_t *ctx,
					       struct db_stmt *stmt STEALS)
{
	struct short_channel_id *res = tal_arr(ctx, struct short_channel_id, 0);

	while (db_step(stmt)) {
		struct short_channel_id scid;
		u64 blocknum, txnum, outnum;
		bool ok;
		blocknum = db_col_int(stmt, "blockheight");
		txnum = db_col_int(stmt, "txindex");
		outnum = db_col_int(stmt, "outnum");
		ok = mk_short_channel_id(&scid, blocknum, txnum, outnum);

		assert(ok);
		tal_arr_expand(&res, scid);
	}
	tal_free(stmt);
	return res;
}

const struct short_channel_id *
wallet_utxoset_get_spent(const tal_t *ctx, struct wallet *w,
			 u32 blockheight)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db, SQL("SELECT"
					" blockheight,"
					" txindex,"
					" outnum "
					"FROM utxoset "
					"WHERE spendheight = ?"));
	db_bind_int(stmt, blockheight);
	db_query_prepared(stmt);

	return db_scids(ctx, stmt);
}

const struct short_channel_id *
wallet_utxoset_get_created(const tal_t *ctx, struct wallet *w,
			   u32 blockheight)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db, SQL("SELECT"
					" blockheight,"
					" txindex,"
					" outnum "
					"FROM utxoset "
					"WHERE blockheight = ?"));
	db_bind_int(stmt, blockheight);
	db_query_prepared(stmt);

	return db_scids(ctx, stmt);
}

void wallet_transaction_add(struct wallet *w, const struct wally_tx *tx,
			    const u32 blockheight, const u32 txindex)
{
	struct bitcoin_txid txid;
	struct db_stmt *stmt = db_prepare_v2(
	    w->db, SQL("SELECT blockheight FROM transactions WHERE id=?"));

	wally_txid(tx, &txid);
	db_bind_txid(stmt, &txid);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		/* This transaction is still unknown, insert */
		stmt = db_prepare_v2(w->db,
				     SQL("INSERT INTO transactions ("
					 "  id"
					 ", blockheight"
					 ", txindex"
					 ", rawtx) VALUES (?, ?, ?, ?);"));
		db_bind_txid(stmt, &txid);
		if (blockheight) {
			db_bind_int(stmt, blockheight);
			db_bind_int(stmt, txindex);
		} else {
			db_bind_null(stmt);
			db_bind_null(stmt);
		}
		db_bind_tx(stmt, tx);
		db_exec_prepared_v2(take(stmt));
	} else {
		db_col_ignore(stmt, "blockheight");
		tal_free(stmt);

		if (blockheight) {
			/* We know about the transaction, update */
			stmt = db_prepare_v2(w->db,
					     SQL("UPDATE transactions "
						 "SET blockheight = ?, txindex = ? "
						 "WHERE id = ?"));
			db_bind_int(stmt, blockheight);
			db_bind_int(stmt, txindex);
			db_bind_txid(stmt, &txid);
			db_exec_prepared_v2(take(stmt));
		}
	}
}

static void wallet_annotation_add(struct wallet *w, const struct bitcoin_txid *txid, int num,
				  enum wallet_tx_annotation_type annotation_type, enum wallet_tx_type type, u64 channel)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(
		w->db,SQL("INSERT INTO transaction_annotations "
			  "(txid, idx, location, type, channel) "
			  "VALUES (?, ?, ?, ?, ?) ON CONFLICT(txid,idx) DO NOTHING;"));

	db_bind_txid(stmt, txid);
	db_bind_int(stmt, num);
	db_bind_int(stmt, annotation_type);
	db_bind_int(stmt, type);
	if (channel != 0)
		db_bind_u64(stmt, channel);
	else
		db_bind_null(stmt);
	db_exec_prepared_v2(take(stmt));
}

void wallet_annotate_txout(struct wallet *w,
			   const struct bitcoin_outpoint *outpoint,
			   enum wallet_tx_type type, u64 channel)
{
	wallet_annotation_add(w, &outpoint->txid, outpoint->n,
			      OUTPUT_ANNOTATION, type, channel);
}

void wallet_annotate_txin(struct wallet *w, const struct bitcoin_txid *txid,
			  int innum, enum wallet_tx_type type, u64 channel)
{
	wallet_annotation_add(w, txid, innum, INPUT_ANNOTATION, type, channel);
}

struct bitcoin_tx *wallet_transaction_get(const tal_t *ctx, struct wallet *w,
					  const struct bitcoin_txid *txid)
{
	struct bitcoin_tx *tx;
	struct db_stmt *stmt = db_prepare_v2(
	    w->db, SQL("SELECT rawtx FROM transactions WHERE id=?"));
	db_bind_txid(stmt, txid);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	if (!db_col_is_null(stmt, "rawtx"))
		tx = db_col_tx(ctx, stmt, "rawtx");
	else
		tx = NULL;

	tal_free(stmt);
	return tx;
}

u32 wallet_transaction_height(struct wallet *w, const struct bitcoin_txid *txid)
{
	u32 blockheight;
	struct db_stmt *stmt = db_prepare_v2(
	    w->db, SQL("SELECT blockheight FROM transactions WHERE id=?"));
	db_bind_txid(stmt, txid);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return 0;
	}

	if (!db_col_is_null(stmt, "blockheight"))
		blockheight = db_col_int(stmt, "blockheight");
	else
		blockheight = 0;
	tal_free(stmt);
	return blockheight;
}

struct txlocator *wallet_transaction_locate(const tal_t *ctx, struct wallet *w,
					    const struct bitcoin_txid *txid)
{
	struct txlocator *loc;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(
		w->db, SQL("SELECT blockheight, txindex FROM transactions WHERE id=?"));
	db_bind_txid(stmt, txid);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	if (db_col_is_null(stmt, "blockheight")) {
		db_col_ignore(stmt, "txindex");
		loc = NULL;
	} else {
		loc = tal(ctx, struct txlocator);
		loc->blkheight = db_col_int(stmt, "blockheight");
		loc->index = db_col_int(stmt, "txindex");
	}
	tal_free(stmt);
	return loc;
}

struct bitcoin_txid *wallet_transactions_by_height(const tal_t *ctx,
						   struct wallet *w,
						   const u32 blockheight)
{
	struct db_stmt *stmt;
	struct bitcoin_txid *txids = tal_arr(ctx, struct bitcoin_txid, 0);
	int count = 0;
	stmt = db_prepare_v2(
	    w->db, SQL("SELECT id FROM transactions WHERE blockheight=?"));
	db_bind_int(stmt, blockheight);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		count++;
		tal_resize(&txids, count);
		db_col_txid(stmt, "id", &txids[count-1]);
	}
	tal_free(stmt);

	return txids;
}

void wallet_channeltxs_add(struct wallet *w, struct channel *chan,
			   const int type, const struct bitcoin_txid *txid,
			   const u32 input_num, const u32 blockheight)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db, SQL("INSERT INTO channeltxs ("
					"  channel_id"
					", type"
					", transaction_id"
					", input_num"
					", blockheight"
					") VALUES (?, ?, ?, ?, ?);"));
	db_bind_int(stmt, chan->dbid);
	db_bind_int(stmt, type);
	db_bind_sha256(stmt, &txid->shad.sha);
	db_bind_int(stmt, input_num);
	db_bind_int(stmt, blockheight);

	db_exec_prepared_v2(take(stmt));
}

u32 *wallet_onchaind_channels(const tal_t *ctx, struct wallet *w)
{
	struct db_stmt *stmt;
	size_t count = 0;
	u32 *channel_ids = tal_arr(ctx, u32, 0);
	stmt = db_prepare_v2(
	    w->db,
	    SQL("SELECT DISTINCT(channel_id) FROM channeltxs WHERE type = ?;"));
	db_bind_int(stmt, WIRE_ONCHAIND_INIT);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		count++;
		tal_resize(&channel_ids, count);
		channel_ids[count-1] = db_col_u64(stmt, "DISTINCT(channel_id)");
	}
	tal_free(stmt);

	return channel_ids;
}

struct channeltx *wallet_channeltxs_get(const tal_t *ctx, struct wallet *w,
					u32 channel_id)
{
	struct db_stmt *stmt;
	size_t count = 0;
	struct channeltx *res = tal_arr(ctx, struct channeltx, 0);
	stmt = db_prepare_v2(
	    w->db, SQL("SELECT"
		       "  c.type"
		       ", c.blockheight"
		       ", t.rawtx"
		       ", c.input_num"
		       ", c.blockheight - t.blockheight + 1 AS depth"
		       ", t.id as txid "
		       "FROM channeltxs c "
		       "JOIN transactions t ON t.id = c.transaction_id "
		       "WHERE c.channel_id = ? "
		       "ORDER BY c.id ASC;"));
	db_bind_int(stmt, channel_id);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		count++;
		tal_resize(&res, count);

		res[count-1].channel_id = channel_id;
		res[count-1].type = db_col_int(stmt, "c.type");
		res[count-1].blockheight = db_col_int(stmt, "c.blockheight");
		res[count-1].tx = db_col_tx(ctx, stmt, "t.rawtx");
		res[count-1].input_num = db_col_int(stmt, "c.input_num");
		res[count-1].depth = db_col_int(stmt, "depth");
		db_col_txid(stmt, "txid", &res[count-1].txid);
	}
	tal_free(stmt);
	return res;
}

static bool wallet_forwarded_payment_update(struct wallet *w,
					    const struct htlc_in *in,
					    const struct htlc_out *out,
					    enum forward_status state,
					    enum onion_wire failcode,
					    struct timeabs *resolved_time,
					    enum forward_style forward_style)
{
	struct db_stmt *stmt;
	bool changed;

	/* We update based solely on the htlc_in since an HTLC cannot be
	 * associated with more than one forwarded payment. This saves us from
	 * having to have two versions of the update statement (one with and
	 * one without the htlc_out restriction).*/
	stmt = db_prepare_v2(w->db,
			     SQL("UPDATE forwards SET"
				 "  updated_index=?"
				 ", in_msatoshi=?"
				 ", out_msatoshi=?"
				 ", state=?"
				 ", resolved_time=?"
				 ", failcode=?"
				 ", forward_style=?"
				 " WHERE in_htlc_id=? AND in_channel_scid=?"));
	/* This may not work so don't increment index yet! */
	db_bind_u64(stmt, w->ld->indexes[WAIT_SUBSYSTEM_FORWARD].i[WAIT_INDEX_UPDATED] + 1);
	db_bind_amount_msat(stmt, &in->msat);

	if (out) {
		db_bind_amount_msat(stmt, &out->msat);
	} else {
		db_bind_null(stmt);
	}

	db_bind_int(stmt, wallet_forward_status_in_db(state));

	if (resolved_time != NULL) {
		db_bind_timeabs(stmt, *resolved_time);
	} else {
		db_bind_null(stmt);
	}

	if (failcode != 0) {
		assert(state == FORWARD_FAILED || state == FORWARD_LOCAL_FAILED);
		db_bind_int(stmt, (int)failcode);
	} else {
		db_bind_null(stmt);
	}

	/* This can happen for malformed onions, reload from db. */
	if (forward_style == FORWARD_STYLE_UNKNOWN)
		db_bind_null(stmt);
	else
		db_bind_int(stmt, forward_style_in_db(forward_style));
	db_bind_u64(stmt, in->key.id);
	db_bind_short_channel_id(stmt, channel_scid_or_local_alias(in->key.channel));
	db_exec_prepared_v2(stmt);
	changed = db_count_changes(stmt) != 0;
	tal_free(stmt);

	return changed;
}

void wallet_forwarded_payment_add(struct wallet *w, const struct htlc_in *in,
				  enum forward_style forward_style,
				  const struct short_channel_id *scid_out,
				  const struct htlc_out *out,
				  enum forward_status state,
				  enum onion_wire failcode)
{
	struct db_stmt *stmt;
	struct timeabs *resolved_time;
	u64 id, updated_index;

	if (state == FORWARD_SETTLED || state == FORWARD_FAILED) {
		resolved_time = tal(tmpctx, struct timeabs);
		*resolved_time = time_now();
	} else {
		resolved_time = NULL;
	}

	if (wallet_forwarded_payment_update(w, in, out, state, failcode, resolved_time, forward_style)) {
		updated_index =
			forward_index_update_status(w->ld,
						    state,
						    channel_scid_or_local_alias(in->key.channel),
						    in->key.id,
						    in->msat,
						    scid_out);
		id = 0;
		goto notify;
	}

	updated_index = 0;
	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO forwards ("
				 "  rowid"
				 ", in_htlc_id"
				 ", out_htlc_id"
				 ", in_channel_scid"
				 ", out_channel_scid"
				 ", in_msatoshi"
				 ", out_msatoshi"
				 ", state"
				 ", received_time"
				 ", resolved_time"
				 ", failcode"
				 ", forward_style"
				 ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));
	id = forward_index_created(w->ld,
				   state,
				   channel_scid_or_local_alias(in->key.channel),
				   in->key.id,
				   in->msat,
				   scid_out);

	db_bind_u64(stmt, id);
	db_bind_u64(stmt, in->key.id);

	/* FORWARD_LOCAL_FAILED may occur before we get htlc_out */
	if (!out || !scid_out) {
 		assert(failcode != 0);
 		assert(state == FORWARD_LOCAL_FAILED);
	}

	if (out)
		db_bind_u64(stmt, out->key.id);
	else
		db_bind_null(stmt);

	/* We use the LOCAL alias, since that's under our control, and
	 * we keep it stable, whereas the REMOTE alias is likely what
	 * the sender used to specify the channel, but that's under
	 * control of the remote end. */
	assert(in->key.channel->scid != NULL || in->key.channel->alias[LOCAL]);
	db_bind_short_channel_id(stmt, channel_scid_or_local_alias(in->key.channel));

	if (scid_out)
		db_bind_short_channel_id(stmt, *scid_out);
	else
		db_bind_null(stmt);
	db_bind_amount_msat(stmt, &in->msat);
	if (out)
		db_bind_amount_msat(stmt, &out->msat);
	else
		db_bind_null(stmt);

	db_bind_int(stmt, wallet_forward_status_in_db(state));
	db_bind_timeabs(stmt, in->received_time);

	if (resolved_time != NULL)
		db_bind_timeabs(stmt, *resolved_time);
	else
		db_bind_null(stmt);

	if (failcode != 0) {
		assert(state == FORWARD_FAILED || state == FORWARD_LOCAL_FAILED);
		db_bind_int(stmt, (int)failcode);
	} else {
		db_bind_null(stmt);
	}
	/* This can happen for malformed onions, reload from db! */
	if (forward_style == FORWARD_STYLE_UNKNOWN)
		db_bind_null(stmt);
	else
		db_bind_int(stmt, forward_style_in_db(forward_style));

	db_exec_prepared_v2(take(stmt));

notify:
	notify_forward_event(w->ld, in, scid_out, out ? &out->msat : NULL,
			     state, failcode, resolved_time, forward_style,
			     id, updated_index);
}

struct amount_msat wallet_total_forward_fees(struct wallet *w)
{
	struct db_stmt *stmt;
	struct amount_msat total, deleted;
	bool res;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					" CAST(COALESCE(SUM(in_msatoshi - out_msatoshi), 0) AS BIGINT)"
					" FROM forwards "
					"WHERE state = ?;"));
	db_bind_int(stmt, wallet_forward_status_in_db(FORWARD_SETTLED));
	db_query_prepared(stmt);

	res = db_step(stmt);
	assert(res);

	total = db_col_amount_msat(stmt, "CAST(COALESCE(SUM(in_msatoshi - out_msatoshi), 0) AS BIGINT)");
	tal_free(stmt);

	deleted = amount_msat(db_get_intvar(w->db, "deleted_forward_fees", 0));
	if (!amount_msat_add(&total, total, deleted))
		db_fatal(w->db, "Adding forward fees %s + %s overflowed",
			 fmt_amount_msat(tmpctx, total),
			 fmt_amount_msat(tmpctx, deleted));

	return total;
}

const struct forwarding *wallet_forwarded_payments_get(const tal_t *ctx,
						       struct wallet *w,
						       enum forward_status status,
						       const struct short_channel_id *chan_in,
						       const struct short_channel_id *chan_out,
						       const enum wait_index *listindex,
						       u64 liststart,
						       const u32 *listlimit)
{
	struct forwarding *results = tal_arr(ctx, struct forwarding, 0);
	size_t count = 0;
	struct db_stmt *stmt;

	// placeholder for any parameter, the value doesn't matter because it's discarded by sql
	const int any = -1;

	/* We don't support start/limits with this */
	if (chan_in || chan_out) {
		stmt = db_prepare_v2(
			w->db,
			SQL("SELECT"
			    "  state"
			    ", in_msatoshi"
			    ", out_msatoshi"
			    ", in_channel_scid"
			    ", out_channel_scid"
			    ", in_htlc_id"
			    ", out_htlc_id"
			    ", received_time"
			    ", resolved_time"
			    ", failcode "
			    ", forward_style "
			    ", rowid "
			    ", updated_index "
			    "FROM forwards "
			    "WHERE (1 = ? OR state = ?) AND "
			    "(1 = ? OR in_channel_scid = ?) AND "
			    "(1 = ? OR out_channel_scid = ?)"));

		if (status == FORWARD_ANY) {
			// any status
			db_bind_int(stmt, 1);
			db_bind_int(stmt, any);
		} else {
			// specific forward status
			db_bind_int(stmt, 0);
			db_bind_int(stmt, status);
		}

		if (chan_in) {
			// specific in_channel
			db_bind_int(stmt, 0);
			db_bind_short_channel_id(stmt, *chan_in);
		} else {
			// any in_channel
			db_bind_int(stmt, 1);
			db_bind_int(stmt, any);
		}

		if (chan_out) {
			// specific out_channel
			db_bind_int(stmt, 0);
			db_bind_short_channel_id(stmt, *chan_out);
		} else {
			// any out_channel
			db_bind_int(stmt, 1);
			db_bind_int(stmt, any);
		}
	} else if (listindex && *listindex == WAIT_INDEX_UPDATED) {
		stmt = db_prepare_v2(
			w->db,
			SQL("SELECT"
			    "  state"
			    ", in_msatoshi"
			    ", out_msatoshi"
			    ", in_channel_scid"
			    ", out_channel_scid"
			    ", in_htlc_id"
			    ", out_htlc_id"
			    ", received_time"
			    ", resolved_time"
			    ", failcode "
			    ", forward_style "
			    ", rowid "
			    ", updated_index "
			    "FROM forwards "
			    " WHERE"
			    "  (1 = ? OR state = ?)"
			    " AND"
			    "  updated_index >= ?"
			    " ORDER BY updated_index"
			    " LIMIT ?;"));
		if (status == FORWARD_ANY) {
			// any status
			db_bind_int(stmt, 1);
			db_bind_int(stmt, any);
		} else {
			// specific forward status
			db_bind_int(stmt, 0);
			db_bind_int(stmt, status);
		}
		db_bind_u64(stmt, liststart);
		if (listlimit)
			db_bind_int(stmt, *listlimit);
		else
			db_bind_int(stmt, INT_MAX);
	} else {
		stmt = db_prepare_v2(
			w->db,
			SQL("SELECT"
			    "  state"
			    ", in_msatoshi"
			    ", out_msatoshi"
			    ", in_channel_scid"
			    ", out_channel_scid"
			    ", in_htlc_id"
			    ", out_htlc_id"
			    ", received_time"
			    ", resolved_time"
			    ", failcode "
			    ", forward_style "
			    ", rowid "
			    ", updated_index "
			    "FROM forwards "
			    " WHERE"
			    "  (1 = ? OR state = ?)"
			    " AND"
			    "  rowid >= ?"
			    " ORDER BY rowid"
			    " LIMIT ?;"));
		if (status == FORWARD_ANY) {
			// any status
			db_bind_int(stmt, 1);
			db_bind_int(stmt, any);
		} else {
			// specific forward status
			db_bind_int(stmt, 0);
			db_bind_int(stmt, status);
		}
		db_bind_u64(stmt, liststart);
		if (listlimit)
			db_bind_int(stmt, *listlimit);
		else
			db_bind_int(stmt, INT_MAX);
	}
	db_query_prepared(stmt);

	for (count=0; db_step(stmt); count++) {
		tal_resize(&results, count+1);
		struct forwarding *cur = &results[count];
		cur->status = db_col_int(stmt, "state");
		cur->msat_in = db_col_amount_msat(stmt, "in_msatoshi");
		cur->created_index = db_col_u64(stmt, "rowid");
		cur->updated_index = db_col_u64(stmt, "updated_index");

		if (!db_col_is_null(stmt, "out_msatoshi")) {
			cur->msat_out = db_col_amount_msat(stmt, "out_msatoshi");
			if (!amount_msat_sub(&cur->fee, cur->msat_in, cur->msat_out)) {
				log_broken(w->log, "Forwarded in %s less than out %s!",
					   fmt_amount_msat(tmpctx, cur->msat_in),
					   fmt_amount_msat(tmpctx, cur->msat_out));
				cur->fee = AMOUNT_MSAT(0);
			}
		}
		else {
			assert(cur->status == FORWARD_LOCAL_FAILED);
			cur->msat_out = AMOUNT_MSAT(0);
			/* For this case, this forward_payment doesn't have out channel,
			 * so the fee should be set as 0.*/
			cur->fee =  AMOUNT_MSAT(0);
		}

		cur->channel_in = db_col_short_channel_id(stmt, "in_channel_scid");

#ifdef COMPAT_V0121
		/* This can happen due to migration! */
		if (!db_col_is_null(stmt, "in_htlc_id"))
			cur->htlc_id_in = db_col_u64(stmt, "in_htlc_id");
		else
			cur->htlc_id_in = HTLC_INVALID_ID;
#else
		cur->htlc_id_in = db_col_u64(stmt, "in_htlc_id");
#endif

		if (!db_col_is_null(stmt, "out_channel_scid")) {
			cur->channel_out = db_col_short_channel_id(stmt, "out_channel_scid");
		} else {
			assert(cur->status == FORWARD_LOCAL_FAILED);
			cur->channel_out.u64 = 0;
		}
		if (!db_col_is_null(stmt, "out_htlc_id")) {
			cur->htlc_id_out = tal(results, u64);
			*cur->htlc_id_out = db_col_u64(stmt, "out_htlc_id");
		} else
			cur->htlc_id_out = NULL;

		cur->received_time = db_col_timeabs(stmt, "received_time");

		if (!db_col_is_null(stmt, "resolved_time")) {
			cur->resolved_time = tal(ctx, struct timeabs);
			*cur->resolved_time
				= db_col_timeabs(stmt, "resolved_time");
		} else {
			cur->resolved_time = NULL;
		}

		if (!db_col_is_null(stmt, "failcode")) {
			assert(cur->status == FORWARD_FAILED ||
			       cur->status == FORWARD_LOCAL_FAILED);
			cur->failcode = db_col_int(stmt, "failcode");
		} else {
			cur->failcode = 0;
		}
		if (db_col_is_null(stmt, "forward_style")) {
			cur->forward_style = FORWARD_STYLE_UNKNOWN;
		} else {
			cur->forward_style
				= forward_style_in_db(db_col_int(stmt, "forward_style"));
		}
	}
	tal_free(stmt);
	return results;
}

bool wallet_forward_delete(struct wallet *w,
			   struct short_channel_id chan_in,
			   const u64 *htlc_id,
			   enum forward_status state)
{
	struct db_stmt *stmt;
	bool changed;

	/* When deleting settled ones, we have to add to deleted_forward_fees! */
	if (state == FORWARD_SETTLED) {
		/* Of course, it might not be settled: don't add if they're wrong! */
		if (htlc_id) {
			stmt = db_prepare_v2(w->db, SQL("SELECT"
							" CAST(COALESCE(SUM(in_msatoshi - out_msatoshi), 0) AS BIGINT)"
							" FROM forwards "
							" WHERE in_channel_scid = ?"
							" AND in_htlc_id = ?"
							" AND state = ?;"));
			db_bind_short_channel_id(stmt, chan_in);
			db_bind_u64(stmt, *htlc_id);
			db_bind_int(stmt, wallet_forward_status_in_db(FORWARD_SETTLED));
		} else {
			stmt = db_prepare_v2(w->db, SQL("SELECT"
							" CAST(COALESCE(SUM(in_msatoshi - out_msatoshi), 0) AS BIGINT)"
							" FROM forwards "
							" WHERE in_channel_scid = ?"
							" AND in_htlc_id IS NULL"
							" AND state = ?;"));
			db_bind_short_channel_id(stmt, chan_in);
			db_bind_int(stmt, wallet_forward_status_in_db(FORWARD_SETTLED));
		}
		db_query_prepared(stmt);

		if (db_step(stmt)) {
			struct amount_msat deleted;

			deleted = db_col_amount_msat(stmt, "CAST(COALESCE(SUM(in_msatoshi - out_msatoshi), 0) AS BIGINT)");
			deleted.millisatoshis += /* Raw: db access */
				db_get_intvar(w->db, "deleted_forward_fees", 0);
			db_set_intvar(w->db, "deleted_forward_fees",
				      deleted.millisatoshis); /* Raw: db access */
		}
		tal_free(stmt);
	}

	if (htlc_id) {
		stmt = db_prepare_v2(w->db,
				     SQL("DELETE FROM forwards"
					 " WHERE in_channel_scid = ?"
					 " AND in_htlc_id = ?"
					 " AND state = ?"));
		db_bind_short_channel_id(stmt, chan_in);
		db_bind_u64(stmt, *htlc_id);
		db_bind_int(stmt, wallet_forward_status_in_db(state));
	} else {
		stmt = db_prepare_v2(w->db,
				     SQL("DELETE FROM forwards"
					 " WHERE in_channel_scid = ?"
					 " AND in_htlc_id IS NULL"
					 " AND state = ?"));
		db_bind_short_channel_id(stmt, chan_in);
		db_bind_int(stmt, wallet_forward_status_in_db(state));
	}
	db_exec_prepared_v2(stmt);
	changed = db_count_changes(stmt) != 0;
	tal_free(stmt);

	if (changed) {
		/* FIXME: We don't set in->msat or out here, since that would
		 * need an extra lookup */
		forward_index_deleted(w->ld,
				      state,
				      chan_in,
				      htlc_id ? *htlc_id : HTLC_INVALID_ID,
				      NULL, NULL);
	}

	return changed;
}

struct wallet_transaction *wallet_transactions_get(const tal_t *ctx, struct wallet *w)
{
	struct db_stmt *stmt;
	struct wallet_transaction *txs = tal_arr(ctx, struct wallet_transaction, 0);

	stmt = db_prepare_v2(
	    w->db,
	    SQL("SELECT"
		"  t.id"
		", t.rawtx"
		", t.blockheight"
		", t.txindex"
		" FROM"
		"  transactions t LEFT JOIN"
		"  channels c ON (t.channel_id = c.id) "
		"ORDER BY t.blockheight, t.txindex ASC"));
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct wallet_transaction *cur;

		tal_resize(&txs, tal_count(txs) + 1);
		cur = &txs[tal_count(txs) - 1];
		db_col_txid(stmt, "t.id", &cur->id);
		cur->tx = db_col_tx(txs, stmt, "t.rawtx");
		cur->rawtx = db_col_arr(txs, stmt, "t.rawtx", u8);
		if (!db_col_is_null(stmt, "t.blockheight")) {
			cur->blockheight = db_col_int(stmt, "t.blockheight");
			if (!db_col_is_null(stmt, "t.txindex")) {
				cur->txindex = db_col_int(stmt, "t.txindex");
			} else {
				cur->txindex = 0;
			}
		} else {
			db_col_ignore(stmt, "t.txindex");
			cur->blockheight = 0;
			cur->txindex = 0;
		}
	}
	tal_free(stmt);
	return txs;
}

void wallet_penalty_base_add(struct wallet *w, u64 chan_id,
			     const struct penalty_base *pb)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO penalty_bases ("
				 "  channel_id"
				 ", commitnum"
				 ", txid"
				 ", outnum"
				 ", amount"
				 ") VALUES (?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, chan_id);
	db_bind_u64(stmt, pb->commitment_num);
	db_bind_txid(stmt, &pb->txid);
	db_bind_int(stmt, pb->outnum);
	db_bind_amount_sat(stmt, &pb->amount);

	db_exec_prepared_v2(take(stmt));
}

struct penalty_base *wallet_penalty_base_load_for_channel(const tal_t *ctx,
							  struct wallet *w,
							  u64 chan_id)
{
	struct db_stmt *stmt;
	struct penalty_base *res = tal_arr(ctx, struct penalty_base, 0);
	stmt = db_prepare_v2(
		w->db,
		SQL("SELECT commitnum, txid, outnum, amount "
		    "FROM penalty_bases "
		    "WHERE channel_id = ?"));

	db_bind_u64(stmt, chan_id);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct penalty_base pb;
		pb.commitment_num = db_col_u64(stmt, "commitnum");
		db_col_txid(stmt, "txid", &pb.txid);
		pb.outnum = db_col_int(stmt, "outnum");
		pb.amount = db_col_amount_sat(stmt, "amount");
		tal_arr_expand(&res, pb);
	}
	tal_free(stmt);
	return res;
}

void wallet_penalty_base_delete(struct wallet *w, u64 chan_id, u64 commitnum)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(
		w->db,
		SQL("DELETE FROM penalty_bases "
		    "WHERE channel_id = ? AND commitnum = ?"));
	db_bind_u64(stmt, chan_id);
	db_bind_u64(stmt, commitnum);
	db_exec_prepared_v2(take(stmt));
}

bool wallet_offer_create(struct wallet *w,
			 const struct sha256 *offer_id,
			 const char *bolt12,
			 const struct json_escape *label,
			 enum offer_status status)
{
	struct db_stmt *stmt;

	assert(offer_status_active(status));

	/* Test if already exists. */
	stmt = db_prepare_v2(w->db, SQL("SELECT 1"
					"  FROM offers"
					" WHERE offer_id = ?;"));
	db_bind_sha256(stmt, offer_id);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		db_col_ignore(stmt, "1");
		tal_free(stmt);
		return false;
	}
	tal_free(stmt);

	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO offers ("
				 "  offer_id"
				 ", bolt12"
				 ", label"
				 ", status"
				 ") VALUES (?, ?, ?, ?);"));

	db_bind_sha256(stmt, offer_id);
	db_bind_text(stmt, bolt12);
	if (label)
		db_bind_json_escape(stmt, label);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, offer_status_in_db(status));
	db_exec_prepared_v2(take(stmt));
	return true;
}

char *wallet_offer_find(const tal_t *ctx,
			struct wallet *w,
			const struct sha256 *offer_id,
			const struct json_escape **label,
			enum offer_status *status)
{
	struct db_stmt *stmt;
	char *bolt12;

	stmt = db_prepare_v2(w->db, SQL("SELECT bolt12, label, status"
					"  FROM offers"
					" WHERE offer_id = ?;"));
	db_bind_sha256(stmt, offer_id);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	bolt12 = db_col_strdup(ctx, stmt, "bolt12");
	if (label) {
		if (db_col_is_null(stmt, "label"))
			*label = NULL;
		else
			*label = db_col_json_escape(ctx, stmt, "label");
	} else
		db_col_ignore(stmt, "label");

	if (status)
		*status = offer_status_in_db(db_col_int(stmt, "status"));
	else
		db_col_ignore(stmt, "status");

	tal_free(stmt);
	return bolt12;
}

struct db_stmt *wallet_offer_id_first(struct wallet *w, struct sha256 *offer_id)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT offer_id FROM offers;"));
	db_query_prepared(stmt);

	return wallet_offer_id_next(w, stmt, offer_id);
}

struct db_stmt *wallet_offer_id_next(struct wallet *w,
				     struct db_stmt *stmt,
				     struct sha256 *offer_id)
{
	if (!db_step(stmt))
		return tal_free(stmt);

	db_col_sha256(stmt, "offer_id", offer_id);
	return stmt;
}

/* If we make an offer inactive, this also expires all invoices
 * which we issued for it. */
static void offer_status_update(struct db *db,
				const struct sha256 *offer_id,
				enum offer_status oldstatus,
				enum offer_status newstatus)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("UPDATE offers"
				     " SET status=?"
				     " WHERE offer_id = ?;"));
	db_bind_int(stmt, offer_status_in_db(newstatus));
	db_bind_sha256(stmt, offer_id);
	db_exec_prepared_v2(take(stmt));

	if (!offer_status_active(oldstatus)
	    || offer_status_active(newstatus))
		return;

	stmt = db_prepare_v2(db, SQL("UPDATE invoices"
				     " SET state=?"
				     " WHERE state=? AND local_offer_id = ?;"));
	db_bind_int(stmt, invoice_status_in_db(EXPIRED));
	db_bind_int(stmt, invoice_status_in_db(UNPAID));
	db_bind_sha256(stmt, offer_id);
	db_exec_prepared_v2(take(stmt));
}

enum offer_status wallet_offer_disable(struct wallet *w,
				       const struct sha256 *offer_id,
				       enum offer_status s)
{
	enum offer_status newstatus;

	assert(offer_status_active(s));

	newstatus = offer_status_in_db(s & ~OFFER_STATUS_ACTIVE_F);
	offer_status_update(w->db, offer_id, s, newstatus);

	return newstatus;
}

void wallet_offer_mark_used(struct db *db, const struct sha256 *offer_id)
{
	struct db_stmt *stmt;
	enum offer_status status;

	stmt = db_prepare_v2(db, SQL("SELECT status"
				     "  FROM offers"
				     " WHERE offer_id = ?;"));
	db_bind_sha256(stmt, offer_id);
	db_query_prepared(stmt);
	if (!db_step(stmt))
		fatal("%s: unknown offer_id %s",
		      __func__,
		      fmt_sha256(tmpctx, offer_id));

	status = offer_status_in_db(db_col_int(stmt, "status"));
	tal_free(stmt);

	if (!offer_status_active(status))
		fatal("%s: offer_id %s not active: status %i",
		      __func__,
		      fmt_sha256(tmpctx, offer_id),
		      status);

	if (!offer_status_used(status)) {
		enum offer_status newstatus;

		if (offer_status_single(status))
			newstatus = OFFER_SINGLE_USE_USED;
		else
			newstatus = OFFER_MULTIPLE_USE_USED;
		offer_status_update(db, offer_id, status, newstatus);
	}
}

bool wallet_invoice_request_create(struct wallet *w,
				   const struct sha256 *invreq_id,
				   const char *bolt12,
				   const struct json_escape *label,
				   enum offer_status status)
{
	struct db_stmt *stmt;

	assert(offer_status_active(status));

	/* Test if already exists. */
	stmt = db_prepare_v2(w->db, SQL("SELECT 1"
					"  FROM invoicerequests"
					" WHERE invreq_id = ?;"));
	db_bind_sha256(stmt, invreq_id);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		db_col_ignore(stmt, "1");
		tal_free(stmt);
		return false;
	}
	tal_free(stmt);

	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO invoicerequests ("
				 "  invreq_id"
				 ", bolt12"
				 ", label"
				 ", status"
				 ") VALUES (?, ?, ?, ?);"));

	db_bind_sha256(stmt, invreq_id);
	db_bind_text(stmt, bolt12);
	if (label)
		db_bind_json_escape(stmt, label);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, offer_status_in_db(status));
	db_exec_prepared_v2(take(stmt));
	return true;
}

char *wallet_invoice_request_find(const tal_t *ctx,
			struct wallet *w,
			const struct sha256 *invreq_id,
			const struct json_escape **label,
			enum offer_status *status)
{
	struct db_stmt *stmt;
	char *bolt12;

	stmt = db_prepare_v2(w->db, SQL("SELECT bolt12, label, status"
					"  FROM invoicerequests"
					" WHERE invreq_id = ?;"));
	db_bind_sha256(stmt, invreq_id);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	bolt12 = db_col_strdup(ctx, stmt, "bolt12");
	if (label) {
		if (db_col_is_null(stmt, "label"))
			*label = NULL;
		else
			*label = db_col_json_escape(ctx, stmt, "label");
	} else
		db_col_ignore(stmt, "label");

	if (status)
		*status = offer_status_in_db(db_col_int(stmt, "status"));
	else
		db_col_ignore(stmt, "status");

	tal_free(stmt);
	return bolt12;
}

struct db_stmt *wallet_invreq_id_first(struct wallet *w, struct sha256 *invreq_id)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db, SQL("SELECT invreq_id FROM invoicerequests;"));
	db_query_prepared(stmt);

	return wallet_invreq_id_next(w, stmt, invreq_id);
}

struct db_stmt *wallet_invreq_id_next(struct wallet *w,
				     struct db_stmt *stmt,
				     struct sha256 *invreq_id)
{
	if (!db_step(stmt))
		return tal_free(stmt);

	db_col_sha256(stmt, "invreq_id", invreq_id);
	return stmt;
}

/* If we make an invoice_request inactive */
static void invoice_request_status_update(struct db *db,
					  const struct sha256 *invreq_id,
					  enum offer_status oldstatus,
					  enum offer_status newstatus)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("UPDATE invoicerequests"
				     " SET status=?"
				     " WHERE invreq_id = ?;"));
	db_bind_int(stmt, offer_status_in_db(newstatus));
	db_bind_sha256(stmt, invreq_id);
	db_exec_prepared_v2(take(stmt));
}

enum offer_status wallet_invoice_request_disable(struct wallet *w,
						 const struct sha256 *invreq_id,
						 enum offer_status s)
{
	enum offer_status newstatus;

	assert(offer_status_active(s));

	newstatus = offer_status_in_db(s & ~OFFER_STATUS_ACTIVE_F);
	invoice_request_status_update(w->db, invreq_id, s, newstatus);

	return newstatus;
}

void wallet_invoice_request_mark_used(struct db *db, const struct sha256 *invreq_id)
{
	struct db_stmt *stmt;
	enum offer_status status;

	stmt = db_prepare_v2(db, SQL("SELECT status"
				     "  FROM invoicerequests"
				     " WHERE invreq_id = ?;"));
	db_bind_sha256(stmt, invreq_id);
	db_query_prepared(stmt);
	if (!db_step(stmt))
		fatal("%s: unknown invreq_id %s",
		      __func__,
		      fmt_sha256(tmpctx, invreq_id));

	status = offer_status_in_db(db_col_int(stmt, "status"));
	tal_free(stmt);

	if (!offer_status_active(status))
		fatal("%s: invreq_id %s not active: status %i",
		      __func__,
		      fmt_sha256(tmpctx, invreq_id),
		      status);

	if (!offer_status_used(status)) {
		enum offer_status newstatus;

		if (offer_status_single(status))
			newstatus = OFFER_SINGLE_USE_USED;
		else
			newstatus = OFFER_MULTIPLE_USE_USED;
		invoice_request_status_update(db, invreq_id, status, newstatus);
	}
}

/* We join key parts with nuls for now. */
static void db_bind_datastore_key(struct db_stmt *stmt,
				  const char **key)
{
	u8 *joined;
	size_t len;

	if (tal_count(key) == 1) {
		db_bind_blob(stmt, (u8 *)key[0], strlen(key[0]));
		return;
	}

	len = strlen(key[0]);
	joined = (u8 *)tal_strdup(tmpctx, key[0]);
	for (size_t i = 1; i < tal_count(key); i++) {
		tal_resize(&joined, len + 1 + strlen(key[i]));
		joined[len] = '\0';
		memcpy(joined + len + 1, key[i], strlen(key[i]));
		len += 1 + strlen(key[i]);
	}
	db_bind_blob(stmt, joined, len);
}

static const char **db_col_datastore_key(const tal_t *ctx,
					 struct db_stmt *stmt,
					 const char *colname)
{
	char **key;
	const u8 *joined = db_col_blob(stmt, colname);
	size_t len = db_col_bytes(stmt, colname);

	key = tal_arr(ctx, char *, 0);
	do {
		size_t partlen;
		for (partlen = 0; partlen < len; partlen++) {
			if (joined[partlen] == '\0') {
				partlen++;
				break;
			}
		}
		tal_arr_expand(&key, tal_strndup(key, (char *)joined, partlen));
		len -= partlen;
		joined += partlen;
	} while (len != 0);

	return cast_const2(const char **, key);
}

void wallet_datastore_update(struct wallet *w, const char **key, const u8 *data)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db,
			     SQL("UPDATE datastore SET data=?, generation=generation+1 WHERE key=?;"));
	db_bind_talarr(stmt, data);
	db_bind_datastore_key(stmt, key);
	db_exec_prepared_v2(take(stmt));
}

void wallet_datastore_create(struct wallet *w, const char **key, const u8 *data)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO datastore VALUES (?, ?, 0);"));

	db_bind_datastore_key(stmt, key);
	db_bind_talarr(stmt, data);
	db_exec_prepared_v2(take(stmt));
}

static void db_datastore_remove(struct db *db, const char **key)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("DELETE FROM datastore"
				     " WHERE key = ?"));
	db_bind_datastore_key(stmt, key);
	db_exec_prepared_v2(take(stmt));
}

void wallet_datastore_remove(struct wallet *w, const char **key)
{
	db_datastore_remove(w->db, key);
}

/* Does k1 match k2 as far as k2 goes? */
bool datastore_key_startswith(const char **k1, const char **k2)
{
	size_t k1len = tal_count(k1), k2len = tal_count(k2);

	if (k2len > k1len)
		return false;

	for (size_t i = 0; i < k2len; i++) {
		if (!streq(k1[i], k2[i]))
			return false;
	}
	return true;
}

bool datastore_key_eq(const char **k1, const char **k2)
{
	return tal_count(k1) == tal_count(k2)
		&& datastore_key_startswith(k1, k2);
}

static u8 *db_datastore_get(const tal_t *ctx,
			    struct db *db,
			    const char **key,
			    u64 *generation)
{
	struct db_stmt *stmt;
	u8 *ret;

	stmt = db_prepare_v2(db,
			     SQL("SELECT data, generation"
				 " FROM datastore"
				 " WHERE key = ?"));
	db_bind_datastore_key(stmt, key);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		tal_free(stmt);
		return NULL;
	}

	ret = db_col_arr(ctx, stmt, "data", u8);
	if (generation)
		*generation = db_col_u64(stmt, "generation");
	else
		db_col_ignore(stmt, "generation");
	tal_free(stmt);
	return ret;
}

u8 *wallet_datastore_get(const tal_t *ctx,
			 struct wallet *w,
			 const char **key,
			 u64 *generation)
{
	return db_datastore_get(ctx, w->db, key, generation);
}

static struct db_stmt *db_datastore_next(const tal_t *ctx,
					 struct db_stmt *stmt,
					 const char **startkey,
					 const char ***key,
					 const u8 **data,
					 u64 *generation)
{
	if (!db_step(stmt))
		return tal_free(stmt);

	*key = db_col_datastore_key(ctx, stmt, "key");

	/* We select from startkey onwards, so once we're past it, stop */
	if (startkey && !datastore_key_startswith(*key, startkey)) {
		db_col_ignore(stmt, "data");
		db_col_ignore(stmt, "generation");
		return tal_free(stmt);
	}

	if (data)
		*data = db_col_arr(ctx, stmt, "data", u8);
	else
		db_col_ignore(stmt, "data");

	if (generation)
		*generation = db_col_u64(stmt, "generation");
	else
		db_col_ignore(stmt, "generation");

	return stmt;
}

static struct db_stmt *db_datastore_first(const tal_t *ctx,
					  struct db *db,
					  const char **startkey,
					  const char ***key,
					  const u8 **data,
					  u64 *generation)
{
	struct db_stmt *stmt;

	if (startkey) {
		stmt = db_prepare_v2(db,
				     SQL("SELECT key, data, generation"
					 " FROM datastore"
					 " WHERE key >= ?"
					 " ORDER BY key;"));
		db_bind_datastore_key(stmt, startkey);
	} else {
		stmt = db_prepare_v2(db,
				     SQL("SELECT key, data, generation"
					 " FROM datastore"
					 " ORDER BY key;"));
	}
	db_query_prepared(stmt);

	return db_datastore_next(ctx, stmt, startkey, key, data, generation);
}

struct db_stmt *wallet_datastore_first(const tal_t *ctx,
				       struct wallet *w,
				       const char **startkey,
				       const char ***key,
				       const u8 **data,
				       u64 *generation)
{
	return db_datastore_first(ctx, w->db, startkey, key, data, generation);
}

struct db_stmt *wallet_datastore_next(const tal_t *ctx,
				      const char **startkey,
				      struct db_stmt *stmt,
				      const char ***key,
				      const u8 **data,
				      u64 *generation)
{
	return db_datastore_next(ctx, stmt, startkey, key, data, generation);
}

/* We use a different query form if we only care about a single channel. */
struct wallet_htlc_iter {
	struct db_stmt *stmt;
	/* Non-zero if they specified it */
	struct short_channel_id scid;
};

struct wallet_htlc_iter *wallet_htlcs_first(const tal_t *ctx,
					    struct wallet *w,
					    const struct channel *chan,
					    struct short_channel_id *scid,
					    u64 *htlc_id,
					    int *cltv_expiry,
					    enum side *owner,
					    struct amount_msat *msat,
					    struct sha256 *payment_hash,
					    enum htlc_state *hstate)
{
	struct wallet_htlc_iter *i = tal(ctx, struct wallet_htlc_iter);

	if (chan) {
		i->scid = channel_scid_or_local_alias(chan);
		assert(i->scid.u64 != 0);
		assert(chan->dbid != 0);

		i->stmt = db_prepare_v2(w->db,
					SQL("SELECT h.channel_htlc_id"
					    ", h.cltv_expiry"
					    ", h.direction"
					    ", h.msatoshi"
					    ", h.payment_hash"
					    ", h.hstate"
					    " FROM channel_htlcs h"
					    " WHERE channel_id = ?"
					    " ORDER BY id ASC"));
		db_bind_u64(i->stmt, chan->dbid);
	} else {
		i->scid.u64 = 0;
		i->stmt = db_prepare_v2(w->db,
					SQL("SELECT channels.scid"
					    ", channels.alias_local"
					    ", h.channel_htlc_id"
					    ", h.cltv_expiry"
					    ", h.direction"
					    ", h.msatoshi"
					    ", h.payment_hash"
					    ", h.hstate"
					    " FROM channel_htlcs h"
					    " JOIN channels ON channels.id = h.channel_id"
					    " ORDER BY h.id ASC"));
	}
	/* FIXME: db_prepare should take ctx! */
	tal_steal(i, i->stmt);
	db_query_prepared(i->stmt);

	return wallet_htlcs_next(w, i,
				 scid, htlc_id, cltv_expiry, owner, msat,
				 payment_hash, hstate);
}

struct wallet_htlc_iter *wallet_htlcs_next(struct wallet *w,
					   struct wallet_htlc_iter *iter,
					   struct short_channel_id *scid,
					   u64 *htlc_id,
					   int *cltv_expiry,
					   enum side *owner,
					   struct amount_msat *msat,
					   struct sha256 *payment_hash,
					   enum htlc_state *hstate)
{
	if (!db_step(iter->stmt))
		return tal_free(iter);

	if (iter->scid.u64 != 0)
		*scid = iter->scid;
	else {
		if (db_col_is_null(iter->stmt, "channels.scid"))
			*scid = db_col_short_channel_id(iter->stmt, "channels.alias_local");
		else {
			*scid = db_col_short_channel_id(iter->stmt, "channels.scid");
			db_col_ignore(iter->stmt, "channels.alias_local");
		}
	}
	*htlc_id = db_col_u64(iter->stmt, "h.channel_htlc_id");
	if (db_col_int(iter->stmt, "h.direction") == DIRECTION_INCOMING)
		*owner = REMOTE;
	else
		*owner = LOCAL;
	*msat = db_col_amount_msat(iter->stmt, "h.msatoshi");
	db_col_sha256(iter->stmt, "h.payment_hash", payment_hash);
	*cltv_expiry = db_col_int(iter->stmt, "h.cltv_expiry");
	*hstate = db_col_int(iter->stmt, "h.hstate");
	return iter;
}

u64 wallet_get_rune_next_unique_id(const tal_t *ctx, struct wallet *wallet)
{
	struct db_stmt *stmt;
	u64 next_unique_id;

	stmt = db_prepare_v2(wallet->db, SQL("SELECT (COALESCE(MAX(id), -1) + 1) FROM runes"));
	db_query_prepared(stmt);
	db_step(stmt);

	next_unique_id = db_col_u64(stmt, "(COALESCE(MAX(id), -1) + 1)");

	tal_free(stmt);
	return next_unique_id;
}

struct rune_blacklist *wallet_get_runes_blacklist(const tal_t *ctx, struct wallet *wallet)
{
	struct db_stmt *stmt;
	struct rune_blacklist *blist = tal_arr(ctx, struct rune_blacklist, 0);

	stmt = db_prepare_v2(wallet->db, SQL("SELECT start_index, end_index FROM runes_blacklist ORDER BY start_index ASC"));
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct rune_blacklist b;
		b.start = db_col_u64(stmt, "start_index");
		b.end = db_col_u64(stmt, "end_index");
		tal_arr_expand(&blist, b);
	}
	tal_free(stmt);
	return blist;
}

static struct timeabs db_col_time_from_nsec(struct db_stmt *stmt, const char *colname)
{
	struct timerel t;
	struct timeabs tabs;

	if (db_col_is_null(stmt, colname))
		t = time_from_nsec(0);
	else
		t = time_from_nsec(db_col_u64(stmt, colname));
	tabs.ts = t.ts;
	return tabs;
}

const char *wallet_get_rune(const tal_t *ctx, struct wallet *wallet, u64 unique_id, struct timeabs *last_used)
{
	struct db_stmt *stmt;
	const char *runestr;

	stmt = db_prepare_v2(wallet->db, SQL("SELECT rune, last_used_nsec FROM runes WHERE id = ?"));
	db_bind_u64(stmt, unique_id);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		runestr = db_col_strdup(ctx, stmt, "rune");
		*last_used = db_col_time_from_nsec(stmt, "last_used_nsec");
	} else {
		runestr = NULL;
	}
	tal_free(stmt);
	return runestr;
}

/* Migration code needs db, and db does not have last_used_nsec yet */
static const char **db_get_runes(const tal_t *ctx, struct db *db)
{
	struct db_stmt *stmt;
	const char **strs = tal_arr(ctx, const char *, 0);

	stmt = db_prepare_v2(db, SQL("SELECT rune FROM runes"));
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		const char *str = db_col_strdup(strs, stmt, "rune");
		tal_arr_expand(&strs, str);
	}
	tal_free(stmt);
	return strs;
}

/* Wallet has last_used_nsec by now */
const char **wallet_get_runes(const tal_t *ctx, struct wallet *wallet, struct timeabs **last_used)
{
	struct db_stmt *stmt;
	const char **strs = tal_arr(ctx, const char *, 0);

	*last_used = tal_arr(ctx, struct timeabs, 0);
	stmt = db_prepare_v2(wallet->db, SQL("SELECT rune, last_used_nsec FROM runes"));
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		const char *str = db_col_strdup(strs, stmt, "rune");
		tal_arr_expand(&strs, str);
		tal_arr_expand(last_used, db_col_time_from_nsec(stmt, "last_used_nsec"));
	}
	tal_free(stmt);
	return strs;
}

static void db_rune_insert(struct db *db,
			   const struct rune *rune)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db,
			     SQL("INSERT INTO runes (id, rune) VALUES (?, ?);"));
	db_bind_u64(stmt, atol(rune->unique_id));
	db_bind_text(stmt, rune_to_base64(tmpctx, rune));
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

void wallet_rune_insert(struct wallet *wallet, const struct rune *rune)
{
	db_rune_insert(wallet->db, rune);
}

void wallet_rune_update_last_used(struct wallet *wallet, const struct rune *rune, struct timeabs last_used)
{
	struct db_stmt *stmt;
	struct timerel t;

	t.ts = last_used.ts;
	stmt = db_prepare_v2(wallet->db,
			     SQL("UPDATE runes SET last_used_nsec = ? WHERE id = ?;"));
	db_bind_u64(stmt, time_to_nsec(t));
	db_bind_u64(stmt, rune_unique_id(rune));
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

static void db_insert_blacklist(struct db *db,
				const struct rune_blacklist *entry)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db,
			     SQL("INSERT INTO runes_blacklist VALUES (?,?)"));
	db_bind_u64(stmt, entry->start);
	db_bind_u64(stmt, entry->end);
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

void wallet_insert_blacklist(struct wallet *wallet, const struct rune_blacklist *entry)
{
	db_insert_blacklist(wallet->db, entry);
}

void wallet_delete_blacklist(struct wallet *wallet, const struct rune_blacklist *entry)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(wallet->db,
			     SQL("DELETE FROM runes_blacklist WHERE start_index = ? AND end_index = ?"));
	db_bind_u64(stmt, entry->start);
	db_bind_u64(stmt, entry->end);
	db_exec_prepared_v2(stmt);
	if (db_count_changes(stmt) != 1) {
		db_fatal(wallet->db, "Failed to delete from runes_blacklist");
	}
	tal_free(stmt);
}

void migrate_datastore_commando_runes(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt;
	const char **startkey, **k;
	const u8 *data;
	size_t max;

	/* datastore routines expect a tal_arr */
	startkey = tal_arr(tmpctx, const char *, 2);
	startkey[0] = "commando";
	startkey[1] = "runes";

	for (stmt = db_datastore_first(tmpctx, db, startkey, &k, &data, NULL);
	     stmt;
	     stmt = db_datastore_next(tmpctx, stmt, startkey, &k, &data, NULL)) {
		const char *err, *str;
		struct rune *r;

		str = db_col_strdup(tmpctx, stmt, "data");
		r = rune_from_base64(tmpctx, str);
		if (!r)
			db_fatal(db, "Invalid commando rune %s", str);
		err = rune_is_ours(ld, r);
		if (err) {
			log_unusual(ld->log,
				    "Warning: removing commando"
				    " rune %s (uid %s): %s",
				    str, r->unique_id, err);
		} else {
			log_debug(ld->log, "Transferring commando rune to db: %s",
				  str);
			db_rune_insert(db, r);
		}
		db_datastore_remove(db, k);
	}

	/* Now convert blacklist */
	startkey[0] = "commando";
	startkey[1] = "blacklist";

	data = db_datastore_get(tmpctx, db, startkey, NULL);
	max = tal_bytelen(data);
	while (max) {
		struct rune_blacklist b;

		b.start = fromwire_u64(&data, &max);
		b.end = fromwire_u64(&data, &max);

		if (!data)
			db_fatal(db, "Invalid commando blacklist?");
		log_debug(ld->log, "Transferring commando blacklist to db: %"PRIu64"-%"PRIu64,
			  b.start, b.end);
		db_insert_blacklist(db, &b);
	}
	db_datastore_remove(db, startkey);

	/* Might as well clean up "rune_counter" while we're here, so
	 * commando datastore is completely clean. */
	startkey[0] = "commando";
	startkey[1] = "rune_counter";
	db_datastore_remove(db, startkey);
}

void migrate_runes_idfix(struct lightningd *ld, struct db *db)
{
	/* ID fields were wrong.  Pull them all out and put them back */
	const char **runes = db_get_runes(tmpctx, db);
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("DELETE FROM runes;"));
	db_exec_prepared_v2(stmt);
	tal_free(stmt);

	for (size_t i = 0; i < tal_count(runes); i++) {
		struct rune *r;

		r = rune_from_base64(tmpctx, runes[i]);
		if (!r)
			db_fatal(db, "Invalid databse rune %s", runes[i]);

		db_rune_insert(db, r);
	}
}

void wallet_set_local_anchor(struct wallet *w,
			     u64 channel_id,
			     const struct local_anchor_info *anchor,
			     u64 remote_index)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db,
			     SQL("INSERT INTO local_anchors VALUES (?,?,?,?,?,?)"));
	db_bind_u64(stmt, channel_id);
	db_bind_u64(stmt, remote_index);
	db_bind_txid(stmt, &anchor->anchor_point.txid);
	db_bind_int(stmt, anchor->anchor_point.n);
	db_bind_amount_sat(stmt, &anchor->commitment_fee);
	db_bind_int(stmt, anchor->commitment_weight);
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

void wallet_remove_local_anchors(struct wallet *w,
				 u64 channel_id,
				 u64 old_remote_index)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(w->db,
			     SQL("DELETE FROM local_anchors "
				 "WHERE channel_id = ? and commitment_index <= ?;"));
	db_bind_u64(stmt, channel_id);
	db_bind_u64(stmt, old_remote_index);
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

struct local_anchor_info *wallet_get_local_anchors(const tal_t *ctx,
						   struct wallet *w,
						   u64 channel_id)
{
	struct db_stmt *stmt;
	struct local_anchor_info *anchors;

	stmt = db_prepare_v2(w->db, SQL("SELECT"
					"  commitment_txid "
					", commitment_anchor_outnum "
					", commitment_fee "
					", commitment_weight "
					"FROM local_anchors"
					" WHERE channel_id = ?;"));
	db_bind_u64(stmt, channel_id);
	db_query_prepared(stmt);

	anchors = tal_arr(ctx, struct local_anchor_info, 0);
	while (db_step(stmt)) {
		struct local_anchor_info a;
		a.commitment_fee = db_col_amount_sat(stmt, "commitment_fee");
		a.commitment_weight = db_col_int(stmt, "commitment_weight");
		db_col_txid(stmt, "commitment_txid", &a.anchor_point.txid);
		a.anchor_point.n = db_col_int(stmt, "commitment_anchor_outnum");
		tal_arr_expand(&anchors, a);
	}
	tal_free(stmt);

	return anchors;
}
