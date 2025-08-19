#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <inttypes.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>

void json_add_onchain_fee(struct json_stream *out,
			  struct onchain_fee *fee)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", fee->acct_name);
	json_add_string(out, "type", "onchain_fee");
	json_add_string(out, "tag", "onchain_fee");
	json_add_amount_msat(out, "credit_msat", fee->credit);
	json_add_amount_msat(out, "debit_msat", fee->debit);
	json_add_string(out, "currency", chainparams->lightning_hrp);
	json_add_u64(out, "timestamp", fee->timestamp);
	json_add_txid(out, "txid", &fee->txid);
	json_object_end(out);
}

static struct onchain_fee *stmt2onchain_fee(const tal_t *ctx,
					    struct db_stmt *stmt)
{
	struct onchain_fee *of = tal(ctx, struct onchain_fee);

	of->acct_name = db_col_strdup(of, stmt, "of.account_name");
	db_col_txid(stmt, "of.txid", &of->txid);
	of->credit = db_col_amount_msat(stmt, "of.credit");
	of->debit = db_col_amount_msat(stmt, "of.debit");
	of->timestamp = db_col_u64(stmt, "of.timestamp");
	of->update_count = db_col_int(stmt, "of.update_count");

	return of;
}

static struct onchain_fee **find_onchain_fees(const tal_t *ctx,
					      struct db_stmt *stmt TAKES)
{
	struct onchain_fee **results;

	db_query_prepared(stmt);
	if (stmt->error)
		db_fatal(stmt->db, "find_onchain_fees err: %s", stmt->error);
	results = tal_arr(ctx, struct onchain_fee *, 0);
	while (db_step(stmt)) {
		struct onchain_fee *of = stmt2onchain_fee(results, stmt);
		tal_arr_expand(&results, of);
	}

	if (taken(stmt))
		tal_free(stmt);

	return results;
}

struct onchain_fee **account_get_chain_fees(const tal_t *ctx, struct db *db,
					    struct account *acct)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.account_name"
				     ", of.txid"
				     ", of.credit"
				     ", of.debit"
				     ", of.timestamp"
				     ", of.update_count"
				     " FROM onchain_fees of"
				     " WHERE of.account_name = ?"
				     " ORDER BY "
				     "  of.timestamp"
				     ", of.txid"
				     ", of.update_count"));

	db_bind_text(stmt, acct->name);
	return find_onchain_fees(ctx, take(stmt));
}

struct onchain_fee **get_chain_fees_by_txid(const tal_t *ctx, struct db *db,
					    struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.account_name"
				     ", of.txid"
				     ", of.credit"
				     ", of.debit"
				     ", of.timestamp"
				     ", of.update_count"
				     " FROM onchain_fees of"
				     " WHERE of.txid = ?"
				     " ORDER BY "
				     "  of.timestamp"
				     ", of.txid"
				     ", of.update_count"));

	db_bind_txid(stmt, txid);
	return find_onchain_fees(ctx, take(stmt));
}

struct onchain_fee **list_chain_fees_timebox(const tal_t *ctx, struct db *db,
					     u64 start_time, u64 end_time)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.account_name"
				     ", of.txid"
				     ", of.credit"
				     ", of.debit"
				     ", of.timestamp"
				     ", of.update_count"
				     " FROM onchain_fees of"
				     " WHERE timestamp > ?"
				     "  AND timestamp <= ?"
				     " ORDER BY "
				     "  of.timestamp"
				     ", of.account_name"
				     ", of.txid"
				     ", of.update_count"));

	db_bind_u64(stmt, start_time);
	db_bind_u64(stmt, end_time);
	return find_onchain_fees(ctx, take(stmt));
}

struct onchain_fee **list_chain_fees(const tal_t *ctx, struct db *db)
{
	return list_chain_fees_timebox(ctx, db, 0, SQLITE_MAX_UINT);
}

struct onchain_fee **account_onchain_fees(const tal_t *ctx,
					  struct db *db,
					  struct account *acct)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.account_name"
				     ", of.txid"
				     ", of.credit"
				     ", of.debit"
				     ", of.timestamp"
				     ", of.update_count"
				     " FROM onchain_fees of"
				     " WHERE of.account_name = ?;"));

	db_bind_text(stmt, acct->name);
	return find_onchain_fees(ctx, take(stmt));
}

static void insert_chain_fees_diff(struct db *db,
				   const char *acct_name,
				   struct bitcoin_txid *txid,
				   struct amount_msat amount,
				   u64 timestamp)
{
	struct db_stmt *stmt;
	u32 update_count;
	struct amount_msat current_amt, credit, debit;

	/* First, look to see if there's an already existing
	 * record to update */
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  update_count"
				     ", credit"
				     ", debit"
				     " FROM onchain_fees"
				     " WHERE txid = ?"
				     " AND account_name = ?"
				     " ORDER BY update_count"));

	db_bind_txid(stmt, txid);
	db_bind_text(stmt, acct_name);
	db_query_prepared(stmt);

	/* If there's no current record, add it */
	current_amt = AMOUNT_MSAT(0);
	update_count = 0;
	while (db_step(stmt)) {
		update_count = db_col_int(stmt, "update_count");
		credit = db_col_amount_msat(stmt, "credit");
		debit = db_col_amount_msat(stmt, "debit");

		/* These should apply perfectly, as we sorted them by
		 * insert order */
		if (!amount_msat_accumulate(&current_amt, credit))
			db_fatal(db, "Overflow when adding onchain fees");

		if (!amount_msat_sub(&current_amt, current_amt, debit))
			db_fatal(db, "Underflow when subtracting onchain fees");

	}
	tal_free(stmt);

	/* If they're already equal, no need to update */
	if (amount_msat_eq(current_amt, amount))
		return;

	if (!amount_msat_sub(&credit, amount, current_amt)) {
		credit = AMOUNT_MSAT(0);
		if (!amount_msat_sub(&debit, current_amt, amount))
			db_fatal(db, "shouldn't happen, unable to subtract");
	} else
		debit = AMOUNT_MSAT(0);

	stmt = db_prepare_v2(db, SQL("INSERT INTO onchain_fees"
				     " ("
				     "  account_name"
				     ", txid"
				     ", credit"
				     ", debit"
				     ", timestamp"
				     ", update_count"
				     ") VALUES"
				     " (?, ?, ?, ?, ?, ?);"));

	db_bind_text(stmt, acct_name);
	db_bind_txid(stmt, txid);
	db_bind_amount_msat(stmt, credit);
	db_bind_amount_msat(stmt, debit);
	db_bind_u64(stmt, timestamp);
	db_bind_int(stmt, ++update_count);
	db_exec_prepared_v2(take(stmt));
}

struct fee_sum **calculate_onchain_fee_sums(const tal_t *ctx, struct db *db)
{
	struct db_stmt *stmt;
	struct fee_sum **sums;
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.txid"
				     ", of.account_name"
				     ", CAST(SUM(of.credit) AS BIGINT) as credit"
				     ", CAST(SUM(of.debit) AS BIGINT) as debit"
				     " FROM onchain_fees of"
				     " GROUP BY of.txid"
				     ", of.account_name"
				     " ORDER BY txid, account_name"));

	db_query_prepared(stmt);

	sums = tal_arr(ctx, struct fee_sum *, 0);
	while (db_step(stmt)) {
		struct fee_sum *sum;
		struct amount_msat debit;
		bool ok;

		sum = tal(sums, struct fee_sum);
		sum->txid = tal(sum, struct bitcoin_txid);

		db_col_txid(stmt, "of.txid", sum->txid);
		sum->acct_name = db_col_strdup(sum, stmt, "of.account_name");
		sum->fees_paid = db_col_amount_msat(stmt, "credit");
		debit = db_col_amount_msat(stmt, "debit");

		ok = amount_msat_sub(&sum->fees_paid, sum->fees_paid,
				     debit);
		assert(ok);
		tal_arr_expand(&sums, sum);
	}

	tal_free(stmt);
	return sums;
}

char *update_channel_onchain_fees(const tal_t *ctx,
				  struct db *db,
				  struct account *acct)
{
	struct chain_event *close_ev, **events;
	struct amount_msat onchain_amt;

	assert(acct->onchain_resolved_block);
	close_ev = find_chain_event_by_id(ctx, db,
					  *acct->closed_event_db_id);
	events = find_chain_events_bytxid(ctx, db,
					  close_ev->spending_txid);

	/* Starting balance is close-ev's debit amount */
	onchain_amt = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(events); i++) {
		struct chain_event *ev = events[i];

		/* Ignore:
		    - htlc_fufill (to me)
		    - anchors (already exlc from output)
		    - to_external (if !htlc_fulfill)
		*/
		if (is_channel_account(ev->acct_name)
		    && streq("htlc_fulfill", ev->tag))
			continue;

		if (streq("anchor", ev->tag))
			continue;

		/* Ignore stuff which is paid to
		 * the peer's account (external),
		 * except for fulfilled htlcs (which originated
		 * in our balance) */
		if (is_external_account(ev->acct_name)
		    && !streq("htlc_fulfill", ev->tag))
			continue;

		/* anything else we count? */
		if (!amount_msat_accumulate(&onchain_amt, ev->credit))
			return tal_fmt(ctx, "Unable to add"
				       "onchain + %s's credit",
				       ev->tag);
	}

	if (amount_msat_less_eq(onchain_amt, close_ev->debit)) {
		struct amount_msat fees;
		if (!amount_msat_sub(&fees, close_ev->debit,
				     onchain_amt))
			return tal_fmt(ctx, "Unable to sub"
				       "onchain sum from %s",
				       close_ev->tag);

		insert_chain_fees_diff(db, acct->name,
				       close_ev->spending_txid,
				       fees,
				       close_ev->timestamp);
	}

	return NULL;
}

static char *is_closed_channel_txid(const tal_t *ctx,
				    struct bkpr *bkpr,
				    struct chain_event *ev,
				    struct bitcoin_txid *txid,
				    bool *is_channel_close_tx)
{
	struct account *acct;
	struct chain_event *closed;
	u8 *inner_ctx = tal(NULL, u8);

	/* Figure out if this is a channel close tx */
	acct = find_account(bkpr, ev->acct_name);
	assert(acct);

	/* There's a separate process for figuring out
	 * our onchain fees for channel closures */
	if (!acct->closed_event_db_id) {
		*is_channel_close_tx = false;
		tal_free(inner_ctx);
		return NULL;
	}

	/* is the closed utxo the same as the one
	 * we're trying to find fees for now */
	closed = find_chain_event_by_id(inner_ctx, bkpr->db,
			*acct->closed_event_db_id);
	if (!closed) {
		*is_channel_close_tx = false;
		tal_free(inner_ctx);
		return tal_fmt(ctx, "Unable to find"
			      " db record (chain_evt)"
			      " with id %"PRIu64,
			      *acct->closed_event_db_id);
	}

	if (!closed->spending_txid) {
		*is_channel_close_tx = false;
		tal_free(inner_ctx);
		return tal_fmt(ctx, "Marked a closing"
			      " event that's not"
			      " actually a spend");
	}

	*is_channel_close_tx =
		bitcoin_txid_eq(txid, closed->spending_txid);
	tal_free(inner_ctx);
	return NULL;
}

char *maybe_update_onchain_fees(const tal_t *ctx,
				struct bkpr *bkpr,
			        struct bitcoin_txid *txid)
{
	size_t no_accts = 0, plus_ones;
	const char *last_acctname = NULL;
	bool contains_wallet = false, skip_wallet = false;
	struct chain_event **events;
	struct amount_msat deposit_msat = AMOUNT_MSAT(0),
			   withdraw_msat = AMOUNT_MSAT(0),
			   fees_msat, fee_part_msat;
	char *err = NULL;
	u8 *inner_ctx = tal(NULL, u8);

	/* Find all the deposits/withdrawals for this txid */
	events = find_chain_events_bytxid(inner_ctx, bkpr->db, txid);

	/* If we don't even have two events, skip */
	if (tal_count(events) < 2)
		goto finished;

	for (size_t i = 0; i < tal_count(events); i++) {
		bool is_channel_close_tx;
		err = is_closed_channel_txid(ctx, bkpr,
					     events[i], txid,
					     &is_channel_close_tx);

		if (err)
			goto finished;

		/* We skip channel close txs here! */
		if (is_channel_close_tx)
			goto finished;

		if (events[i]->spending_txid) {
			if (!amount_msat_accumulate(&withdraw_msat,
						    events[i]->debit)) {
				err = tal_fmt(ctx, "Overflow adding withdrawal debits for"
					      " txid: %s",
					      fmt_bitcoin_txid(ctx,
							     txid));
				goto finished;
			}
		} else {
			if (!amount_msat_accumulate(&deposit_msat,
						    events[i]->credit)) {
				err = tal_fmt(ctx, "Overflow adding deposit credits for"
					      " txid: %s",
					      fmt_bitcoin_txid(ctx,
							     txid));
				goto finished;
			}
		}

		/* While we're here, also count number of accts
		 * that were involved! Two little tricks here.
		 *
		 * One) we sorted the output
		 * by acct id, so we can cheat how we count: if
		 * it's a different acct_id than the last seen, we inc
		 * the counter.
		 *
		 * Two) who "gets" fee attribution is complicated
		 * and requires knowing if the wallet/external accts
		 * were involved (everything else is channel accts)
		 * */
		if (!last_acctname || !streq(last_acctname, events[i]->acct_name)) {
			last_acctname = events[i]->acct_name;
			/* Don't count external accts */
			if (!is_external_account(last_acctname))
				no_accts++;

			contains_wallet |= is_wallet_account(last_acctname);
		}
	}

	/* Only affects external accounts, we can ignore */
	if (no_accts == 0)
		goto finished;

	/* If either is zero, keep waiting */
	if (amount_msat_is_zero(withdraw_msat)
	    || amount_msat_is_zero(deposit_msat))
		goto finished;

	/* If our withdraws < deposits, wait for more data */
	if (amount_msat_less(withdraw_msat, deposit_msat))
		goto finished;

	if (!amount_msat_sub(&fees_msat, withdraw_msat, deposit_msat)) {
		err = tal_fmt(ctx, "Err subtracting withdraw %s from deposit %s"
			      " for txid %s",
			      fmt_amount_msat(ctx, withdraw_msat),
			      fmt_amount_msat(ctx, deposit_msat),
			      fmt_bitcoin_txid(ctx, txid));
		goto finished;
	}

	/* Now we need to figure out how to allocate fees to each account
	 * that was involved in the tx. This is a lil complex, buckle up*/

	/* If the wallet's involved + there were any other accounts, decr by one */
	if (no_accts > 1 && contains_wallet) {
		skip_wallet = true;
		no_accts--;
	}

	/* Now we divide by the number of accts involved, to figure out the
	 * value to log for each account! */
	fee_part_msat = amount_msat_div(fees_msat, no_accts);

	/* So we don't lose any msats b/c of rounding, find the number of
	 * accts to add an extra msat onto */
	plus_ones = fees_msat.millisatoshis % no_accts; /* Raw: mod calc */

	/* Now we log (or update the existing record) for each acct */
	last_acctname = NULL;
	for (size_t i = 0; i < tal_count(events); i++) {
		struct amount_msat fees;

		if (last_acctname && streq(last_acctname, events[i]->acct_name))
			continue;

		last_acctname = events[i]->acct_name;

		/* We *never* assign fees to external accounts;
		 * if external funds were contributed to a tx
		 * we wouldn't record it -- fees are solely ours */
		if (is_external_account(last_acctname))
			continue;

		/* We only attribute fees to the wallet
		 * if the wallet is the only game in town */
		if (skip_wallet && is_wallet_account(last_acctname)) {
			/* But we might need to clean up any fees assigned
			 * to the wallet from a previous round, where it
			 * *was* the only game in town */
			insert_chain_fees_diff(bkpr->db, last_acctname, txid,
					       AMOUNT_MSAT(0),
					       events[i]->timestamp);
			continue;
		}

		/* Add an extra msat onto plus_ones accts
		 * so we don't lose any precision in
		 * our accounting */
		if (plus_ones > 0) {
			plus_ones--;
			if (!amount_msat_add(&fees, fee_part_msat,
					     AMOUNT_MSAT(1))) {
				err = "Overflow adding 1 ... yeah right";
				/* We're gonna keep going, yolo */
				fees = fee_part_msat;
			}
		} else
			fees = fee_part_msat;

		insert_chain_fees_diff(bkpr->db, last_acctname, txid, fees,
				       events[i]->timestamp);

	}

finished:
	tal_free(inner_ctx);
	return err;
}

struct fee_sum **find_account_onchain_fees(const tal_t *ctx,
					   struct db *db,
					   struct account *acct)
{
	struct db_stmt *stmt;
	struct fee_sum **sums;
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  txid"
				     ", CAST(SUM(credit) AS BIGINT) as credit"
				     ", CAST(SUM(debit) AS BIGINT) as debit"
				     " FROM onchain_fees"
				     " WHERE account_name = ?"
				     " GROUP BY txid"
				     " ORDER BY txid"));

	db_bind_text(stmt, acct->name);
	db_query_prepared(stmt);

	sums = tal_arr(ctx, struct fee_sum *, 0);
	while (db_step(stmt)) {
		struct fee_sum *sum;
		struct amount_msat amt;
		bool ok;

		sum = tal(sums, struct fee_sum);
		sum->acct_name = acct->name;
		sum->txid = tal(sum, struct bitcoin_txid);
		db_col_txid(stmt, "txid", sum->txid);

		sum->fees_paid = db_col_amount_msat(stmt, "credit");
		amt = db_col_amount_msat(stmt, "debit");
		ok = amount_msat_sub(&sum->fees_paid, sum->fees_paid, amt);
		assert(ok);
		tal_arr_expand(&sums, sum);
	}

	tal_free(stmt);
	return sums;
}

u64 onchain_fee_last_timestamp(struct db *db,
			       const char *acct_name,
			       struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;
	u64 timestamp;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  timestamp"
				     " FROM onchain_fees"
				     " WHERE account_name = ?"
				     " AND txid = ?"
				     " ORDER BY timestamp DESC"));


	db_bind_text(stmt, acct_name);
	db_bind_txid(stmt, txid);
	db_query_prepared(stmt);

	if (db_step(stmt))
		timestamp = db_col_u64(stmt, "timestamp");
	else
		timestamp = 0;

	tal_free(stmt);
	return timestamp;
}
