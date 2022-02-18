#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/json_helpers.h>
#include <common/json_stream.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/incomestmt.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>

static struct account *get_account(struct account **accts,
				   u64 acct_db_id)
{
	for (size_t i = 0; i < tal_count(accts); i++) {
		if (accts[i]->db_id == acct_db_id)
			return accts[i];
	}
	return NULL;
}

static struct income_event *chain_to_income(const tal_t *ctx,
					    struct chain_event *ev,
					    char *acct_to_attribute,
					    struct amount_msat credit,
					    struct amount_msat debit)
{
	struct income_event *inc = tal(ctx, struct income_event);

	inc->acct_name = tal_strdup(inc, acct_to_attribute);
	inc->tag = tal_strdup(inc, ev->tag);
	inc->credit = credit;
	inc->debit = debit;
	inc->currency = tal_strdup(inc, ev->currency);
	inc->timestamp = ev->timestamp;
	inc->outpoint = tal_dup(inc, struct bitcoin_outpoint, &ev->outpoint);

	if (ev->spending_txid)
		inc->txid = tal_dup(inc, struct bitcoin_txid,
				    ev->spending_txid);
	else
		inc->txid = NULL;

	if (ev->payment_id)
		inc->payment_id = tal_dup(inc, struct sha256, ev->payment_id);
	else
		inc->payment_id = NULL;

	return inc;
}

static struct income_event *channel_to_income(const tal_t *ctx,
					      struct channel_event *ev,
					      struct amount_msat credit,
					      struct amount_msat debit)
{
	struct income_event *inc = tal(ctx, struct income_event);

	inc->acct_name = tal_strdup(inc, ev->acct_name);
	inc->tag = tal_strdup(inc, ev->tag);
	inc->credit = credit;
	inc->debit = debit;
	inc->currency = tal_strdup(inc, ev->currency);
	inc->timestamp = ev->timestamp;
	inc->outpoint = NULL;
	inc->txid = NULL;
	if (ev->payment_id)
		inc->payment_id = tal_dup(inc, struct sha256, ev->payment_id);
	else
		inc->payment_id = NULL;

	return inc;
}

static struct income_event *onchainfee_to_income(const tal_t *ctx,
						 struct onchain_fee *fee)
{
	struct income_event *inc = tal(ctx, struct income_event);

	inc->acct_name = tal_strdup(inc, fee->acct_name);
	inc->tag = tal_fmt(inc, "%s", "onchain_fee");
	/* We swap these, as they're actually opposite */
	inc->credit = fee->debit;
	inc->debit = fee->credit;
	inc->currency = tal_strdup(inc, fee->currency);
	inc->timestamp = fee->timestamp;
	inc->txid = tal_dup(inc, struct bitcoin_txid, &fee->txid);
	inc->outpoint = NULL;
	inc->payment_id = NULL;

	return inc;
}

static struct income_event *maybe_chain_income(const tal_t *ctx,
					       struct db *db,
					       struct account *acct,
					       struct chain_event *ev)
{
	if (streq(ev->tag, "htlc_fulfill")) {
		if (streq(ev->acct_name, EXTERNAL_ACCT))
			/* Swap the credit/debit as it went to external */
			return chain_to_income(ctx, ev,
					       ev->origin_acct,
					       ev->debit,
					       ev->credit);
		/* Normal credit/debit as it originated from external */
		return chain_to_income(ctx, ev,
				       ev->acct_name,
				       ev->credit, ev->debit);
	}

	/* expenses */
	if (streq(ev->tag, "anchor")) {
		if (acct->we_opened)
			/* for now, we count all anchors as expenses */
			return chain_to_income(ctx, ev,
					       ev->acct_name,
					       ev->debit,
					       ev->credit);
		/* non-openers dont spend/gain anything on anchors */
		return NULL;
	}

	/* income */
	if (streq(ev->tag, "deposit")) {
		struct db_stmt *stmt;

		/* deposit to external is cost to us */
		if (streq(ev->acct_name, EXTERNAL_ACCT)) {
			struct income_event *iev;
			iev = chain_to_income(ctx, ev,
					      ev->origin_acct,
					      ev->debit,
					      ev->credit);
			/* Also, really a withdrawal.. phh */
			iev->tag = tal_strdup(iev, mvt_tag_str(WITHDRAWAL));
			return iev;
		}


		/* Did this deposit originate from within our
		 * wallet? */
		/*FIXME: there's an edge case where we put funds
		 * into a tx that included funds from a 3rd party
		 * coming to us... eg. a splice out from the peer
		 * to our onchain wallet */
		stmt = db_prepare_v2(db, SQL("SELECT"
					     "  1"
					     " FROM chain_events e"
					     " LEFT OUTER JOIN accounts a"
					     " ON e.account_id = a.id"
					     " WHERE "
					     "  e.spending_txid = ?"));

		db_bind_txid(stmt, 0, &ev->outpoint.txid);
		db_query_prepared(stmt);
		if (!db_step(stmt)) {
			tal_free(stmt);
			/* no matching withdrawal from internal,
			 * so must be new deposit (external) */
			return chain_to_income(ctx, ev,
					       ev->acct_name,
					       ev->credit,
					       ev->debit);
		}

		db_col_ignore(stmt, "1");
		tal_free(stmt);
		return NULL;
	}

	return NULL;
}

static struct income_event *maybe_channel_income(const tal_t *ctx,
						 struct channel_event *ev)
{
	/* We record a +/- penalty adj, but we only count the credit */
	if (streq(ev->tag, "penalty_adj")) {
		if (!amount_msat_zero(ev->credit))
			return channel_to_income(ctx, ev,
						 ev->credit,
						 ev->debit);
		return NULL;
	}

	if (streq(ev->tag, "invoice")) {
		/* FIXME: add a sub-category for fees paid */
		return channel_to_income(ctx, ev,
					 ev->credit,
					 ev->debit);
	}

	/* for routed payments, we only record the fees on the
	 * debiting side -- the side the $$ was made on! */
	if (streq(ev->tag, "routed")) {
		if (!amount_msat_zero(ev->debit))
			return channel_to_income(ctx, ev,
						 ev->fees,
						 AMOUNT_MSAT(0));
		return NULL;
	}

	/* For everything else, it's straight forward */
	/* (lease_fee, pushed, journal_entry) */
	return channel_to_income(ctx, ev, ev->credit, ev->debit);
}

struct income_event **list_income_events(const tal_t *ctx,
					 struct db *db,
					 u64 start_time,
					 u64 end_time)
{
	struct channel_event **channel_events;
	struct chain_event **chain_events;
	struct onchain_fee **onchain_fees;
	struct account **accts;

	struct income_event **evs;

	channel_events = list_channel_events_timebox(ctx, db,
						     start_time, end_time);
	chain_events = list_chain_events_timebox(ctx, db, start_time, end_time);
	onchain_fees = list_chain_fees_timebox(ctx, db, start_time, end_time);
	accts = list_accounts(ctx, db);

	evs = tal_arr(ctx, struct income_event *, 0);

	for (size_t i = 0, j = 0, k = 0;
	     i < tal_count(chain_events)
	     || j < tal_count(channel_events)
	     || k < tal_count(onchain_fees);
	     /* Incrementing happens inside loop */) {
		struct channel_event *chan;
		struct chain_event *chain;
		struct onchain_fee *fee;
		u64 lowest = 0;

		if (i < tal_count(chain_events))
			chain = chain_events[i];
		else
			chain = NULL;
		if (j < tal_count(channel_events))
			chan = channel_events[j];
		else
			chan = NULL;
		if (k < tal_count(onchain_fees))
			fee = onchain_fees[k];
		else
			fee = NULL;

		if (chain)
			lowest = chain->timestamp;

		if (chan
		    && (lowest == 0 || lowest > chan->timestamp))
			lowest = chan->timestamp;

		if (fee
		    && (lowest == 0 || lowest > fee->timestamp))
			lowest = fee->timestamp;

		/* chain events first, then channel events, then fees. */
		if (chain && chain->timestamp == lowest) {
			struct income_event *ev;
			struct account *acct =
				get_account(accts, chain->acct_db_id);

			ev = maybe_chain_income(evs, db, acct, chain);
			if (ev)
				tal_arr_expand(&evs, ev);
			i++;
			continue;
		}

		if (chan && chan->timestamp == lowest) {
			struct income_event *ev;
			ev = maybe_channel_income(evs, chan);
			if (ev)
				tal_arr_expand(&evs, ev);

			j++;
			continue;
		}

		/* Last thing left is the fee */
		tal_arr_expand(&evs, onchainfee_to_income(evs, fee));
		k++;
	}

	return evs;
}

struct income_event **list_income_events_all(const tal_t *ctx, struct db *db)
{
	return list_income_events(ctx, db, 0, SQLITE_MAX_UINT);
}

void json_add_income_event(struct json_stream *out, struct income_event *ev)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", ev->acct_name);
	json_add_string(out, "tag", ev->tag);
	json_add_amount_msat_only(out, "credit", ev->credit);
	json_add_amount_msat_only(out, "debit", ev->debit);
	json_add_string(out, "currency", ev->currency);
	json_add_u64(out, "timestamp", ev->timestamp);

	if (ev->outpoint)
		json_add_outpoint(out, "outpoint", ev->outpoint);

	if (ev->txid)
		json_add_txid(out, "txid", ev->txid);

	if (ev->payment_id)
		json_add_sha256(out, "payment_id", ev->payment_id);

	json_object_end(out);
}
