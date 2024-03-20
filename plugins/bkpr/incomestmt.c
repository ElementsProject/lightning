#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/json_parse_simple.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <inttypes.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/incomestmt.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>
#include <time.h>

#define ONCHAIN_FEE "onchain_fee"

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
	inc->fees = AMOUNT_MSAT(0);
	inc->currency = tal_strdup(inc, ev->currency);
	inc->timestamp = ev->timestamp;
	inc->outpoint = tal_dup(inc, struct bitcoin_outpoint, &ev->outpoint);
	inc->desc = tal_strdup_or_null(inc, ev->desc);
	inc->txid = tal_dup_or_null(inc, struct bitcoin_txid, ev->spending_txid);
	inc->payment_id = tal_dup_or_null(inc, struct sha256, ev->payment_id);

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
	inc->fees = ev->fees;
	inc->currency = tal_strdup(inc, ev->currency);
	inc->timestamp = ev->timestamp;
	inc->outpoint = NULL;
	inc->txid = NULL;
	inc->desc = tal_strdup_or_null(inc, ev->desc);
	inc->payment_id = tal_dup_or_null(inc, struct sha256, ev->payment_id);

	return inc;
}

static struct income_event *onchainfee_to_income(const tal_t *ctx,
						 struct onchain_fee *fee)
{
	struct income_event *inc = tal(ctx, struct income_event);

	inc->acct_name = tal_strdup(inc, fee->acct_name);
	inc->tag = tal_fmt(inc, "%s", ONCHAIN_FEE);
	/* We swap these, as they're actually opposite */
	inc->credit = fee->debit;
	inc->debit = fee->credit;
	inc->fees = AMOUNT_MSAT(0);
	inc->currency = tal_strdup(inc, fee->currency);
	inc->timestamp = fee->timestamp;
	inc->txid = tal_dup(inc, struct bitcoin_txid, &fee->txid);
	inc->outpoint = NULL;
	inc->payment_id = NULL;
	inc->desc = NULL;

	return inc;
}

/* CSVs don't like ',' in the middle. We short circuit this
 * by wrapping the desc in double-quotes ("). But what if
 * there's already double-quotes? Well we swap these to
 * single-quotes (') and then use the json_escape function */
static char *csv_safe_str(const tal_t *ctx, char *input TAKES)
{
	struct json_escape *esc;
	char *dupe;

	/* Update the double-quotes in place */
	dupe = tal_strdup(tmpctx, input);
	for (size_t i = 0; dupe[i] != '\0'; i++) {
		if (dupe[i] == '"')
			dupe[i] = '\'';
	}

	esc = json_escape(tmpctx, take(dupe));
	return tal_fmt(ctx, "\"%s\"", esc->s);
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

			/* External deposits w/o a blockheight
			 * aren't confirmed yet */
			if (ev->blockheight == 0)
				return NULL;

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

		db_bind_txid(stmt, &ev->outpoint.txid);
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

static struct income_event *paid_invoice_fee(const tal_t *ctx,
					     struct channel_event *ev)
{
	struct income_event *iev;
	iev = channel_to_income(ctx, ev, AMOUNT_MSAT(0), ev->fees);
	iev->tag = tal_free(ev->tag);
	iev->tag = (char *)account_entry_tag_str(INVOICEFEE);
	return iev;
}

static struct income_event *rebalance_fee(const tal_t *ctx,
					  struct channel_event *ev)
{
	struct income_event *iev;
	iev = channel_to_income(ctx, ev, AMOUNT_MSAT(0), ev->fees);
	iev->tag = tal_free(ev->tag);
	iev->tag = (char *)account_entry_tag_str(REBALANCEFEE);
	return iev;
}

static struct income_event *maybe_channel_income(const tal_t *ctx,
						 struct channel_event *ev)
{
	if (amount_msat_zero(ev->credit)
	    && amount_msat_zero(ev->debit))
		return NULL;

	/* We record a +/- penalty adj, but we only count the credit */
	if (streq(ev->tag, "penalty_adj")) {
		if (!amount_msat_zero(ev->credit))
			return channel_to_income(ctx, ev,
						 ev->credit,
						 ev->debit);
		return NULL;
	}

	if (streq(ev->tag, "invoice")) {
		/* Skip events for rebalances */
		if (ev->rebalance_id)
			return NULL;

		/* If it's a payment, we note fees separately */
		if (!amount_msat_zero(ev->debit)) {
			struct amount_msat paid;
			bool ok;
			ok = amount_msat_sub(&paid, ev->debit, ev->fees);
			assert(ok);
			return channel_to_income(ctx, ev,
						 ev->credit,
						 paid);
		}

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

static struct onchain_fee **find_consolidated_fees(const tal_t *ctx,
						   struct db *db,
						   u64 start_time,
						   u64 end_time)
{
	struct fee_sum **sums;
	struct onchain_fee **fee_sums
		= tal_arr(ctx, struct onchain_fee *, 0);

	sums = calculate_onchain_fee_sums(ctx, db);

	for (size_t i = 0; i < tal_count(sums); i++) {
		/* Find the last matching feerate's data */
		struct onchain_fee *fee;

		if (amount_msat_zero(sums[i]->fees_paid))
			continue;

		fee = tal(fee_sums, struct onchain_fee);
		fee->credit = sums[i]->fees_paid;
		fee->debit = AMOUNT_MSAT(0);
		fee->currency = tal_steal(fee, sums[i]->currency);
		fee->acct_name = tal_steal(fee, sums[i]->acct_name);
		fee->txid = *sums[i]->txid;

		fee->timestamp =
			onchain_fee_last_timestamp(db, sums[i]->acct_db_id,
						   sums[i]->txid);

		tal_arr_expand(&fee_sums, fee);
	}

	tal_free(sums);
	return fee_sums;
}

struct income_event **list_income_events(const tal_t *ctx,
					 struct db *db,
					 u64 start_time,
					 u64 end_time,
					 bool consolidate_fees)
{
	struct channel_event **channel_events;
	struct chain_event **chain_events;
	struct onchain_fee **onchain_fees;
	struct account **accts;

	struct income_event **evs;

	channel_events = list_channel_events_timebox(ctx, db,
						     start_time, end_time);
	chain_events = list_chain_events_timebox(ctx, db, start_time, end_time);
	accts = list_accounts(ctx, db);

	if (consolidate_fees) {
		onchain_fees = find_consolidated_fees(ctx, db,
						      start_time,
						      end_time);
	} else
		onchain_fees = list_chain_fees_timebox(ctx, db,
						       start_time, end_time);

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

			/* Report fees on payments, if present */
			if (streq(chan->tag, "invoice")
			    && !amount_msat_zero(chan->debit)
			    && !amount_msat_zero(chan->fees)) {
				if (!chan->rebalance_id)
					ev = paid_invoice_fee(evs, chan);
				else
					ev = rebalance_fee(evs, chan);
				tal_arr_expand(&evs, ev);
			}

			j++;
			continue;
		}

		/* Last thing left is the fee */
		tal_arr_expand(&evs, onchainfee_to_income(evs, fee));
		k++;
	}

	return evs;
}

struct income_event **list_income_events_all(const tal_t *ctx, struct db *db,
					     bool consolidate_fees)
{
	return list_income_events(ctx, db, 0, SQLITE_MAX_UINT,
				  consolidate_fees);
}

void json_add_income_event(struct json_stream *out, struct income_event *ev)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", ev->acct_name);
	json_add_string(out, "tag", ev->tag);
	json_add_amount_msat(out, "credit_msat", ev->credit);
	json_add_amount_msat(out, "debit_msat", ev->debit);
	json_add_string(out, "currency", ev->currency);
	json_add_u64(out, "timestamp", ev->timestamp);

	if (ev->desc)
		json_add_string(out, "description", ev->desc);

	if (ev->outpoint)
		json_add_outpoint(out, "outpoint", ev->outpoint);

	if (ev->txid)
		json_add_txid(out, "txid", ev->txid);

	if (ev->payment_id)
		json_add_sha256(out, "payment_id", ev->payment_id);

	json_object_end(out);
}

const char *csv_filename(const tal_t *ctx, const struct csv_fmt *fmt)
{
	return tal_fmt(ctx, "cln_incomestmt_%s_%lu.csv",
		       fmt->fmt_name,
		       (unsigned long)time_now().ts.tv_sec);
}

static char *convert_asset_type(struct income_event *ev)
{
	/* We use the bech32 human readable part which is "bc"
	 * for mainnet -> map to 'BTC' for cointracker */
	if (streq(ev->currency, "bc"))
		return "btc";

	return ev->currency;
}

static void cointrack_header(FILE *csvf)
{
	fprintf(csvf,
		"Date"
		",Received Quantity"
		",Received Currency"
		",Sent Quantity"
		",Sent Currency"
		",Fee Amount"
		",Fee Currency"
		",Tag"
		",Account");
}

static char *income_event_cointrack_type(const struct income_event *ev)
{
	/*  ['gift', 'lost', 'mined', 'airdrop', 'payment',
	 *  'fork', 'donation', 'staked'] */
	if (!amount_msat_zero(ev->debit)
	    && streq(ev->tag, "penalty"))
		return "lost";

	if (streq(ev->tag, "invoice")
	    || streq(ev->tag, "routed"))
		return "payment";

	/* Default to empty */
	return "";
}

static void cointrack_entry(const tal_t *ctx, FILE *csvf, struct income_event *ev)
{
	/* Date mm/dd/yyyy HH:MM:SS UTC */
	time_t tv;
	tv = ev->timestamp;
	char timebuf[sizeof("mm/dd/yyyy HH:MM:SS")];

	/* Cointrack counts invoice fee events inline */
	if (streq(ev->tag, account_entry_tag_str(INVOICEFEE)))
		return;

	fprintf(csvf, "\n");

	strftime(timebuf, sizeof(timebuf), "%m/%d/%Y %T", gmtime(&tv));
	fprintf(csvf, "%s", timebuf);
	fprintf(csvf, ",");

	/* Received Quantity + Received Currency */
	if (!amount_msat_zero(ev->credit)) {
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->credit, false));
		fprintf(csvf, ",");
		fprintf(csvf, "%s", convert_asset_type(ev));
	} else
		fprintf(csvf, ",");

	fprintf(csvf, ",");

	/* "Sent Quantity,Sent Currency," */
	if (!amount_msat_zero(ev->debit)) {
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->debit, false));
		fprintf(csvf, ",");
		fprintf(csvf, "%s", convert_asset_type(ev));
	} else
		fprintf(csvf, ",");

	fprintf(csvf, ",");

	/* "Fee Amount,Fee Currency," */
	if (!amount_msat_zero(ev->fees)
	    && streq(ev->tag, mvt_tag_str(INVOICE))) {
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->fees, false));
		fprintf(csvf, ",");
		fprintf(csvf, "%s", convert_asset_type(ev));
	} else
		fprintf(csvf, ",");

	fprintf(csvf, ",");

	/* Tag */
	fprintf(csvf, "%s", income_event_cointrack_type(ev));
	fprintf(csvf, ",");

	/* Account */
	fprintf(csvf, "%s", ev->acct_name);
}

static void koinly_header(FILE *csvf)
{
	fprintf(csvf,
		"Date"
		",Sent Amount"
		",Sent Currency"
		",Received Amount"
		",Received Currency"
		",Fee Amount"
		",Fee Currency"
		",Label"
		",Description"
		",TxHash");
}

static void koinly_entry(const tal_t *ctx, FILE *csvf, struct income_event *ev)
{
	/* Date */
	time_t tv;
	tv = ev->timestamp;
	/* 2018-01-01 14:25 UTC */
	char timebuf[sizeof("yyyy-mm-dd HH:MM UTC")];

	/* Koinly counts invoice fee events inline */
	if (streq(ev->tag, account_entry_tag_str(INVOICEFEE)))
		return;

	fprintf(csvf, "\n");

	strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M UTC", gmtime(&tv));
	fprintf(csvf, "%s", timebuf);
	fprintf(csvf, ",");

	/* "Sent Amount,Sent Currency," */
	if (!amount_msat_zero(ev->debit)) {
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->debit, false));
		fprintf(csvf, ",");
		fprintf(csvf, "%s", convert_asset_type(ev));
	} else
		fprintf(csvf, ",");

	fprintf(csvf, ",");

	/* Received Amount, Received Currency */
	if (!amount_msat_zero(ev->credit)) {
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->credit, false));
		fprintf(csvf, ",");
		fprintf(csvf, "%s", convert_asset_type(ev));
	} else
		fprintf(csvf, ",");

	fprintf(csvf, ",");


	/* "Fee Amount,Fee Currency," */
	if (!amount_msat_zero(ev->fees)
	    && streq(ev->tag, mvt_tag_str(INVOICE))) {
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->fees, false));
		fprintf(csvf, ",");
		fprintf(csvf, "%s", convert_asset_type(ev));
	} else
		fprintf(csvf, ",");

	fprintf(csvf, ",");

	/* Label */
	fprintf(csvf, "%s", ev->tag);
	fprintf(csvf, ",");

	/* Description */
	if (ev->desc)
		fprintf(csvf, "%s", csv_safe_str(ev, ev->desc));
	fprintf(csvf, ",");

	/* TxHash */
	if (ev->txid)
		fprintf(csvf, "%s",
			fmt_bitcoin_txid(ctx, ev->txid));
	else if (ev->payment_id)
		fprintf(csvf, "%s",
			fmt_sha256(ctx, ev->payment_id));
	else if (ev->outpoint)
		fprintf(csvf, "%s",
			fmt_bitcoin_outpoint(ctx, ev->outpoint));
}

static void harmony_header(FILE *csvf)
{
	/* Type Declaration */
	fprintf(csvf, "HarmonyCSV v0.2");
	/* Add 9 extra blank cols
	 * (so ea row has same # cols, which is csv spec) */
	fprintf(csvf, ",,,,,,,,,\n");

	/* Header Declarations */
	fprintf(csvf, "Provenance,cln-bookkeeper");
	/* Only 8 extra blank cols */
	fprintf(csvf, ",,,,,,,,\n");

	/* Blank Line */
	fprintf(csvf, ",,,,,,,,,\n");
	/* Entries */
	fprintf(csvf,
		"Timestamp" 	/* ISO-8601 */
		",Venue"
		",Type"
		",Amount"
		",Asset" 	/* currency */
		",Transaction ID"
		",Order ID" 	/* payment hash, if any */
		",Account"
		",Network ID"	/* outpoint */
		",Note"		/* tag */
		);
}

static char *income_event_harmony_type(const struct income_event *ev)
{
	/* From the v0.2 version of types:subtypes
	 * https://github.com/harmony-csv/harmony#entry-types */
	if (streq(ONCHAIN_FEE, ev->tag))
		return "fee:network";

	if (!amount_msat_zero(ev->credit)) {
		if (streq(WALLET_ACCT, ev->acct_name))
			return tal_fmt(ev, "transfer:%s", ev->tag);

		return tal_fmt(ev, "income:%s", ev->tag);
	}

	/* Ok otherwise it's a debit */
	if (streq("penalty", ev->tag)) {
		return "loss:penalty";
	}
	if (streq(WALLET_ACCT, ev->acct_name))
		return tal_fmt(ev, "transfer:%s", ev->tag);

	/* FIXME: add "fee:transfer" to invoice routing fees */

	return tal_fmt(ev, "expense:%s", ev->tag);
}

static void harmony_entry(const tal_t *ctx, FILE *csvf, struct income_event *ev)
{
	time_t tv;
	tv = ev->timestamp;
	/* datefmt: ISO-8601 */
	char timebuf[sizeof("yyyy-mm-ddTHH:MM:SSZ")];
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%TZ", gmtime(&tv));

	/* New line! */
	fprintf(csvf, "\n");

	fprintf(csvf, "%s", timebuf);
	fprintf(csvf, ",");

	/* ",Venue" */
	/* FIXME: use node_id ? */
	fprintf(csvf, "cln");
	fprintf(csvf, ",");

	/* ",Type" */
	fprintf(csvf, "%s", income_event_harmony_type(ev));
	fprintf(csvf, ",");

	/* ",Amount" */
	if (!amount_msat_zero(ev->debit)) {
		/* Debits are negative */
		fprintf(csvf, "-");
		fprintf(csvf, "%s",
			fmt_amount_msat_btc(ctx, ev->debit, false));
	} else
		fprintf(csvf, "%s",
			fmt_amount_msat_btc(ctx, ev->credit, false));

	fprintf(csvf, ",");

	/* ",Asset"  */
	fprintf(csvf, "%s", convert_asset_type(ev));
	fprintf(csvf, ",");

	/* ",Transaction ID" */
	/* Some of this data is duplicated in other fields.
	 * We don't have a standard 'txid' for every event though */
	if (ev->txid)
		fprintf(csvf, "%s",
			fmt_bitcoin_txid(ctx, ev->txid));
	else if (ev->payment_id)
		fprintf(csvf, "%s",
			fmt_sha256(ctx, ev->payment_id));
	else if (ev->outpoint)
		fprintf(csvf, "%s",
			fmt_bitcoin_outpoint(ctx, ev->outpoint));
	fprintf(csvf, ",");

	/* ",Order ID"  payment hash, if any */
	if (ev->payment_id)
		fprintf(csvf, "%s",
			fmt_sha256(ctx, ev->payment_id));
	fprintf(csvf, ",");

	/* ",Account" */
	fprintf(csvf, "%s", ev->acct_name);
	fprintf(csvf, ",");

	/* ",Network ID"  outpoint */
	if (ev->outpoint)
		fprintf(csvf, "%s",
			fmt_bitcoin_outpoint(ctx, ev->outpoint));
	fprintf(csvf, ",");

	/* ",Note"  description (may be NULL) */
	fprintf(csvf, "%s", ev->desc ? csv_safe_str(ev, ev->desc) : "");
}

static void quickbooks_header(FILE *csvf)
{
	fprintf(csvf,
		"Date"
		",Description"
		",Credit"
		",Debit"
		);
}

static void quickbooks_entry(const tal_t *ctx, FILE *csvf, struct income_event *ev)
{
	/* "Make sure the dates are in one format.
	 * We recommend you use: dd/mm/yyyy."
	 * from: https://quickbooks.intuit.com/learn-support/global/bank-transactions/import-bank-transactions-using-excel-csv-files/00/381530 */
	time_t tv;
	tv = ev->timestamp;
	/* datefmt: dd/mm/yyyy */
	char timebuf[sizeof("dd/mm/yyyy")];
	strftime(timebuf, sizeof(timebuf), "%d/%m/%Y", gmtime(&tv));

	/* New line! */
	fprintf(csvf, "\n");

	fprintf(csvf, "%s", timebuf);
	fprintf(csvf, ",");

	/* Description */
	fprintf(csvf, "%s (%s) %s: %s",
		ev->tag, ev->acct_name, ev->currency,
		ev->desc ? csv_safe_str(ev, ev->desc) : "no desc");
	fprintf(csvf, ",");

	/* Credit */
	if (!amount_msat_zero(ev->credit))
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->credit, false));

	fprintf(csvf, ",");

	/* Debit */
	if (!amount_msat_zero(ev->debit))
		fprintf(csvf, "%s", fmt_amount_msat_btc(ctx, ev->debit, false));
}

const struct csv_fmt csv_fmts[] = {
	{
		.fmt_name = "cointracker",
		.emit_header = cointrack_header,
		.emit_entry = cointrack_entry,
	},
	{
		.fmt_name = "koinly",
		.emit_header = koinly_header,
		.emit_entry = koinly_entry,
	},
	{
		.fmt_name = "harmony",
		.emit_header = harmony_header,
		.emit_entry = harmony_entry,
	},
	{
		.fmt_name = "quickbooks",
		.emit_header = quickbooks_header,
		.emit_entry = quickbooks_entry,
	},
};

const struct csv_fmt *csv_match_token(const char *buffer, const jsmntok_t *tok)
{
	for (size_t i = 0; i < ARRAY_SIZE(csv_fmts); i++) {
		if (json_tok_streq(buffer, tok, csv_fmts[i].fmt_name))
			return &csv_fmts[i];
	}

	return NULL;
}

const char *csv_list_fmts(const tal_t *ctx)
{
	char *fmtlist = tal(ctx, char);
	for (size_t i = 0; i < ARRAY_SIZE(csv_fmts); i++) {
		if (i > 0)
			tal_append_fmt(&fmtlist, ",");
		tal_append_fmt(&fmtlist, "\"%s\"", csv_fmts[i].fmt_name);
	}
	return (const char *) fmtlist;
}


char *csv_print_income_events(const tal_t *ctx,
			      const struct csv_fmt *csvfmt,
			      const char *filename,
			      struct income_event **evs)
{
	FILE *csvf;

	csvf = fopen(filename, "w");
	if (!csvf)
		return tal_fmt(ctx, "Failed to open csv file %s", filename);

	csvfmt->emit_header(csvf);
	for (size_t i = 0; i < tal_count(evs); i++)
		csvfmt->emit_entry(ctx, csvf, evs[i]);

	fclose(csvf);
	return NULL;
}
