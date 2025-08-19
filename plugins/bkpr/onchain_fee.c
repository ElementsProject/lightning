#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/asort/asort.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/intmap/intmap.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <inttypes.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

/* We keep a hash of onchain_fee arrays.  Each array is sorted. */

/* Sort these as ORDER BY timestamp, account_name, txid, update_count */
static int compare_onchain_fee(struct onchain_fee *const *a,
			       struct onchain_fee *const *b,
			       void *arg)
{
	const struct onchain_fee *ofa = *a, *ofb = *b;
	int cmp;

	if (ofa->timestamp < ofb->timestamp)
		return -1;
	if (ofa->timestamp > ofb->timestamp)
		return 1;
	cmp = strcmp(ofa->acct_name, ofb->acct_name);
	if (cmp)
		return cmp;
	cmp = memcmp(&ofa->txid, &ofb->txid, sizeof(ofb->txid));
	if (cmp)
		return cmp;
	if (ofa->update_count < ofb->update_count)
		return -1;
	if (ofa->update_count > ofb->update_count)
		return 1;
	return 0;
}

static void order_fees(struct onchain_fee **ofs)
{
	asort(ofs, tal_count(ofs), compare_onchain_fee, NULL);
}

/* Convenience struct: array is always in compare_onchain_fee order! */
struct ordered_ofees {
	struct onchain_fee **ofs;
};

static size_t hash_acctname(const char *str)
{
	return siphash24(siphash_seed(), str, strlen(str));
}

static const char *onchain_fees_keyof(const struct ordered_ofees *ofees)
{
	return ofees->ofs[0]->acct_name;
}

static bool onchain_account_eq(const struct ordered_ofees *ofees,
			       const char *acct_name)
{
	return streq(ofees->ofs[0]->acct_name, acct_name);
}

HTABLE_DEFINE_NODUPS_TYPE(struct ordered_ofees,
			  onchain_fees_keyof,
			  hash_acctname,
			  onchain_account_eq,
			  ofees_hash);

struct onchain_fees {
	/* Hash table by account. */
	struct ofees_hash *by_account;
};

static void destroy_onchain_fee(struct onchain_fee *of,
				struct ofees_hash *ofees_hash)
{
	struct ordered_ofees *ofees = ofees_hash_get(ofees_hash,
						     of->acct_name);
	/* Only one in array?  Must be this. */
	if (tal_count(ofees->ofs) == 1) {
		ofees_hash_del(ofees_hash, ofees);
		assert(ofees->ofs[0] == of);
		tal_free(ofees);
		return;
	}
	for (size_t i = 0; i < tal_count(ofees->ofs); i++) {
		if (ofees->ofs[i] == of) {
			tal_arr_remove(&ofees->ofs, i);
			return;
		}
	}
	abort();
}

static struct onchain_fee *new_onchain_fee(struct onchain_fees *onchain_fees,
					   const char *acct_name TAKES,
					   const struct bitcoin_txid *txid,
					   struct amount_msat credit,
					   struct amount_msat debit,
					   u64 timestamp,
					   u32 update_count)
{
	struct onchain_fee *of = tal(NULL, struct onchain_fee);
	struct ordered_ofees *ofees;

	of->acct_name = tal_strdup(of, acct_name);
	of->txid = *txid;
	of->credit = credit;
	of->debit = debit;
	of->timestamp = timestamp;
	of->update_count = update_count;

	/* Add to sorted array in hash table */
	ofees = ofees_hash_get(onchain_fees->by_account, of->acct_name);
	if (ofees) {
		tal_arr_expand(&ofees->ofs, of);
		order_fees(ofees->ofs);
	} else {
		ofees = tal(onchain_fees->by_account, struct ordered_ofees);
		ofees->ofs = tal_arr(ofees, struct onchain_fee *, 1);
		ofees->ofs[0] = of;
		ofees_hash_add(onchain_fees->by_account, ofees);
	}
	tal_steal(ofees->ofs, of);

	tal_add_destructor2(of, destroy_onchain_fee, onchain_fees->by_account);
	return of;
}

static void towire_onchain_fee(u8 **pptr, const struct onchain_fee *of)
{
	towire_wirestring(pptr, of->acct_name);
	towire_bitcoin_txid(pptr, &of->txid);
	towire_amount_msat(pptr, of->credit);
	towire_amount_msat(pptr, of->debit);
	towire_u64(pptr, of->timestamp);
	towire_u32(pptr, of->update_count);
}

static struct onchain_fee *fromwire_onchain_fee(struct onchain_fees *onchain_fees,
						const u8 **pptr, size_t *max)
{
	const char *acctname;
	struct bitcoin_txid txid;
	struct amount_msat credit;
	struct amount_msat debit;
	u64 timestamp;
	u32 update_count;

	acctname = fromwire_wirestring(tmpctx, pptr, max);
	fromwire_bitcoin_txid(pptr, max, &txid);
	credit = fromwire_amount_msat(pptr, max);
	debit = fromwire_amount_msat(pptr, max);
	timestamp = fromwire_u64(pptr, max);
	update_count = fromwire_u32(pptr, max);
	if (pptr == NULL)
		return NULL;

	return new_onchain_fee(onchain_fees,
			       take(acctname), &txid, credit, debit, timestamp,
			       update_count);
}

static const char *ds_ofee_path(const tal_t *ctx, const char *acctname)
{
	return tal_fmt(ctx, "bookkeeper/onchain_fee/%s", acctname);
}

static void onchain_fee_datastore_add(struct command *cmd,
				      const struct onchain_fee *of)
{
	const char *path = ds_ofee_path(tmpctx, of->acct_name);
	u8 *data = tal_arr(tmpctx, u8, 0);

	towire_onchain_fee(&data, of);
	jsonrpc_set_datastore_binary(cmd, path, data, tal_bytelen(data),
				     "create-or-append",
				     ignore_datastore_reply, NULL, NULL);
}

void json_add_onchain_fee(struct json_stream *out,
			  const struct onchain_fee *fee)
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

/* Get all onchain_fee for this account */
struct onchain_fee **account_get_chain_fees(const tal_t *ctx,
					    const struct bkpr *bkpr,
					    const char *acct_name)
{
	struct ordered_ofees *ofees;

	ofees = ofees_hash_get(bkpr->onchain_fees->by_account, acct_name);
	if (ofees)
		return tal_dup_talarr(ctx, struct onchain_fee *, ofees->ofs);
	return NULL;
}

/* FIXME: Slow */
struct onchain_fee **get_chain_fees_by_txid(const tal_t *ctx,
					    const struct bkpr *bkpr,
					    const struct bitcoin_txid *txid)
{
	struct onchain_fee **ret = tal_arr(ctx, struct onchain_fee *, 0);
	struct ofees_hash_iter it;
	struct ordered_ofees *ofees;

	for (ofees = ofees_hash_first(bkpr->onchain_fees->by_account, &it);
	     ofees;
	     ofees = ofees_hash_next(bkpr->onchain_fees->by_account, &it)) {
		for (size_t i = 0; i < tal_count(ofees->ofs); i++) {
			if (bitcoin_txid_eq(&ofees->ofs[i]->txid, txid))
				tal_arr_expand(&ret, ofees->ofs[i]);
		}
	}
	order_fees(ret);
	return ret;
}

/* FIXME: slow */
struct onchain_fee **list_chain_fees_timebox(const tal_t *ctx,
					     const struct bkpr *bkpr,
					     u64 start_time, u64 end_time)
{
	struct onchain_fee **ret = tal_arr(ctx, struct onchain_fee *, 0);
	struct ofees_hash_iter it;
	struct ordered_ofees *ofees;

	for (ofees = ofees_hash_first(bkpr->onchain_fees->by_account, &it);
	     ofees;
	     ofees = ofees_hash_next(bkpr->onchain_fees->by_account, &it)) {
		for (size_t i = 0; i < tal_count(ofees->ofs); i++) {
			if (ofees->ofs[i]->timestamp <= start_time)
				continue;
			if (ofees->ofs[i]->timestamp > end_time)
				continue;
			tal_arr_expand(&ret, ofees->ofs[i]);
		}
	}
	order_fees(ret);
	return ret;
}

struct onchain_fee **list_chain_fees(const tal_t *ctx, const struct bkpr *bkpr)
{
	return list_chain_fees_timebox(ctx, bkpr, 0, SQLITE_MAX_UINT);
}

static void insert_chain_fees_diff(struct command *cmd,
				   struct bkpr *bkpr,
				   const char *acct_name,
				   struct bitcoin_txid *txid,
				   struct amount_msat amount,
				   u64 timestamp)
{
	struct onchain_fee *of, **ofs;
	u32 max_update_count = 0;
	struct amount_msat current_amt, credit, debit;

	current_amt = AMOUNT_MSAT(0);
	ofs = account_get_chain_fees(tmpctx, bkpr, acct_name);

	for (size_t i = 0; i < tal_count(ofs); i++) {
		if (!bitcoin_txid_eq(&ofs[i]->txid, txid))
			continue;
		if (!amount_msat_accumulate(&current_amt, ofs[i]->credit))
			plugin_err(cmd->plugin, "Overflow when adding onchain fees");

		if (!amount_msat_sub(&current_amt, current_amt, ofs[i]->debit))
			plugin_err(cmd->plugin, "Underflow when subtracting onchain fees");
		if (ofs[i]->update_count > max_update_count)
			max_update_count = ofs[i]->update_count;
	}

	/* If they're already equal, no need to update */
	if (amount_msat_eq(current_amt, amount))
		return;

	if (!amount_msat_sub(&credit, amount, current_amt)) {
		credit = AMOUNT_MSAT(0);
		if (!amount_msat_sub(&debit, current_amt, amount))
			plugin_err(cmd->plugin, "shouldn't happen, unable to subtract");
	} else
		debit = AMOUNT_MSAT(0);

	of = new_onchain_fee(bkpr->onchain_fees,
			     acct_name, txid, credit, debit, timestamp,
			     max_update_count+1);
	onchain_fee_datastore_add(cmd, of);
}

/* Sort these as ORDER BY txid, account_name */
static int compare_onchain_fee_txid_account(struct onchain_fee *const *a,
					    struct onchain_fee *const *b,
					    void *arg)
{
	const struct onchain_fee *ofa = *a, *ofb = *b;
	int cmp;

	cmp = memcmp(&ofa->txid, &ofb->txid, sizeof(ofb->txid));
	if (cmp)
		return cmp;
	return strcmp(ofa->acct_name, ofb->acct_name);
}

static void finalize_sum(struct fee_sum ***sums,
			 struct fee_sum *sum,
			 struct amount_msat credit,
			 struct amount_msat debit)
{
	bool ok;
	ok = amount_msat_sub(&sum->fees_paid, credit, debit);
	assert(ok);
	tal_arr_expand(sums, sum);
}

/* Add up each account/txid group into a fee_sum */
static struct fee_sum **fee_sums_by_txid_and_account(const tal_t *ctx,
						     struct onchain_fee **ofs)
{
	struct fee_sum **sums, *sum;
	struct amount_msat credit, debit;
	bool ok;

	/* We want this ordered by txid, accountname */
	if (ofs) /* Keep pendantic sanity checker happy! */
		asort(ofs, tal_count(ofs), compare_onchain_fee_txid_account, NULL);

	sums = tal_arr(ctx, struct fee_sum *, 0);
	sum = NULL;

	/* Now for each txid, account_name pair, create a sum */
	for (size_t i = 0; i < tal_count(ofs); i++) {
		/* If this is a new group, end the previous. */
		if (sum
		    && (!bitcoin_txid_eq(&ofs[i]->txid, sum->txid)
			|| !streq(ofs[i]->acct_name, sum->acct_name))) {
			finalize_sum(&sums, sum, credit, debit);
			sum = NULL;
		}
		if (!sum) {
			sum = tal(sums, struct fee_sum);
			sum->acct_name = tal_strdup(sum, ofs[i]->acct_name);
			sum->txid = tal_dup(sum, struct bitcoin_txid,
					    &ofs[i]->txid);
			credit = debit = AMOUNT_MSAT(0);
		}
		ok = amount_msat_accumulate(&credit, ofs[i]->credit);
		assert(ok);
		ok = amount_msat_accumulate(&debit, ofs[i]->debit);
	}

	/* Final, if any */
	if (sum)
		finalize_sum(&sums, sum, credit, debit);

	return sums;
}

struct fee_sum **calculate_onchain_fee_sums(const tal_t *ctx,
					    const struct bkpr *bkpr)
{
	struct onchain_fee **ofs;

	ofs = list_chain_fees(tmpctx, bkpr);
	return fee_sums_by_txid_and_account(ctx, ofs);
}

char *update_channel_onchain_fees(const tal_t *ctx,
				  struct command *cmd,
				  struct bkpr *bkpr,
				  struct account *acct)
{
	struct chain_event *close_ev, **events;
	struct amount_msat onchain_amt;

	assert(acct->onchain_resolved_block);
	close_ev = find_chain_event_by_id(ctx, bkpr->db,
					  *acct->closed_event_db_id);
	events = find_chain_events_bytxid(ctx, bkpr->db,
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

		insert_chain_fees_diff(cmd, bkpr, acct->name,
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
				struct command *cmd,
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
			insert_chain_fees_diff(cmd, bkpr, last_acctname, txid,
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

		insert_chain_fees_diff(cmd, bkpr, last_acctname, txid, fees,
				       events[i]->timestamp);

	}

finished:
	tal_free(inner_ctx);
	return err;
}

struct fee_sum **find_account_onchain_fees(const tal_t *ctx,
					   const struct bkpr *bkpr,
					   const struct account *acct)
{
	struct onchain_fee **ofs;

	ofs = account_get_chain_fees(tmpctx, bkpr, acct->name);
	return fee_sums_by_txid_and_account(ctx, ofs);
}

/* FIXME: Put this value into fee_sums! */
u64 onchain_fee_last_timestamp(const struct bkpr *bkpr,
			       const char *acct_name,
			       const struct bitcoin_txid *txid)
{
	struct onchain_fee **ofs;
	u64 timestamp = 0;

	ofs = account_get_chain_fees(tmpctx, bkpr, acct_name);
	for (size_t i = 0; i < tal_count(ofs); i++) {
		if (!bitcoin_txid_eq(&ofs[i]->txid, txid))
			continue;
		if (ofs[i]->timestamp > timestamp)
			timestamp = ofs[i]->timestamp;
	}
	return timestamp;
}

/* If we're freeing the entire hash table, remove destructors from
 * individual entries! */
static void ofees_hash_destroy(struct ofees_hash *ofees_hash)
{
	struct ofees_hash_iter it;
	struct ordered_ofees *ofees;

	for (ofees = ofees_hash_first(ofees_hash, &it);
	     ofees;
	     ofees = ofees_hash_next(ofees_hash, &it)) {
		for (size_t i = 0; i < tal_count(ofees->ofs); i++) {
			tal_del_destructor2(ofees->ofs[i],
					    destroy_onchain_fee, ofees_hash);
		}
	}
}

static void memleak_scan_ofees_hash(struct htable *memtable,
				    struct ofees_hash *ht)
{
	memleak_scan_htable(memtable, &ht->raw);
}

struct onchain_fees *init_onchain_fees(const tal_t *ctx,
				       struct command *init_cmd)
{
	struct onchain_fees *onchain_fees = tal(ctx, struct onchain_fees);
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;

	onchain_fees->by_account = tal(onchain_fees, struct ofees_hash);
	ofees_hash_init(onchain_fees->by_account);
	tal_add_destructor(onchain_fees->by_account, ofees_hash_destroy);
	memleak_add_helper(onchain_fees->by_account, memleak_scan_ofees_hash);

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bookkeeper");
	json_out_addstr(params, NULL, "onchain_fee");
	json_out_end(params, ']');
	json_out_end(params, '}');
	result = jsonrpc_request_sync(tmpctx, init_cmd,
				      "listdatastore",
				      params, &buf);

	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		size_t datalen;
		const jsmntok_t *key, *datatok;
		const u8 *data;

		/* Key is an array, first two elements are bookkeeper, onchain_fee */
		key = json_get_member(buf, t, "key") + 3;
		datatok = json_get_member(buf, t, "hex");
		/* In case someone creates a subdir? */
		if (!datatok)
			continue;

		data = json_tok_bin_from_hex(tmpctx, buf, datatok);
		datalen = tal_bytelen(data);

		while (datalen != 0) {
			if (!fromwire_onchain_fee(onchain_fees, &data, &datalen))
				plugin_err(init_cmd->plugin,
					   "Invalid onchain_fee for %.*s in datastore",
					   json_tok_full_len(key),
					   json_tok_full(buf, key));
		}
	}
	return onchain_fees;
}
