#include "config.h"

#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/lease_rates.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/channelsapy.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>

#define BLOCK_YEAR 52364

static int cmp_channel_event_acct(struct channel_event *const *ev1,
				  struct channel_event *const *ev2,
				  void *unused UNUSED)
{
	if ((*ev1)->acct_db_id < (*ev2)->acct_db_id)
		return -1;
	else if ((*ev1)->acct_db_id > (*ev2)->acct_db_id)
		return 1;
	return 0;
}

static int cmp_acct(struct account *const *a1,
		    struct account *const *a2,
		    void *unused UNUSED)
{
	if ((*a1)->db_id < (*a2)->db_id)
		return -1;
	else if ((*a1)->db_id > (*a2)->db_id)
		return 1;
	return 0;
}

struct channel_apy *new_channel_apy(const tal_t *ctx)
{
	struct channel_apy *apy = tal(ctx, struct channel_apy);

	apy->routed_in = AMOUNT_MSAT(0);
	apy->routed_out = AMOUNT_MSAT(0);
	apy->fees_in = AMOUNT_MSAT(0);
	apy->fees_out = AMOUNT_MSAT(0);
	apy->push_in = AMOUNT_MSAT(0);
	apy->push_out = AMOUNT_MSAT(0);
	apy->lease_in = AMOUNT_MSAT(0);
	apy->lease_out = AMOUNT_MSAT(0);
	return apy;
}

bool channel_apy_sum(struct channel_apy *sum_apy,
		     const struct channel_apy *entry)
{
	bool ok;
	ok = amount_msat_add(&sum_apy->routed_in,
			     sum_apy->routed_in,
			     entry->routed_in);
	ok &= amount_msat_add(&sum_apy->routed_out,
			      sum_apy->routed_out,
			      entry->routed_out);
	ok &= amount_msat_add(&sum_apy->fees_in,
			      sum_apy->fees_in,
			      entry->fees_in);
	ok &= amount_msat_add(&sum_apy->fees_out,
			      sum_apy->fees_out,
			      entry->fees_out);
	ok &= amount_msat_add(&sum_apy->push_in,
			      sum_apy->push_in,
			      entry->push_in);
	ok &= amount_msat_add(&sum_apy->push_out,
			      sum_apy->push_out,
			      entry->push_out);
	ok &= amount_msat_add(&sum_apy->lease_in,
			      sum_apy->lease_in,
			      entry->lease_in);
	ok &= amount_msat_add(&sum_apy->lease_out,
			      sum_apy->lease_out,
			      entry->lease_out);

	ok &= amount_msat_add(&sum_apy->our_start_bal,
			      sum_apy->our_start_bal,
			      entry->our_start_bal);

	ok &= amount_msat_add(&sum_apy->total_start_bal,
			      sum_apy->total_start_bal,
			      entry->total_start_bal);

	if (sum_apy->start_blockheight > entry->start_blockheight)
		sum_apy->start_blockheight = entry->start_blockheight;

	if (sum_apy->end_blockheight < entry->end_blockheight)
		sum_apy->end_blockheight = entry->end_blockheight;

	return ok;
}

static struct account *search_account(struct account **accts, u64 acct_id)
{
	for (size_t i = 0; i < tal_count(accts); i++) {
		if (accts[i]->db_id == acct_id)
			return accts[i];
	}

	return NULL;
}

static void fillin_apy_acct_details(struct db *db,
				    const struct account *acct,
				    u32 current_blockheight,
				    struct channel_apy *apy)
{
	struct chain_event *ev;
	bool ok;

	apy->acct_name = tal_strdup(apy, acct->name);

	assert(acct->open_event_db_id);
	ev = find_chain_event_by_id(acct, db, *acct->open_event_db_id);
	assert(ev);

	apy->start_blockheight = ev->blockheight;
	apy->our_start_bal = ev->credit;
	apy->total_start_bal = ev->output_value;

	/* if this account is closed, add closing blockheight */
	if (acct->closed_event_db_id) {
		ev = find_chain_event_by_id(acct, db,
					    *acct->closed_event_db_id);
		assert(ev);
		apy->end_blockheight = ev->blockheight;
	} else
		apy->end_blockheight = current_blockheight;

	/* If there is any push_out or lease_fees_out, we subtract
	 * from starting balance */
	ok = amount_msat_sub(&apy->our_start_bal, apy->our_start_bal,
			     apy->push_out);
	assert(ok);
	ok = amount_msat_sub(&apy->our_start_bal, apy->our_start_bal,
			     apy->lease_out);
	assert(ok);

	/* we add values in to starting balance */
	ok = amount_msat_add(&apy->our_start_bal, apy->our_start_bal,
			     apy->push_in);
	assert(ok);
	ok = amount_msat_add(&apy->our_start_bal, apy->our_start_bal,
			     apy->lease_in);
	assert(ok);
}

struct channel_apy **compute_channel_apys(const tal_t *ctx, struct db *db,
					  u64 start_time,
					  u64 end_time,
					  u32 current_blockheight)
{
	struct channel_event **evs;
	struct channel_apy *apy, **apys;
	struct account *acct, **accts;

	evs = list_channel_events_timebox(ctx, db, start_time, end_time);
	accts = list_accounts(ctx, db);

	apys = tal_arr(ctx, struct channel_apy *, 0);

	/* Sort events by acct_name */
	asort(evs, tal_count(evs), cmp_channel_event_acct, NULL);
	/* Sort accounts by name also */
	asort(accts, tal_count(accts), cmp_acct, NULL);

	acct = NULL;
	apy = new_channel_apy(apys);
	for (size_t i = 0; i < tal_count(evs); i++) {
		struct channel_event *ev = evs[i];
		bool ok;

		if (!acct || acct->db_id != ev->acct_db_id) {
			if (acct && is_channel_account(acct)) {
				fillin_apy_acct_details(db, acct,
							current_blockheight,
							apy);
				/* Save current apy, make new */
				tal_arr_expand(&apys, apy);
				apy = new_channel_apy(apys);
			}
			acct = search_account(accts, ev->acct_db_id);
			assert(acct);
		}

		/* No entry for external or wallet accts */
		if (!is_channel_account(acct))
			continue;

		/* Accumulate routing stats */
		if (streq("routed", ev->tag)
		    || streq("invoice", ev->tag)) {
			ok = amount_msat_add(&apy->routed_in,
					     apy->routed_in,
					     ev->credit);
			assert(ok);
			ok = amount_msat_add(&apy->routed_out,
					     apy->routed_out,
					     ev->debit);
			assert(ok);

			/* No fees for invoices */
			if (streq("invoice", ev->tag))
				continue;

			if (!amount_msat_zero(ev->credit))
				ok = amount_msat_add(&apy->fees_in,
						     apy->fees_in,
						     ev->fees);
			else
				ok = amount_msat_add(&apy->fees_out,
						     apy->fees_out,
						     ev->fees);
			assert(ok);
		}
		else if (streq("pushed", ev->tag)) {
			ok = amount_msat_add(&apy->push_in,
					     apy->push_in,
					     ev->credit);
			assert(ok);
			ok = amount_msat_add(&apy->push_out,
					     apy->push_out,
					     ev->debit);
			assert(ok);
		} else if (streq("lease_fee", ev->tag)) {
			ok = amount_msat_add(&apy->lease_in,
					     apy->lease_in,
					     ev->credit);
			assert(ok);
			ok = amount_msat_add(&apy->lease_out,
					     apy->lease_out,
					     ev->debit);
			assert(ok);
		}

		/* Note: we ignore 'journal_entry's because there's no
		 * relevant fee data attached to them */
	}

	if (acct && is_channel_account(acct)) {
		fillin_apy_acct_details(db, acct,
					current_blockheight,
					apy);
		/* Save current apy, make new */
		tal_arr_expand(&apys, apy);
	}

	return apys;
}

WARN_UNUSED_RESULT static bool calc_apy(struct amount_msat earned,
					struct amount_msat capital,
					u32 blocks_elapsed,
					double *result)
{
	double apy;

	assert(!amount_msat_zero(capital));
	assert(blocks_elapsed > 0);

	apy = amount_msat_ratio(earned, capital) * BLOCK_YEAR / blocks_elapsed;

	/* convert to percent */
	apy *= 100;

	/* If mantissa is < 64 bits, a naive "if (scaled >
	 * UINT64_MAX)" doesn't work.  Stick to powers of 2. */
	if (apy >= (double)((u64)1 << 63) * 2)
		return false;

	*result = apy;
	return true;
}

void json_add_channel_apy(struct json_stream *res,
			  const struct channel_apy *apy)
{
	bool ok;
	u32 blocks_elapsed;
	double apy_result, utilization;
	struct amount_msat total_fees, their_start_bal;

	ok = amount_msat_sub(&their_start_bal, apy->total_start_bal,
			     apy->our_start_bal);
	assert(ok);

	json_object_start(res, NULL);

	json_add_string(res, "account", apy->acct_name);

	json_add_amount_msat(res, "routed_out_msat", apy->routed_out);
	json_add_amount_msat(res, "routed_in_msat", apy->routed_in);
	json_add_amount_msat(res, "lease_fee_paid_msat", apy->lease_out);
	json_add_amount_msat(res, "lease_fee_earned_msat", apy->lease_in);
	json_add_amount_msat(res, "pushed_out_msat", apy->push_out);
	json_add_amount_msat(res, "pushed_in_msat", apy->push_in);

	json_add_amount_msat(res, "our_start_balance_msat", apy->our_start_bal);
	json_add_amount_msat(res, "channel_start_balance_msat",
			     apy->total_start_bal);

	ok = amount_msat_add(&total_fees, apy->fees_in, apy->fees_out);
	assert(ok);
	json_add_amount_msat(res, "fees_out_msat", apy->fees_out);
	json_add_amount_msat(res, "fees_in_msat", apy->fees_in);

	/* utilization (out): routed_out/total_balance */
	assert(!amount_msat_zero(apy->total_start_bal));
	utilization = amount_msat_ratio(apy->routed_out, apy->total_start_bal);
	json_add_string(res, "utilization_out",
			tal_fmt(apy, "%.4f%%", utilization * 100));

	if (!amount_msat_zero(apy->our_start_bal)) {
		utilization = amount_msat_ratio(apy->routed_out,
						apy->our_start_bal);
		json_add_string(res, "utilization_out_initial",
				tal_fmt(apy, "%.4f%%", utilization * 100));
	}

	/* utilization (in): routed_in/total_balance */
	utilization = amount_msat_ratio(apy->routed_in, apy->total_start_bal);
	json_add_string(res, "utilization_in",
			tal_fmt(apy, "%.4f%%", utilization * 100));

	if (!amount_msat_zero(their_start_bal)) {
		utilization = amount_msat_ratio(apy->routed_in,
						their_start_bal);
		json_add_string(res, "utilization_in_initial",
				tal_fmt(apy, "%.4f%%", utilization * 100));
	}

	/* Can't divide by zero */
	blocks_elapsed = apy->end_blockheight - apy->start_blockheight + 1;

	/* APY (outbound) */
	ok = calc_apy(apy->fees_out, apy->total_start_bal,
		      blocks_elapsed, &apy_result);
	assert(ok);
	json_add_string(res, "apy_out", tal_fmt(apy, "%.4f%%", apy_result));

	/* APY (outbound, initial) */
	if (!amount_msat_zero(apy->our_start_bal)) {
		ok = calc_apy(apy->fees_out, apy->our_start_bal,
			      blocks_elapsed, &apy_result);
		assert(ok);
		json_add_string(res, "apy_out_initial",
				tal_fmt(apy, "%.4f%%", apy_result));
	}

	/* APY (inbound) */
	ok = calc_apy(apy->fees_in, apy->total_start_bal,
		      blocks_elapsed, &apy_result);
	assert(ok);
	json_add_string(res, "apy_in", tal_fmt(apy, "%.4f%%", apy_result));

	if (!amount_msat_zero(their_start_bal)) {
		ok = calc_apy(apy->fees_in, their_start_bal,
			      blocks_elapsed, &apy_result);
		assert(ok);
		json_add_string(res, "apy_in_initial",
				tal_fmt(apy, "%.4f%%", apy_result));
	}

	/* APY (total) */
	ok = calc_apy(total_fees, apy->total_start_bal,
		      blocks_elapsed, &apy_result);
	assert(ok);
	json_add_string(res, "apy_total", tal_fmt(apy, "%.4f%%", apy_result));

	if (!amount_msat_zero(apy->our_start_bal)) {
		ok = calc_apy(total_fees, apy->total_start_bal,
			      blocks_elapsed, &apy_result);
		assert(ok);
		json_add_string(res, "apy_total_initial",
				tal_fmt(apy, "%.4f%%", apy_result));
	}

	/* If you earned fees for leasing funds, calculate APY
	 * Note that this is a bit higher than it *should* be,
	 * given that the onchainfees are partly covered here */
	if (!amount_msat_zero(apy->lease_in)) {
		struct amount_msat start_no_lease_in;

		/* We added the lease in to the starting balance, so we
		 * should subtract it out again before finding APY */
		ok = amount_msat_sub(&start_no_lease_in,
				     apy->our_start_bal,
				     apy->lease_in);
		assert(ok);
		ok = calc_apy(apy->lease_in, start_no_lease_in,
			      /* we use the lease rate duration here! */
			      LEASE_RATE_DURATION, &apy_result);
		assert(ok);
		json_add_string(res, "apy_lease",
				tal_fmt(apy, "%.4f%%", apy_result));
	}

	json_object_end(res);
}

