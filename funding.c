#include "funding.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/structeq/structeq.h>
#include <string.h>

static bool subtract_fees(uint64_t *funder, uint64_t *non_funder,
			  uint64_t *funder_fee, uint64_t *non_funder_fee,
			  bool non_funder_paying, uint64_t fee)
{
	/* Funder gets 1 millisatsoshi rounding benefit! */
	*non_funder_fee = fee - fee / 2;

	if (*non_funder < *non_funder_fee) {
		/*
		 * This happens initially, as funder has all the money.
		 * That's OK, but don't let non-funder spend if they can't
		 * cover fee.
		 */
		if (non_funder_paying)
			return false;

		/* Pay everything they can, funder pays rest. */
		*non_funder_fee = *non_funder;
	}

	/* Funder must always ensure they can pay their share. */
	*funder_fee = fee - *non_funder_fee;
	if (*funder < *funder_fee)
		return false;

	*non_funder -= *non_funder_fee;
	*funder -= *funder_fee;
	return true;
}

/* Total, in millisatoshi. */
static uint64_t htlcs_total(const struct channel_htlc *htlcs)
{
	size_t i, n = tal_count(htlcs);
	uint64_t total = 0;

	for (i = 0; i < n; i++)
		total += htlcs[i].msatoshis;
	return total;
}

static bool change_funding(uint64_t anchor_satoshis,
			   int64_t delta_a_msat,
			   int64_t htlc_msat,
			   uint64_t a, uint64_t b, uint64_t fee,
			   struct channel_oneside *a_side,
			   struct channel_oneside *b_side)
{
	uint64_t a_fee, b_fee;
	int64_t delta_b_msat;
	bool got_fees;

	assert(a + b + htlcs_total(a_side->htlcs) + htlcs_total(b_side->htlcs)
	       == anchor_satoshis * 1000);
	assert(a_side->offered_anchor != b_side->offered_anchor);

	/* B gets whatever A gives. */
	delta_b_msat = -delta_a_msat;
	/* A also pays for the htlc (if any). */
	delta_a_msat -= htlc_msat;

	/* Transferring more than we have? */
	if (delta_b_msat < 0 && -delta_b_msat > b)
		return false;
	if (delta_a_msat < 0 && -delta_a_msat > a)
		return false;

	/* Adjust amounts. */
	a += delta_a_msat;
	b += delta_b_msat;

	/* Take off fee from both parties if possible. */
	if (a_side->offered_anchor)
		got_fees = subtract_fees(&a, &b, &a_fee, &b_fee,
					 delta_b_msat < 0, fee);
	else
		got_fees = subtract_fees(&b, &a, &b_fee, &a_fee,
					 delta_a_msat < 0, fee);

	if (!got_fees)
		return false;

	/* Now we know we're succeeding, update caller's state */
	a_side->pay_msat = a;
	b_side->pay_msat = b;
	a_side->fee_msat = a_fee;
	b_side->fee_msat = b_fee;
	return true;
}

bool funding_delta(uint64_t anchor_satoshis,
		   int64_t delta_a_msat,
		   int64_t htlc_msat,
		   struct channel_oneside *a_side,
		   struct channel_oneside *b_side)
{
	uint64_t a, b;
	uint64_t fee;

	/* Start with A and B's current contributions, and maintain fee. */
	a = a_side->pay_msat + a_side->fee_msat;
	b = b_side->pay_msat + b_side->fee_msat;
	fee = a_side->fee_msat + b_side->fee_msat;

	return change_funding(anchor_satoshis,
			      delta_a_msat, htlc_msat,
			      a, b, fee,
			      a_side, b_side);
}

struct channel_state *initial_funding(const tal_t *ctx,
				      bool am_funder,
				      uint64_t anchor_satoshis,
				      uint64_t fee)
{
	struct channel_state *cstate = talz(ctx, struct channel_state);

	cstate->a.htlcs = tal_arr(cstate, struct channel_htlc, 0);
	cstate->b.htlcs = tal_arr(cstate, struct channel_htlc, 0);
	
	if (fee > anchor_satoshis)
		return tal_free(cstate);

	if (anchor_satoshis > (1ULL << 32) / 1000)
		return tal_free(cstate);
	
	/* Initially, all goes back to funder. */
	cstate->a.pay_msat = anchor_satoshis * 1000 - fee * 1000;
	cstate->a.fee_msat = fee * 1000;
	cstate->a.offered_anchor = true;
	cstate->b.offered_anchor = false;

	/* If B (not A) is funder, invert. */
	if (!am_funder)
		invert_cstate(cstate);

	/* Make sure it checks out. */
	assert(funding_delta(anchor_satoshis, 0, 0, &cstate->a, &cstate->b));
	return cstate;
}

bool adjust_fee(uint64_t anchor_satoshis,
		uint64_t fee_satoshis,
		struct channel_oneside *a_side,
		struct channel_oneside *b_side)
{
	uint64_t a, b;

	a = a_side->pay_msat + a_side->fee_msat;
	b = b_side->pay_msat + b_side->fee_msat;

	/* No HTLC or delta, just fee recalculate. */
	return change_funding(anchor_satoshis,
			      0, 0, a, b, fee_satoshis * 1000,
			      a_side, b_side);
}
	
/* We take the minimum.  If one side offers too little, it should be rejected */
uint64_t commit_fee(uint64_t a_satoshis, uint64_t b_satoshis)
{
	if (a_satoshis < b_satoshis)
		return a_satoshis;
	return b_satoshis;
}

void invert_cstate(struct channel_state *cstate)
{
	struct channel_oneside tmp;

	tmp = cstate->a;
	cstate->a = cstate->b;
	cstate->b = tmp;
}

void funding_add_htlc(struct channel_oneside *creator,
		      u32 msatoshis, const struct abs_locktime *expiry,
		      const struct sha256 *rhash)
{
	size_t n = tal_count(creator->htlcs);
	tal_resize(&creator->htlcs, n+1);

	creator->htlcs[n].msatoshis = msatoshis;
	creator->htlcs[n].expiry = *expiry;
	creator->htlcs[n].rhash = *rhash;
	memcheck(&creator->htlcs[n].msatoshis,
		 sizeof(creator->htlcs[n].msatoshis));
	memcheck(&creator->htlcs[n].rhash, sizeof(creator->htlcs[n].rhash));
}

size_t funding_find_htlc(struct channel_oneside *creator,
			 const struct sha256 *rhash)
{
	size_t i;

	for (i = 0; i < tal_count(creator->htlcs); i++) {
		if (structeq(&creator->htlcs[i].rhash, rhash))
			break;
	}
	return i;
}

void funding_remove_htlc(struct channel_oneside *creator, size_t i)
{
	size_t n = tal_count(creator->htlcs);
	assert(i < n);
	memmove(creator->htlcs + i, creator->htlcs + i + 1,
		(n - i - 1) * sizeof(*creator->htlcs));
	tal_resize(&creator->htlcs, n-1);
}

struct channel_state *copy_funding(const tal_t *ctx,
				   const struct channel_state *cstate)
{
	struct channel_state *cs = tal_dup(ctx, struct channel_state, cstate);

	cs->a.htlcs = tal_dup_arr(cs, struct channel_htlc, cs->a.htlcs,
				  tal_count(cs->a.htlcs), 0);
	cs->b.htlcs = tal_dup_arr(cs, struct channel_htlc, cs->b.htlcs,
				  tal_count(cs->b.htlcs), 0);
	return cs;
}
