#include "funding.h"
#include <assert.h>
#include <string.h>

static bool is_funder(const OpenChannel *o)
{
	return o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR;
}

static bool subtract_fees(uint64_t *funder, uint64_t *non_funder,
			  uint64_t *funder_fee, uint64_t *non_funder_fee,
			  bool non_funder_paying, uint64_t fee)
{
	/* Funder gets 1 satsoshi rounding benefit! */
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
	
bool funding_delta(const OpenChannel *oa,
		   const OpenChannel *ob,
		   const OpenAnchor *anchor,
		   int64_t delta_a,
		   struct channel_oneside *a_side,
		   struct channel_oneside *b_side)
{
	uint64_t a, b, a_fee, b_fee;
	uint64_t fee;
	bool got_fees;

	a = a_side->pay + a_side->fee;
	b = b_side->pay + b_side->fee;
	fee = a_side->fee + b_side->fee;
	assert(a + b == anchor->amount);

	/* Only one can be funder. */
	if (is_funder(oa) == is_funder(ob))
		return false;

	/* Transferring more than we have? */
	if (delta_a > 0 && delta_a > b)
		return false;
	if (delta_a < 0 && -delta_a > a)
		return false;

	/* Adjust amounts. */
	a += delta_a;
	b -= delta_a;

	/* Take off fee from both parties if possible. */
	if (is_funder(oa))
		got_fees = subtract_fees(&a, &b, &a_fee, &b_fee,
					 delta_a > 0, fee);
	else
		got_fees = subtract_fees(&b, &a, &b_fee, &a_fee,
					 delta_a < 0, fee);

	if (!got_fees)
		return false;

	/* Now we know we're succeeding, update caller's state */
	a_side->pay = a;
	b_side->pay = b;
	a_side->fee = a_fee;
	b_side->fee = b_fee;
	return true;
}

struct channel_state *initial_funding(const tal_t *ctx,
				      const OpenChannel *a,
				      const OpenChannel *b,
				      const OpenAnchor *anchor,
				      uint64_t fee)
{
	struct channel_state *state = talz(ctx, struct channel_state);

	if (fee > anchor->amount)
		return tal_free(state);

	/* Initially, all goes back to funder. */
	state->a.pay = anchor->amount - fee;
	state->a.fee = fee;

	/* If B (not A) is funder, invert. */
	if (is_funder(b))
		invert_cstate(state);

	/* This checks we only have 1 anchor, and is nice code reuse. */
	if (!funding_delta(a, b, anchor, 0, &state->a, &state->b))
		return tal_free(state);
	return state;
}

/* We take the minimum.  If one side offers too little, it should be rejected */
uint64_t commit_fee(const OpenChannel *a, const OpenChannel *b)
{
	if (a->commitment_fee < b->commitment_fee)
		return a->commitment_fee;
	return b->commitment_fee;
}

void invert_cstate(struct channel_state *cstate)
{
	struct channel_oneside tmp;

	tmp = cstate->a;
	cstate->a = cstate->b;
	cstate->b = tmp;
}
