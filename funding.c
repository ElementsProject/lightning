#include "funding.h"
#include <assert.h>

bool funding_delta(const OpenChannel *a,
		   const OpenChannel *b,
		   const OpenAnchor *anchor,
		   uint64_t fee,
		   uint64_t *channel_delta,
		   int64_t delta_a_to_b,
		   uint64_t *a_amount,
		   uint64_t *b_amount)
{
	uint64_t *funder_amount, *non_funder_amount, new_delta;
	int64_t delta_to_funder;
	uint64_t funder_fee, non_funder_fee;

	assert(*channel_delta <= anchor->amount);

	if (a->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR) {
		if (b->anch != OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR)
			return false;
		funder_amount = a_amount;
		non_funder_amount = b_amount;
		delta_to_funder = delta_a_to_b;
	} else {
		if (a->anch != OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR)
			return false;
		if (b->anch != OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
			return false;
		funder_amount = b_amount;
		non_funder_amount = a_amount;
		delta_to_funder = -delta_a_to_b;
	}

	/* Trying to spend more than non-funder has? */
	if (delta_to_funder > 0) {
		if (delta_to_funder > *channel_delta)
			return false;
	/* Trying to spend more than funder has? */
	} else if (-delta_to_funder > anchor->amount - *channel_delta)
		return false;

	new_delta = *channel_delta - delta_to_funder;
	*funder_amount = anchor->amount - new_delta;
	*non_funder_amount = new_delta;

	/* We try to split fee. */
	funder_fee = fee / 2;
	/* Funder gets any 1 satoshi rounding benefit! */
	non_funder_fee = fee - funder_fee;

	if (*non_funder_amount < non_funder_fee) {
		/*
		 * This happens initially, as funder has all the money.
		 * That's OK, but don't let non-funder withdraw if they can't
		 * cover fee.
		 */
		if (delta_to_funder > 0)
			return false;

		/* Pay everything they can, funder pays rest. */
		non_funder_fee = *non_funder_amount;
		funder_fee = fee - non_funder_fee;
	}

	/* Funder must always ensure they can pay their share. */
	if (*funder_amount < funder_fee)
		return false;

	*funder_amount -= funder_fee;
	*non_funder_amount -= non_funder_fee;

	/* Now we know we're succeeding, update caller's channel_delta */
	*channel_delta = new_delta;
	return true;
}

bool initial_funding(const OpenChannel *a,
		     const OpenChannel *b,
		     const OpenAnchor *anchor,
		     uint64_t fee,
		     uint64_t *a_amount,
		     uint64_t *b_amount)
{
	uint64_t channel_delta = 0;

	return funding_delta(a, b, anchor, fee, &channel_delta, 0,
			     a_amount, b_amount);
}

/* We take the minimum.  If one side offers too little, it should be rejected */
uint64_t commit_fee(const OpenChannel *a, const OpenChannel *b)
{
	if (a->commitment_fee < b->commitment_fee)
		return a->commitment_fee;
	return b->commitment_fee;
}
