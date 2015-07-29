#include "funding.h"
#include <assert.h>

/* FIXME: Fees! */
bool funding_delta(const OpenChannel *a,
		   const OpenChannel *b,
		   const OpenAnchor *anchor,
		   uint64_t *channel_delta,
		   int64_t delta_a_to_b,
		   uint64_t *a_amount,
		   uint64_t *b_amount)
{
	uint64_t *funder_amount, *non_funder_amount;
	int64_t delta_to_funder;

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

	*channel_delta -= delta_to_funder;
	*funder_amount = anchor->amount - *channel_delta;
	*non_funder_amount = *channel_delta;
	return true;
}

bool initial_funding(const OpenChannel *a,
		     const OpenChannel *b,
		     const OpenAnchor *anchor,
		     uint64_t *a_amount,
		     uint64_t *b_amount)
{
	uint64_t channel_delta = 0;

	return funding_delta(a, b, anchor, &channel_delta, 0,
			     a_amount, b_amount);
}
