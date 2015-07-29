#ifndef LIGHTNING_FUNDING_H
#define LIGHTNING_FUNDING_H
#include <stdbool.h>

#include "lightning.pb-c.h"

/**
 * initial_funding: Given A, B, and anchor, what is initial state?
 * @a: A's openchannel offer
 * @b: B's openchannel offer
 * @anchor: The anchor offer (A or B)
 * @fee: amount to pay in fees.
 * @a_amount: amount commit tx will output to A.
 * @b_amount: amount commit tx will output to B.
 */
bool initial_funding(const OpenChannel *a,
		     const OpenChannel *b,
		     const OpenAnchor *anchor,
		     uint64_t fee,
		     uint64_t *a_amount,
		     uint64_t *b_amount);

/**
 * funding_delta: With this change, what's the new state?
 * @a: A's openchannel offer
 * @b: B's openchannel offer
 * @anchor: The anchor offer (A or B)
 * @fee: amount to pay in fees.
 * @channel_delta: In/out amount funder pays to non-funder (channel state)
 * @delta_a_to_b: How much A pays to B (satoshi).
 * @a_amount: amount commit tx will output to A.
 * @b_amount: amount commit tx will output to B.
 */
bool funding_delta(const OpenChannel *a,
		   const OpenChannel *b,
		   const OpenAnchor *anchor,
		   uint64_t fee,
		   uint64_t *channel_delta,
		   int64_t delta_a_to_b,
		   uint64_t *a_amount,
		   uint64_t *b_amount);

/**
 * commit_fee: Fee amount for commit tx.
 * @a: A's openchannel offer
 * @b: B's openchannel offer
 */
uint64_t commit_fee(const OpenChannel *a, const OpenChannel *b);
#endif /* LIGHTNING_FUNDING_H */
