#ifndef LIGHTNING_FUNDING_H
#define LIGHTNING_FUNDING_H
#include <ccan/tal/tal.h>
#include <stdbool.h>

#include "lightning.pb-c.h"

struct channel_oneside {
	uint64_t pay, fee;
};

struct channel_state {
	struct channel_oneside a, b;
};

/**
 * initial_funding: Given A, B, and anchor, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @a: A's openchannel offer
 * @b: B's openchannel offer
 * @anchor: The anchor offer (A or B)
 * @fee: amount to pay in fees.
 *
 * Returns state, or NULL if malformed.
 */
struct channel_state *initial_funding(const tal_t *ctx,
				      const OpenChannel *a,
				      const OpenChannel *b,
				      const OpenAnchor *anchor,
				      uint64_t fee);

/**
 * funding_delta: With this change, what's the new state?
 * @a: A's openchannel offer
 * @b: B's openchannel offer
 * @anchor: The anchor offer (A or B)
 * @delta_a: How much A changes (-ve => A pay B, +ve => B pays A)
 * @a_side: channel a's state to update.
 * @b_side: channel b's state to update.
 */
bool funding_delta(const OpenChannel *a,
		   const OpenChannel *b,
		   const OpenAnchor *anchor,
		   int64_t delta_a,
		   struct channel_oneside *a_side,
		   struct channel_oneside *b_side);

/**
 * commit_fee: Fee amount for commit tx.
 * @a: A's openchannel offer
 * @b: B's openchannel offer
 */
uint64_t commit_fee(const OpenChannel *a, const OpenChannel *b);

/**
 * invert_cstate: Get the other side's state.
 * @cstate: the state to invert.
 */
void invert_cstate(struct channel_state *cstate);

#endif /* LIGHTNING_FUNDING_H */
