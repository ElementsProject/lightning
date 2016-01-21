#ifndef LIGHTNING_FUNDING_H
#define LIGHTNING_FUNDING_H
#include "config.h"
#include "bitcoin/locktime.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct channel_htlc {
	u64 msatoshis;
	struct abs_locktime expiry;
	struct sha256 rhash;
};

struct channel_oneside {
	/* Payment and fee is in millisatoshi. */
	uint32_t pay_msat, fee_msat;
	/* Use tal_count to get the number */
	struct channel_htlc *htlcs;
};

struct channel_state {
	struct channel_oneside a, b;
};

/**
 * initial_funding: Given A, B, and anchor, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @am_funder: am I paying for the anchor?
 * @anchor_satoshis: The anchor amount.
 * @fee: amount to pay in fees (in satoshi).
 *
 * Returns state, or NULL if malformed.
 */
struct channel_state *initial_funding(const tal_t *ctx,
				      bool am_funder,
				      uint64_t anchor_satoshis,
				      uint64_t fee);

/**
 * copy_funding: Make a deep copy of channel_state
 * @ctx: tal context to allocate return value from.
 * @cstate: state to copy.
 */
struct channel_state *copy_funding(const tal_t *ctx,
				   const struct channel_state *cstate);

/**
 * funding_delta: With this change, what's the new state?
 * @a_is_funder: is A paying for the anchor?
 * @anchor_satoshis: The anchor amount.
 * @delta_a: How many millisatoshi A changes (-ve => A pay B, +ve => B pays A)
 * @htlc: Millisatoshi A is putting into a HTLC (-ve if htlc is cancelled)
 * @a_side: channel a's state to update.
 * @b_side: channel b's state to update.
 */
bool funding_delta(bool a_is_funder,
		   uint64_t anchor_satoshis,
		   int64_t delta_a_msat,
		   int64_t htlc_msat,
		   struct channel_oneside *a_side,
		   struct channel_oneside *b_side);

/**
 * commit_fee: Fee amount for commit tx.
 * @a_satoshis: A's openchannel->commitment_fee offer
 * @b_satoshis: B's openchannel->commitment_fee offer
 */
uint64_t commit_fee(uint64_t a_satoshis, uint64_t b_satoshis);

/**
 * invert_cstate: Get the other side's state.
 * @cstate: the state to invert.
 */
void invert_cstate(struct channel_state *cstate);

/**
 * funding_add_htlc: append an HTLC to this side of the channel.
 * @creator: channel_state->a or channel_state->b, whichever originated htlc
 * @msatoshis: amount in millisatoshi
 * @expiry: time it expires
 * @rhash: hash of redeem secret
 */
void funding_add_htlc(struct channel_oneside *creator,
		      u32 msatoshis, const struct abs_locktime *expiry,
		      const struct sha256 *rhash);

/**
 * funding_find_htlc: find an HTLC on this side of the channel.
 * @creator: channel_state->a or channel_state->b, whichever originated htlc
 * @rhash: hash of redeem secret
 *
 * Returns a number < tal_count(creator->htlcs), or == tal_count(creator->htlcs)
 * on fail.
 */
size_t funding_find_htlc(struct channel_oneside *creator,
			 const struct sha256 *rhash);

/**
 * funding_remove_htlc: remove an HTLC from this side of the channel.
 * @creator: channel_state->a or channel_state->b, whichever originated htlc
 * @i: index returned from funding_find_htlc.
 */
void funding_remove_htlc(struct channel_oneside *creator, size_t i);

#endif /* LIGHTNING_FUNDING_H */
