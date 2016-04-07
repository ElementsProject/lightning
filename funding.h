#ifndef LIGHTNING_FUNDING_H
#define LIGHTNING_FUNDING_H
#include "config.h"
#include "bitcoin/locktime.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct channel_htlc {
	u64 id;
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
	/* Satoshis paid by anchor. */
	uint64_t anchor;
	/* Satoshis per 1000 bytes. */
	uint32_t fee_rate;
	/* Generation counter (incremented on every change) */
	uint32_t changes;
	struct channel_oneside a, b;
};

/**
 * initial_funding: Given A, B, and anchor, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @am_funder: am I paying for the anchor?
 * @anchor_satoshis: The anchor amount.
 * @fee_rate: amount to pay in fees per kb (in satoshi).
 *
 * Returns state, or NULL if malformed.
 */
struct channel_state *initial_funding(const tal_t *ctx,
				      bool am_funder,
				      uint64_t anchor_satoshis,
				      uint32_t fee_rate);

/**
 * copy_funding: Make a deep copy of channel_state
 * @ctx: tal context to allocate return value from.
 * @cstate: state to copy.
 */
struct channel_state *copy_funding(const tal_t *ctx,
				   const struct channel_state *cstate);

/**
 * funding_a_add_htlc: append an HTLC to A's side of cstate if it can afford it
 * @cstate: The channel state
 * @msatoshis: Millisatoshi A is putting into a HTLC
 * @expiry: time it expires
 * @rhash: hash of redeem secret
 * @id: 64-bit ID for htlc
 *
 * If A can't afford the HTLC (or still owes its half of the fees),
 * this will return false and leave @cstate unchanged.  Otherwise
 * cstate->a.htlcs will have the HTLC appended, and pay_msat and
 * fee_msat are adjusted accordingly.
 */
bool funding_a_add_htlc(struct channel_state *cstate,
			u32 msatoshis, const struct abs_locktime *expiry,
			const struct sha256 *rhash, uint64_t id);

bool funding_b_add_htlc(struct channel_state *cstate,
			u32 msatoshis, const struct abs_locktime *expiry,
			const struct sha256 *rhash, uint64_t id);

/**
 * funding_a_fail_htlc: remove an HTLC from A's side of cstate, funds to A
 * @cstate: The channel state
 * @index: the index into cstate->a.htlcs[].
 *
 * This will remove the @index'th entry in cstate->a.htlcs[], and credit
 * the value of the HTLC (back) to A.
 */
void funding_a_fail_htlc(struct channel_state *cstate, size_t index);
void funding_b_fail_htlc(struct channel_state *cstate, size_t index);

/**
 * funding_a_fulfill_htlc: remove an HTLC from A's side of cstate, funds to B
 * @cstate: The channel state
 * @index: the index into cstate->a.htlcs[].
 *
 * This will remove the @index'th entry in cstate->a.htlcs[], and credit
 * the value of the HTLC to B.
 */
void funding_a_fulfill_htlc(struct channel_state *cstate, size_t index);
void funding_b_fulfill_htlc(struct channel_state *cstate, size_t index);

/**
 * adjust_fee: Change fee rate.
 * @cstate: The channel state
 * @fee_rate: fee in satoshi per 1000 bytes.
 */
void adjust_fee(struct channel_state *cstate, uint32_t fee_rate);

/**
 * force_fee: Change fee to a specific value.
 * @cstate: The channel state
 * @fee: fee in satoshi.
 *
 * This is used for the close transaction, which specifies an exact fee.
 * If the fee cannot be paid in full, this return false (but cstate will
 * still be altered).
 */
bool force_fee(struct channel_state *cstate, uint64_t fee);

/**
 * invert_cstate: Get the other side's state.
 * @cstate: the state to invert.
 */
void invert_cstate(struct channel_state *cstate);

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
 * funding_htlc_by_id: find an HTLC on this side of the channel by ID.
 * @creator: channel_state->a or channel_state->b, whichever originated htlc
 * @id: id for HTLC.
 *
 * Returns a number < tal_count(creator->htlcs), or == tal_count(creator->htlcs)
 * on fail.
 */
size_t funding_htlc_by_id(struct channel_oneside *creator, uint64_t id);

/**
 * fee_for_feerate: calculate the fee (in satoshi) for a given fee_rate.
 * @txsize: transaction size in bytes.
 * @fee_rate: satoshi per 1000 bytes.
 */
uint64_t fee_by_feerate(size_t txsize, uint32_t fee_rate);

/**
 * is_dust_amount: is an output of this value considered dust?
 * @satoshis: number of satoshis.
 *
 * Transactions with dust outputs will not be relayed by the bitcoin
 * network.  It's not an exact definition, unfortunately.
 */
bool is_dust_amount(uint64_t satoshis);

#endif /* LIGHTNING_FUNDING_H */
