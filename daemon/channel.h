#ifndef LIGHTNING_DAEMON_CHANNEL_H
#define LIGHTNING_DAEMON_CHANNEL_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "daemon/htlc.h"
#include <assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct channel_oneside {
	/* Payment and fee is in millisatoshi. */
	uint32_t pay_msat, fee_msat;
	/* Number of HTLCs (required for limiting total number) */
	unsigned int num_htlcs;
};

struct channel_state {
	/* Satoshis paid by anchor. */
	uint64_t anchor;
	/* Satoshis per 1000 bytes. */
	uint64_t fee_rate;
	/* Number of non-dust htlcs (to calculate txsize) */
	unsigned int num_nondust;
	struct channel_oneside side[2];
};

/**
 * initial_cstate: Given initial fees and funding anchor, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @anchor_satoshis: The anchor amount.
 * @fee_rate: amount to pay in fees per kb (in satoshi).
 * @dir: which side paid for the anchor.
 *
 * Returns state, or NULL if malformed.
 */
struct channel_state *initial_cstate(const tal_t *ctx,
				     uint64_t anchor_satoshis,
				     uint64_t fee_rate,
				     enum side side);

/**
 * copy_cstate: Make a deep copy of channel_state
 * @ctx: tal context to allocate return value from.
 * @cstate: state to copy.
 */
struct channel_state *copy_cstate(const tal_t *ctx,
				  const struct channel_state *cstate);

/**
 * cstate_add_htlc: append an HTLC to cstate if it can afford it
 * @cstate: The channel state
 * @htlc: the htlc pointer.
 * @must_afford_fee: true if payer must meet fee.
 *
 * If that direction can't afford the HTLC this will return false and
 * leave @cstate unchanged.  If @must_afford_fee is true, and the
 * direction can't afford its half of the fees, it will also return
 * false and leave @cstate unchanged. Otherwise, pay_msat and fee_msat
 * are adjusted accordingly; true is returned.
 */
bool cstate_add_htlc(struct channel_state *cstate, const struct htlc *htlc,
		     bool must_afford_fee);

/**
 * cstate_fail_htlc: remove an HTLC, funds to the side which offered it.
 * @cstate: The channel state
 * @htlc: the htlc to remove.
 *
 * This will remove the @index'th entry in cstate->side[dir].htlcs[], and credit
 * the value of the HTLC (back) to cstate->side[dir].
 */
void cstate_fail_htlc(struct channel_state *cstate, const struct htlc *htlc);

/**
 * cstate_fulfill_htlc: remove an HTLC, funds to side which accepted it.
 * @cstate: The channel state
 * @htlc: the htlc to remove
 *
 * This will remove the @index'th entry in cstate->side[dir].htlcs[], and credit
 * the value of the HTLC to cstate->side[!dir].
 */
void cstate_fulfill_htlc(struct channel_state *cstate, const struct htlc *htlc);

/**
 * approx_max_feerate: what's the most side could raise fee rate to?
 * @cstate: The channel state
 * @side: LOCAL or REMOTE
 *
 * This is not exact!  To check if their offer is valid, use can_afford_feerate.
 */
uint64_t approx_max_feerate(const struct channel_state *cstate,
			    enum side side);

/**
 * can_afford_feerate: could this side pay for the fee if changed to fee_rate?
 * @cstate: The channel state
 * @fee_rate: the new fee rate proposed
 * @side: LOCAL or REMOTE
 */
bool can_afford_feerate(const struct channel_state *cstate, uint64_t fee_rate,
			enum side side);

/**
 * adjust_fee: Change fee rate.
 * @cstate: The channel state
 * @fee_rate: fee in satoshi per 1000 bytes.
 */
void adjust_fee(struct channel_state *cstate, uint64_t fee_rate);

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
 * fee_for_feerate: calculate the fee (in satoshi) for a given fee_rate.
 * @txsize: transaction size in bytes.
 * @fee_rate: satoshi per 1000 bytes.
 */
uint64_t fee_by_feerate(size_t txsize, uint64_t fee_rate);

/**
 * anchor_too_large: does anchor amount fit in 32-bits of millisatoshi.
 * @anchor_satoshis: amount in satoshis
 */
bool anchor_too_large(uint64_t anchor_satoshis);

/* Routines to db to force HTLC changes out-of-order which may wrap. */
void force_add_htlc(struct channel_state *cstate, const struct htlc *htlc);
void force_fail_htlc(struct channel_state *cstate, const struct htlc *htlc);
void force_fulfill_htlc(struct channel_state *cstate, const struct htlc *htlc);
bool balance_after_force(struct channel_state *cstate);
#endif /* LIGHTNING_DAEMON_CHANNEL_H */
