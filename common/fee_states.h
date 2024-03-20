#ifndef LIGHTNING_COMMON_FEE_STATES_H
#define LIGHTNING_COMMON_FEE_STATES_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/htlc.h>

struct fee_states {
	/* Current feerate in satoshis per 1000 weight: goes through same
	 * state machine as htlc addition, but can only have one rate at a
	 * time in any state and are never removed.
	 *
	 * We need to know if there's an actual change pending though (even if
	 * it's a "change" to an idential feerate!) so we use pointers.
	 */
	u32 *feerate[HTLC_STATE_INVALID];
};

/**
 * new_fee_states: Initialize a fee_states structure as at open-of-channel.
 * @ctx: the tal ctx to allocate off
 * @opener: which side opened the channel (and thus, proposes fee updates).
 * @feerate_per_kw: the initial feerate (if any).
 */
struct fee_states *new_fee_states(const tal_t *ctx,
				  enum side opener,
				  const u32 *feerate_per_kw);

/**
 * dup_fee_states: copy a fee_states structure.
 * @ctx: the tal ctx to allocate off
 * @fee_states: the fee_states to copy.
 */
struct fee_states *dup_fee_states(const tal_t *ctx,
				  const struct fee_states *fee_states TAKES);

/**
 * get_feerate: Get the current feerate
 * @fee_states: the fee state machine
 * @opener: which side opened the channel (and thus, proposes fee updates).
 * @side: which side to get the feerate for
 */
u32 get_feerate(const struct fee_states *fee_states,
		enum side opener,
		enum side side);

/**
 * first_fee_state: get the initial fee state.
 * @opener: which side opened the channel (and thus, proposes fee updates).
 */
enum htlc_state first_fee_state(enum side opener);

/**
 * last_fee_state: get the final fee state.
 * @opener: which side opened the channel (and thus, proposes fee updates).
 */
enum htlc_state last_fee_state(enum side opener);

/**
 * start_fee_update: feed a new fee update into state machine.
 * @fee_states: the fee state machine
 * @opener: which side opened the channel (and thus, proposes fee updates).
 * @feerate_per_kw: the new feerate.
 */
void start_fee_update(struct fee_states *fee_states,
		      enum side opener,
		      u32 feerate_per_kw);

/**
 * inc_fee_state: move this feerate to the next state.
 * @fee_states: the fee state machine
 * @hstate: state
 *
 * Moves fee_states[hstate] to fee_states[hstate+1], if not NULL.
 * Returns true if it wasn't NULL.
 */
bool inc_fee_state(struct fee_states *fee_states, enum htlc_state hstate);

/* Marshal and unmarshal */
void towire_fee_states(u8 **pptr, const struct fee_states *fee_states);
/* FIXME: You must check that fee_states_valid! */
struct fee_states *fromwire_fee_states(const tal_t *ctx,
				       const u8 **cursor, size_t *max);

/**
 * Is this fee_state struct valid for this side?
 */
bool fee_states_valid(const struct fee_states *fee_states, enum side opener);

/* Are there no more fee changes in-flight? */
bool feerate_changes_done(const struct fee_states *fee_states,
			  bool ignore_uncommitted);

char *fmt_fee_states(const tal_t *ctx,
		     const struct fee_states *fee_states);

#endif /* LIGHTNING_COMMON_FEE_STATES_H */
