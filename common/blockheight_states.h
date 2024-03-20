#ifndef LIGHTNING_COMMON_BLOCKHEIGHT_STATES_H
#define LIGHTNING_COMMON_BLOCKHEIGHT_STATES_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/htlc.h>

struct height_states {
	/* Current blockheight: goes through same
	 * state machine as feestate addition.
	 *
	 * We need to know if there's an actual change pending though (even if
	 * it's a "change" to an idential feerate!) so we use pointers.
	 */
	u32 *height[HTLC_STATE_INVALID];
};

/**
 * new_height_states: Initialize a height_states structure as at
 * 		      open-of-channel.
 * @ctx: the tal ctx to allocate off
 * @opener: which side opened the channel
 * 	    (and thus, proposes blockheight updates).
 * @blockheight: the initial blockheight (if any).
 */
struct height_states *new_height_states(const tal_t *ctx,
					enum side opener,
					const u32 *blockheight);

/**
 * get_blockheight: Get the current blockheight
 * @height_states: the blockheight state machine
 * @opener: which side opened the channel
 *          (and thus, proposes blockheight updates).
 * @side: which side to get the blockheight for
 */
u32 get_blockheight(const struct height_states *height_states,
		    enum side opener,
		    enum side side);

/**
 * start_height_update: feed a new blockheight update into state machine.
 * @height_states: the height state machine
 * @opener: which side opened the channel (and thus, proposes
 *          blockheight updates).
 * @blockheight: the new blockheight.
 */
void start_height_update(struct height_states *height_states,
			 enum side opener,
			 u32 blockheight);
/**
 * inc_height_state: move this blockheight to the next state.
 * @height_states: the blockheight state machine
 * @hstate: state
 *
 * Moves height_states[hstate] to height_states[hstate+1], if not NULL.
 * Returns true if it wasn't NULL.
 */
bool inc_height_state(struct height_states *height_states,
		      enum htlc_state hstate);

/* Are blockheights all agreed by both sides? */
bool blockheight_changes_done(const struct height_states *height_states,
			      bool ignore_uncommitted);

/* Duplicate a set of height states */
struct height_states *dup_height_states(const tal_t *ctx,
					const struct height_states *states TAKES);

/* Marshal and unmarshal */
void towire_height_states(u8 **pptr, const struct height_states *height_states);
/* FIXME: You must check that height_states_valid! */
struct height_states *fromwire_height_states(const tal_t *ctx,
				       const u8 **cursor, size_t *max);

char *fmt_height_states(const tal_t *ctx,
			const struct height_states *states);

/**
 * is this height_state struct valid for this side?
 */
bool height_states_valid(const struct height_states *states, enum side opener);
#endif /* LIGHTNING_COMMON_BLOCKHEIGHT_STATES_H */
