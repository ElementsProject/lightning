#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/blockheight_states.h>
#include <common/fee_states.h>
#include <common/type_to_string.h>
#include <wire/wire.h>

struct height_states *new_height_states(const tal_t *ctx,
					enum side opener,
					const u32 *blockheight)
{
	struct height_states *states = tal(ctx, struct height_states);

	/* Set to NULL except terminal value */
	for (size_t i = 0; i < ARRAY_SIZE(states->height); i++)
		states->height[i] = NULL;

	if (blockheight)
		/* We reuse fee states! */
		states->height[last_fee_state(opener)]
			= tal_dup(states, u32, blockheight);
	return states;
}

u32 get_blockheight(const struct height_states *height_states,
		    enum side opener,
		    enum side side)
{
	/* The first non-NULL blockheight committed to this side is current */
	/* We use the same states as update_fee */
	for (enum htlc_state i = first_fee_state(opener);
	     i <= last_fee_state(opener);
	     i++) {
		if (!height_states->height[i])
			continue;
		if (!(htlc_state_flags(i) & HTLC_FLAG(side, HTLC_F_COMMITTED)))
			continue;
		return *height_states->height[i];
	}

	/* Some blockheight should always be set! */
	abort();
}

void start_height_update(struct height_states *height_states,
			 enum side opener,
			 u32 blockheight)
{
	/* Same as the feerate states */
	enum htlc_state start = first_fee_state(opener);

	/* BOLT #2:
	 * Unlike an HTLC, `update_fee` is never closed but simply replaced.
	 */
	if (height_states->height[start] == NULL)
		height_states->height[start] = tal(height_states, u32);
	*height_states->height[start] = blockheight;
}


/* Are blockheights all agreed by both sides? */
bool blockheight_changes_done(const struct height_states *height_states,
			      bool ignore_uncommitted)
{
	size_t num_blockheights = 0;
	for (size_t i = 0; i < ARRAY_SIZE(height_states->height); i++) {
		if (ignore_uncommitted
		    && (i == RCVD_ADD_HTLC || i == SENT_ADD_HTLC))
			continue;
		num_blockheights += (height_states->height[i] != NULL);
	}
	return num_blockheights == 1;
}

bool inc_height_state(struct height_states *height_states,
		      enum htlc_state hstate)
{
	/* These only advance through ADDING states. */
	assert(htlc_state_flags(hstate) & HTLC_ADDING);

	if (!height_states->height[hstate])
		return false;

	/* FIXME: We can never clash, except at final state unless someone
	 * has violated protocol (eg, send two revoke_and_ack back-to-back) */
	tal_free(height_states->height[hstate+1]);
	height_states->height[hstate+1] = height_states->height[hstate];
	height_states->height[hstate] = NULL;
	return true;
}

struct height_states *dup_height_states(const tal_t *ctx,
					const struct height_states *states TAKES)
{
	struct height_states *n;

	if (taken(states))
		return cast_const(struct height_states *,
				  tal_steal(ctx, states));

	n = tal_dup(ctx, struct height_states, states);
	for (size_t i = 0; i < ARRAY_SIZE(n->height); i++)
		n->height[i] = tal_dup_or_null(n, u32, n->height[i]);

	return n;
}

/* FIXME: we don't know opener inside fromwire_height_states, so can't do
 * this there :( */
bool height_states_valid(const struct height_states *states, enum side opener)
{
	/* We use the same states as update fee */
	return states->height[last_fee_state(opener)] != NULL;
}

void towire_height_states(u8 **pptr, const struct height_states *states)
{
	for (enum htlc_state i = 0; i < ARRAY_SIZE(states->height); i++) {
		/* We don't send uncommitted feestates */
		if (!(htlc_state_flags(i) & (HTLC_REMOTE_F_COMMITTED
					     | HTLC_LOCAL_F_COMMITTED))
		    || states->height[i] == NULL) {
			towire_bool(pptr, false);
			continue;
		}
		towire_bool(pptr, true);
		towire_u32(pptr, *states->height[i]);
	}
}

struct height_states *fromwire_height_states(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	struct height_states *states = tal(ctx, struct height_states);

	for (enum htlc_state i = 0; i < ARRAY_SIZE(states->height); i++) {
		if (fromwire_bool(cursor, max)) {
			states->height[i] = tal(states, u32);
			*states->height[i] = fromwire_u32(cursor, max);
		} else {
			states->height[i] = NULL;
		}
	}
	if (!*cursor)
		return tal_free(states);
	return states;
}

static const char *fmt_height_states(const tal_t *ctx,
				     const struct height_states *states)
{
	char *ret = tal_strdup(ctx, "{");
	for (enum htlc_state i = 0; i < ARRAY_SIZE(states->height); i++) {
		if (states->height[i] != NULL)
			tal_append_fmt(&ret, " %s:%u",
				       htlc_state_name(i),
				       *states->height[i]);
	}
	tal_append_fmt(&ret, " }");
	return ret;
}
REGISTER_TYPE_TO_STRING(height_states, fmt_height_states);
