#include "db.h"
#include "htlc.h"
#include "log.h"
#include "peer.h"
#include "peer_internal.h"
#include "type_to_string.h"
#include <bitcoin/preimage.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>

void htlc_changestate(struct htlc *h,
		      enum htlc_state oldstate,
		      enum htlc_state newstate,
		      bool db_commit)
{
	peer_debug(h->peer, "htlc %"PRIu64": %s->%s", h->id,
		  htlc_state_name(h->state), htlc_state_name(newstate));
	assert(h->state == oldstate);

	/* You can only go to consecutive states. */
	assert(newstate == h->state + 1);

	/* You can't change sides. */
	assert((htlc_state_flags(h->state)&(HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER))
	       == (htlc_state_flags(newstate)&(HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER)));

	h->state = newstate;

	if (db_commit) {
		if (newstate == RCVD_ADD_COMMIT || newstate == SENT_ADD_COMMIT) {
			db_new_htlc(h->peer, h);
			return;
		}
		/* These never hit the database. */
		if (oldstate == RCVD_REMOVE_HTLC)
			oldstate = SENT_ADD_ACK_REVOCATION;
		else if (oldstate == SENT_REMOVE_HTLC)
			oldstate = RCVD_ADD_ACK_REVOCATION;
		db_update_htlc_state(h->peer, h, oldstate);
	}
}

void htlc_undostate(struct htlc *h,
		    enum htlc_state oldstate,
		    enum htlc_state newstate)
{
	log_debug(h->peer->log, "htlc %"PRIu64": %s->%s", h->id,
		  htlc_state_name(h->state), htlc_state_name(newstate));
	assert(h->state == oldstate);

	/* You can only return to previous state. */
	assert(newstate == h->state - 1);

	/* And must only be proposal, not commit. */
	assert(h->state == SENT_REMOVE_HTLC || h->state == RCVD_REMOVE_HTLC);

	/* You can't change sides. */
	assert((htlc_state_flags(h->state)&(HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER))
	       == (htlc_state_flags(newstate)&(HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER)));

	h->state = newstate;
}

static char *fmt_htlc(const tal_t *ctx, const struct htlc *h)
{
	return tal_fmt(ctx, "{ id=%"PRIu64
		       " msatoshi=%"PRIu64
		       " expiry=%s"
		       " rhash=%s"
		       " rval=%s"
		       " src=%s }",
		       h->id, h->msatoshi,
		       type_to_string(ctx, struct abs_locktime, &h->expiry),
		       type_to_string(ctx, struct sha256, &h->rhash),
		       h->r ? tal_hexstr(ctx, h->r, sizeof(*h->r))
		       : "UNKNOWN",
		       h->src ? type_to_string(ctx, struct pubkey,
					       h->src->peer->id)
		       : "local");
}
REGISTER_TYPE_TO_STRING(htlc, fmt_htlc);
