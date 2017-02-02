#include "db.h"
#include "htlc.h"
#include "log.h"
#include "peer.h"
#include "type_to_string.h"
  #include "gen_htlc_state_names.h"
#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>

const char *htlc_state_name(enum htlc_state s)
{
	size_t i;

	for (i = 0; enum_htlc_state_names[i].name; i++)
		if (enum_htlc_state_names[i].v == s)
			return enum_htlc_state_names[i].name;
	return "unknown";
}

enum htlc_state htlc_state_from_name(const char *name)
{
	size_t i;

	for (i = 0; enum_htlc_state_names[i].name; i++)
		if (streq(enum_htlc_state_names[i].name, name))
			return enum_htlc_state_names[i].v;
	return HTLC_STATE_INVALID;
}

/* This is the flags for each state. */
static const int per_state_bits[] = {
	[SENT_ADD_HTLC] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_PENDING,

	[SENT_ADD_COMMIT] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_ADD_REVOCATION] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_PENDING
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_ADD_ACK_COMMIT] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[SENT_ADD_ACK_REVOCATION] = HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_REMOVE_HTLC] = HTLC_REMOVING + HTLC_LOCAL_F_OWNER
	+ HTLC_LOCAL_F_PENDING + HTLC_LOCAL_F_COMMITTED
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_REMOVE_COMMIT] = HTLC_REMOVING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[SENT_REMOVE_REVOCATION] = HTLC_REMOVING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_PENDING
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[SENT_REMOVE_ACK_COMMIT] = HTLC_REMOVING + HTLC_LOCAL_F_OWNER
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_REMOVE_ACK_REVOCATION] = HTLC_LOCAL_F_OWNER
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_ADD_HTLC] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_PENDING,

	[RCVD_ADD_COMMIT] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED,

	[SENT_ADD_REVOCATION] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_PENDING
	+ HTLC_LOCAL_F_WAS_COMMITTED,

	[SENT_ADD_ACK_COMMIT] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_ADD_ACK_REVOCATION] = HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[SENT_REMOVE_HTLC] = HTLC_REMOVING + HTLC_REMOTE_F_OWNER
	+ HTLC_REMOTE_F_PENDING
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[SENT_REMOVE_COMMIT] = HTLC_REMOVING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_REMOVE_REVOCATION] = HTLC_REMOVING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_PENDING
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_REMOVE_ACK_COMMIT] = HTLC_REMOVING + HTLC_REMOTE_F_OWNER
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[SENT_REMOVE_ACK_REVOCATION] = HTLC_REMOTE_F_OWNER
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED
};

int htlc_state_flags(enum htlc_state state)
{
	assert(state < ARRAY_SIZE(per_state_bits));
	assert(per_state_bits[state]);
	return per_state_bits[state];
}

void htlc_changestate(struct htlc *h,
		      enum htlc_state oldstate,
		      enum htlc_state newstate,
		      bool db_commit)
{
	log_debug(h->peer->log, "htlc %"PRIu64": %s->%s", h->id,
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
