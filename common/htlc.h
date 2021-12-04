#ifndef LIGHTNING_COMMON_HTLC_H
#define LIGHTNING_COMMON_HTLC_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "htlc_state.h"
#include <assert.h>
#include <ccan/htable/htable_type.h>

#define NUM_SIDES (REMOTE + 1)
enum side {
	LOCAL,
	REMOTE,
};

/* What are we doing: adding or removing? */
#define HTLC_ADDING			0x400
#define HTLC_REMOVING			0x800

/* Uncommitted change is pending */
#define HTLC_F_PENDING			0x01
/* HTLC is in commit_tx */
#define HTLC_F_COMMITTED		0x02
/* We have revoked the previous commit_tx */
#define HTLC_F_REVOKED			0x04
/* We offered it it. */
#define HTLC_F_OWNER			0x08
/* HTLC was ever in a commit_tx */
#define HTLC_F_WAS_COMMITTED		0x10

/* Each of the above flags applies to both sides */
#define HTLC_FLAG(side,flag)		((flag) << ((side) * 5))

#define HTLC_REMOTE_F_PENDING		HTLC_FLAG(REMOTE,HTLC_F_PENDING)
#define HTLC_REMOTE_F_COMMITTED		HTLC_FLAG(REMOTE,HTLC_F_COMMITTED)
#define HTLC_REMOTE_F_REVOKED		HTLC_FLAG(REMOTE,HTLC_F_REVOKED)
#define HTLC_REMOTE_F_OWNER		HTLC_FLAG(REMOTE,HTLC_F_OWNER)
#define HTLC_REMOTE_F_WAS_COMMITTED	HTLC_FLAG(REMOTE,HTLC_F_WAS_COMMITTED)

#define HTLC_LOCAL_F_PENDING		HTLC_FLAG(LOCAL,HTLC_F_PENDING)
#define HTLC_LOCAL_F_COMMITTED		HTLC_FLAG(LOCAL,HTLC_F_COMMITTED)
#define HTLC_LOCAL_F_REVOKED		HTLC_FLAG(LOCAL,HTLC_F_REVOKED)
#define HTLC_LOCAL_F_OWNER		HTLC_FLAG(LOCAL,HTLC_F_OWNER)
#define HTLC_LOCAL_F_WAS_COMMITTED	HTLC_FLAG(LOCAL,HTLC_F_WAS_COMMITTED)

const char *htlc_state_name(enum htlc_state s);
int htlc_state_flags(enum htlc_state state);

static inline enum side htlc_state_owner(enum htlc_state state)
{
	if (state < RCVD_ADD_HTLC) {
		assert((htlc_state_flags(state)
			& (HTLC_REMOTE_F_OWNER|HTLC_LOCAL_F_OWNER))
		       == HTLC_LOCAL_F_OWNER);
		return LOCAL;
	} else {
		assert((htlc_state_flags(state)
			& (HTLC_REMOTE_F_OWNER|HTLC_LOCAL_F_OWNER))
		       == HTLC_REMOTE_F_OWNER);
		return REMOTE;
	}
}

static inline const char *side_to_str(enum side side)
{
	switch (side) {
	case LOCAL: return "LOCAL";
	case REMOTE: return "REMOTE";
	}
	abort();
}
#endif /* LIGHTNING_COMMON_HTLC_H */
