#ifndef LIGHTNING_STATE_H
#define LIGHTNING_STATE_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <state_types.h>
#include <stdbool.h>

/*
 * This is the core state machine.
 *
 * Calling the state machine updates updates peer->state, and may call
 * various peer_ callbacks.  It also returns the status of the current
 * command.
 */

static inline bool state_is_error(enum state s)
{
	return s >= STATE_ERR_BREAKDOWN && s <= STATE_ERR_INTERNAL;
}

static inline bool state_is_shutdown(enum state s)
{
	return s == STATE_SHUTDOWN || s == STATE_SHUTDOWN_COMMITTING;
}

static inline bool state_is_onchain(enum state s)
{
	return s >= STATE_CLOSE_ONCHAIN_CHEATED
		&& s <= STATE_CLOSE_ONCHAIN_MUTUAL;
}

static inline bool state_is_normal(enum state s)
{
	return s == STATE_NORMAL || s == STATE_NORMAL_COMMITTING;
}

static inline bool state_is_opening(enum state s)
{
	return s < STATE_NORMAL;
}

static inline bool state_is_waiting_for_anchor(enum state s)
{
	return s == STATE_OPEN_WAITING_OURANCHOR
		|| s == STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED
		|| s == STATE_OPEN_WAITING_THEIRANCHOR
		|| s == STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED;
}

static inline bool state_can_io(enum state s)
{
	if (state_is_error(s))
		return false;
	if (s == STATE_CLOSED)
		return false;
	if (state_is_onchain(s))
		return false;
	return true;
}

static inline bool state_can_commit(enum state s)
{
	return s == STATE_NORMAL || s == STATE_SHUTDOWN;
}

/* BOLT #2:
 *
 * A node MUST NOT send a `update_add_htlc` after a `close_shutdown`
 */
static inline bool state_can_add_htlc(enum state s)
{
	return state_is_normal(s);
}

static inline bool state_can_remove_htlc(enum state s)
{
	return state_is_normal(s) || state_is_shutdown(s);
}


struct peer;
struct bitcoin_tx;
struct commit_info;

static inline bool input_is_pkt(enum state_input input)
{
	return input <= PKT_ERROR;
}

enum state state(struct peer *peer,
		 const enum state_input input,
		 const Pkt *pkt,
		 const struct bitcoin_tx **broadcast);

/* a == b? */
static inline bool input_is(enum state_input a, enum state_input b)
{
	return a == b;
}

/**
 * peer_watch_anchor: create a watch for the anchor transaction.
 * @peer: the state data for this peer.
 * @depth: depth at which to fire @depthok.
 * @timeout: the input to give if anchor doesn't reach depth in time.
 *
 * @timeout can be INPUT_NONE if it's our anchor (we don't time
 * ourselves out).
 */
void peer_watch_anchor(struct peer *peer,
		       int depth,
		       enum state_input timeout);

/* Start creation of the bitcoin anchor tx. */
void bitcoin_create_anchor(struct peer *peer);

/* Get the bitcoin anchor tx. */
const struct bitcoin_tx *bitcoin_anchor(struct peer *peer);

/* We didn't end up broadcasting the anchor: release the utxos.
 * If done != INPUT_NONE, remove existing create_anchor too. */
void bitcoin_release_anchor(struct peer *peer, enum state_input done);

#endif /* LIGHTNING_STATE_H */
