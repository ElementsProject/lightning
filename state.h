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

static inline bool state_is_clearing(enum state s)
{
	return s == STATE_CLEARING || s == STATE_CLEARING_COMMITTING;
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
	return s == STATE_NORMAL || s == STATE_CLEARING;
}

/* BOLT #2:
 *
 * A node MUST NOT send a `update_add_htlc` after a `close_clearing`
 */
static inline bool state_can_add_htlc(enum state s)
{
	return state_is_normal(s);
}

static inline bool state_can_remove_htlc(enum state s)
{
	return state_is_normal(s) || state_is_clearing(s);
}


struct peer;
struct bitcoin_tx;

static inline bool input_is_pkt(enum state_input input)
{
	return input <= PKT_ERROR;
}

union input {
	/* For PKT_* */
	Pkt *pkt;
	/* For CMD_SEND_HTLC_ADD, CMD_SEND_HTLC_FULFILL, CMD_SEND_HTLC_FAIL */
	union htlc_staging *stage;
};

enum state state(struct peer *peer,
		 const enum state_input input,
		 const union input *idata,
		 const struct bitcoin_tx **broadcast);

/* Any CMD_SEND_HTLC_* */
#define CMD_SEND_UPDATE_ANY INPUT_MAX

/* a == b?  (or one of several for CMD_SEND_UPDATE_ANY) */
static inline bool input_is(enum state_input a, enum state_input b)
{
	if (b == CMD_SEND_UPDATE_ANY) {
		/* Single | here, we want to record all. */
		return input_is(a, CMD_SEND_HTLC_ADD)
			| input_is(a, CMD_SEND_HTLC_FULFILL)
			| input_is(a, CMD_SEND_HTLC_FAIL);
	}

/* For test_state_coverate to make the states. */
#ifdef MAPPING_INPUTS
	MAPPING_INPUTS(b);
#endif
	return a == b;
}

struct signature;

/* Inform peer have an unexpected packet. */
void peer_unexpected_pkt(struct peer *peer, const Pkt *pkt);

/* Send various kinds of packets */
void queue_pkt_open(struct peer *peer, OpenChannel__AnchorOffer anchor);
void queue_pkt_anchor(struct peer *peer);
void queue_pkt_open_commit_sig(struct peer *peer);
void queue_pkt_open_complete(struct peer *peer);
void queue_pkt_htlc_add(struct peer *peer,
			const struct channel_htlc *htlc);
void queue_pkt_htlc_fulfill(struct peer *peer, u64 id, const struct sha256 *r);
void queue_pkt_htlc_fail(struct peer *peer, u64 id);
void queue_pkt_commit(struct peer *peer);
void queue_pkt_revocation(struct peer *peer);
void queue_pkt_close_clearing(struct peer *peer);
void queue_pkt_close_signature(struct peer *peer);

Pkt *pkt_err(struct peer *peer, const char *msg, ...);
void queue_pkt_err(struct peer *peer, Pkt *err);
Pkt *pkt_err_unexpected(struct peer *peer, const Pkt *pkt);

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_anchor(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_open_commit_sig(struct peer *peer, const Pkt *pkt);
	
Pkt *accept_pkt_open_complete(struct peer *peer, const Pkt *pkt);
	
Pkt *accept_pkt_htlc_add(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_htlc_fail(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_update_accept(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_commit(struct peer *peer, const Pkt *pkt);

Pkt *accept_pkt_revocation(struct peer *peer, const Pkt *pkt);
Pkt *accept_pkt_close_clearing(struct peer *peer, const Pkt *pkt);

/**
 * peer_watch_anchor: create a watch for the anchor transaction.
 * @peer: the state data for this peer.
 * @depthok: the input to give when anchor reaches expected depth.
 * @timeout: the input to give if anchor doesn't reach depth in time.
 *
 * @depthok can be INPUT_NONE if it's our anchor (we don't time
 * ourselves out).
 */
void peer_watch_anchor(struct peer *peer,
		       enum state_input depthok,
		       enum state_input timeout);
/**
 * peer_unwatch_anchor_depth: remove depth watch for the anchor.
 * @peer: the state data for this peer.
 * @depthok: the input to give when anchor reaches expected depth.
 * @timeout: the input to give if anchor doesn't reach depth in time.
 *
 * @depthok and @timeout must match bitcoin_watch_anchor() call.
 */
void peer_unwatch_anchor_depth(struct peer *peer,
			       enum state_input depthok,
			       enum state_input timeout);

/**
 * peer_calculate_close_fee: figure out what the fee for closing is.
 * @peer: the state data for this peer.
 */
void peer_calculate_close_fee(struct peer *peer);

/* Start creation of the bitcoin anchor tx. */
void bitcoin_create_anchor(struct peer *peer, enum state_input done);

/* We didn't end up broadcasting the anchor: release the utxos.
 * If done != INPUT_NONE, remove existing create_anchor too. */
void bitcoin_release_anchor(struct peer *peer, enum state_input done);

/* Get the bitcoin anchor tx. */
const struct bitcoin_tx *bitcoin_anchor(struct peer *peer);

/* Create a bitcoin close tx. */
const struct bitcoin_tx *bitcoin_close(struct peer *peer);

/* Create a bitcoin spend tx (to spend our commit's outputs) */
const struct bitcoin_tx *bitcoin_spend_ours(struct peer *peer);

/* Create our commit tx */
const struct bitcoin_tx *bitcoin_commit(struct peer *peer);

#endif /* LIGHTNING_STATE_H */
