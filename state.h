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
	return s >= STATE_ERR_ANCHOR_TIMEOUT && s <= STATE_ERR_INTERNAL;
}

struct peer;
struct bitcoin_tx;

static inline bool input_is_pkt(enum state_input input)
{
	return input <= PKT_ERROR;
}

union input {
	Pkt *pkt;
	struct command *cmd;
	struct bitcoin_tx *tx;
	struct htlc_progress *htlc_prog;
	struct commit_info *ci;
	struct htlc_onchain {
		/* Which commitment we using. */
		struct commit_info *ci;
		/* Which HTLC. */
		size_t i;
		/* The rvalue (or NULL). */
		u8 *r;
	} *htlc_onchain;
};

enum command_status state(struct peer *peer,
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

/* An on-chain transaction revealed an R value. */
void peer_tx_revealed_r_value(struct peer *peer,
			      const struct htlc_onchain *htlc_onchain);

/* Send various kinds of packets */
void queue_pkt_open(struct peer *peer, OpenChannel__AnchorOffer anchor);
void queue_pkt_anchor(struct peer *peer);
void queue_pkt_open_commit_sig(struct peer *peer);
void queue_pkt_open_complete(struct peer *peer);
void queue_pkt_htlc_add(struct peer *peer,
			const struct htlc_progress *htlc_prog);
void queue_pkt_htlc_fulfill(struct peer *peer,
			    const struct htlc_progress *htlc_prog);
void queue_pkt_htlc_fail(struct peer *peer,
			 const struct htlc_progress *htlc_prog);
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
Pkt *accept_pkt_close_sig(struct peer *peer, const Pkt *pkt,
			  bool *acked, bool *we_agree);

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
 * peer_watch_htlcs_cleared: tell us when no HTLCs are in commit txs.
 * @peer: the state data for this peer.
 * @all_done: input to give when all HTLCs are done.
 */
void peer_watch_htlcs_cleared(struct peer *peer,
			      enum state_input all_done);

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

/* Create a bitcoin steal tx (to steal all their commit's outputs) */
const struct bitcoin_tx *bitcoin_steal(const struct peer *peer,
				       struct commit_info *ci);

/* Create our commit tx */
const struct bitcoin_tx *bitcoin_commit(struct peer *peer);

/* Create a HTLC refund collection */
const struct bitcoin_tx *bitcoin_htlc_timeout(const struct peer *peer,
				      const struct htlc_onchain *htlc_onchain);

/* Create a HTLC collection */
const struct bitcoin_tx *bitcoin_htlc_spend(const struct peer *peer,
				    const struct htlc_onchain *htlc_onchain);

#endif /* LIGHTNING_STATE_H */
