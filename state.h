#ifndef LIGHTNING_STATE_H
#define LIGHTNING_STATE_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <state_types.h>
#include <stdbool.h>

enum state_effect_type {
	STATE_EFFECT_new_state,
	STATE_EFFECT_in_error,
	STATE_EFFECT_broadcast_tx,
	STATE_EFFECT_send_pkt,
	STATE_EFFECT_watch,
	STATE_EFFECT_unwatch,
	STATE_EFFECT_cmd_defer,
	STATE_EFFECT_cmd_requeue,
	STATE_EFFECT_cmd_success,
	/* (never applies to CMD_CLOSE) */
	STATE_EFFECT_cmd_fail,
	STATE_EFFECT_cmd_close_done,
	STATE_EFFECT_stop_packets,
	STATE_EFFECT_stop_commands,
	/* FIXME: Use a watch for this?. */
	STATE_EFFECT_close_timeout,
	STATE_EFFECT_htlc_in_progress,
	STATE_EFFECT_update_theirsig,
	STATE_EFFECT_htlc_abandon,
	STATE_EFFECT_htlc_fulfill,
	STATE_EFFECT_r_value,
	/* FIXME: Combine into watches? */
	STATE_EFFECT_watch_htlcs,
	STATE_EFFECT_unwatch_htlc,
	STATE_EFFECT_watch_htlc_spend,
	STATE_EFFECT_unwatch_htlc_spend
};

/*
 * This is the core state machine.
 *
 * Calling the state machine with an input simply returns the new state,
 * and populates the "effect" struct with what it wants done.
 */
struct state_effect {
	struct state_effect *next;

	enum state_effect_type etype;
	union {
		/* New state to enter. */
		enum state new_state;

		/* Transaction to broadcast. */
		struct bitcoin_tx *broadcast_tx;

		/* Packet to send. */
		Pkt *send_pkt;

		/* Event to watch for. */
		struct watch *watch;

		/* Events to no longer watch for. */
		struct watch *unwatch;

		/* Defer an input. */
		enum state_input cmd_defer;

		/* Requeue/succeed/fail command. */
		enum state_input cmd_requeue;
		enum state_input cmd_success;
		void *cmd_fail;

		/* CMD_CLOSE is complete (true if successful mutual close). */
		bool cmd_close_done;

		/* Stop taking packets? commands? */
		bool stop_packets, stop_commands;

		/* Set a timeout for close tx. */
		enum state_input close_timeout;

		/* Error received from other side. */
		Pkt *in_error;

		/* HTLC we're working on. */
		struct htlc_progress *htlc_in_progress;

		/* Their signature for the new commit tx. */
		struct signature *update_theirsig;
	
		/* Stop working on HTLC. */
		bool htlc_abandon;

		/* Finished working on HTLC. */
		bool htlc_fulfill;

		/* R value. */
		const struct htlc_rval *r_value;

		/* HTLC outputs to watch. */
		const struct htlc_watch *watch_htlcs;

		/* HTLC output to unwatch. */
		const struct htlc_unwatch *unwatch_htlc;

		/* HTLC spends to watch/unwatch. */
		const struct htlc_spend_watch *watch_htlc_spend;
		const struct htlc_spend_watch *unwatch_htlc_spend;

		/* FIXME: More to come (for accept_*) */
	} u;
};

static inline bool state_is_error(enum state s)
{
	return s >= STATE_ERR_ANCHOR_TIMEOUT && s <= STATE_ERR_INTERNAL;
}

struct peer;

static inline bool input_is_pkt(enum state_input input)
{
	return input <= PKT_ERROR;
}

union input {
	Pkt *pkt;
	struct command *cmd;
	struct bitcoin_event *btc;
	struct htlc *htlc;
	struct htlc_progress *htlc_prog;
};

struct state_effect *state(const tal_t *ctx,
			   const enum state state,
			   const struct peer *peer,
			   const enum state_input input,
			   const union input *idata);

/* Any CMD_SEND_HTLC_* */
#define CMD_SEND_UPDATE_ANY INPUT_MAX

/* a == b?  (or one of several for CMD_SEND_UPDATE_ANY) */
static inline bool input_is(enum state_input a, enum state_input b)
{
	if (b == CMD_SEND_UPDATE_ANY) {
		/* Single | here, we want to record all. */
		return input_is(a, CMD_SEND_HTLC_UPDATE)
			| input_is(a, CMD_SEND_HTLC_FULFILL)
			| input_is(a, CMD_SEND_HTLC_TIMEDOUT)
			| input_is(a, CMD_SEND_HTLC_ROUTEFAIL);
	}

/* For test_state_coverate to make the states. */
#ifdef MAPPING_INPUTS
	MAPPING_INPUTS(b);
#endif
	return a == b;
}

struct signature;

/* Create various kinds of packets, allocated off @ctx */
Pkt *pkt_open(const tal_t *ctx, const struct peer *peer,
	      OpenChannel__AnchorOffer anchor);
Pkt *pkt_anchor(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_open_commit_sig(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_open_complete(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_htlc_update(const tal_t *ctx, const struct peer *peer,
		     const struct htlc_progress *htlc_prog);
Pkt *pkt_htlc_fulfill(const tal_t *ctx, const struct peer *peer,
		      const struct htlc_progress *htlc_prog);
Pkt *pkt_htlc_timedout(const tal_t *ctx, const struct peer *peer,
		       const struct htlc_progress *htlc_prog);
Pkt *pkt_htlc_routefail(const tal_t *ctx, const struct peer *peer,
			const struct htlc_progress *htlc_prog);
Pkt *pkt_update_accept(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_update_signature(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_update_complete(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_err(const tal_t *ctx, const char *msg);
Pkt *pkt_close(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_close_complete(const tal_t *ctx, const struct peer *peer);
Pkt *pkt_close_ack(const tal_t *ctx, const struct peer *peer);
Pkt *unexpected_pkt(const tal_t *ctx, enum state_input input);

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(const tal_t *ctx,
		     const struct peer *peer,
		     const Pkt *pkt,
		     struct state_effect **effect);

Pkt *accept_pkt_anchor(const tal_t *ctx,
		       const struct peer *peer,
		       const Pkt *pkt,
		       struct state_effect **effect);

Pkt *accept_pkt_open_commit_sig(const tal_t *ctx,
				const struct peer *peer, const Pkt *pkt,
				struct state_effect **effect);
	
Pkt *accept_pkt_htlc_update(const tal_t *ctx,
			    const struct peer *peer, const Pkt *pkt,
			    Pkt **decline,
			    struct htlc_progress **htlcprog,
			    struct state_effect **effect);

Pkt *accept_pkt_htlc_routefail(const tal_t *ctx,
			       const struct peer *peer, const Pkt *pkt,
			       struct htlc_progress **htlcprog,
			       struct state_effect **effect);

Pkt *accept_pkt_htlc_timedout(const tal_t *ctx,
			      const struct peer *peer, const Pkt *pkt,
			      struct htlc_progress **htlcprog,
			      struct state_effect **effect);

Pkt *accept_pkt_htlc_fulfill(const tal_t *ctx,
			     const struct peer *peer, const Pkt *pkt,
			     struct htlc_progress **htlcprog,
			     struct state_effect **effect);

Pkt *accept_pkt_update_accept(const tal_t *ctx,
			      const struct peer *peer, const Pkt *pkt,
			      struct signature **sig,
			      struct state_effect **effect);

Pkt *accept_pkt_update_complete(const tal_t *ctx,
				const struct peer *peer, const Pkt *pkt,
				struct state_effect **effect);

Pkt *accept_pkt_update_signature(const tal_t *ctx,
				 const struct peer *peer,
				 const Pkt *pkt,
				 struct signature **sig,
				 struct state_effect **effect);

Pkt *accept_pkt_close(const tal_t *ctx,
		      const struct peer *peer, const Pkt *pkt,
		      struct state_effect **effect);

Pkt *accept_pkt_close_complete(const tal_t *ctx,
			       const struct peer *peer, const Pkt *pkt,
			       struct state_effect **effect);

Pkt *accept_pkt_simultaneous_close(const tal_t *ctx,
				   const struct peer *peer,
				   const Pkt *pkt,
				   struct state_effect **effect);

Pkt *accept_pkt_close_ack(const tal_t *ctx,
			  const struct peer *peer, const Pkt *pkt,
			  struct state_effect **effect);

/**
 * committed_to_htlcs: do we have any locked-in HTLCs?
 * @peer: the state data for this peer.
 *
 * If we were to generate a commit tx now, would it have HTLCs in it?
 */
bool committed_to_htlcs(const struct peer *peer);

/**
 * bitcoin_watch_anchor: create a watch for the anchor.
 * @ctx: context to tal the watch struct off.
 * @peer: the state data for this peer.
 * @depthok: the input to give when anchor reaches expected depth.
 * @timeout: the input to give if anchor doesn't reach depth in time.
 * @unspent: the input to give if anchor is unspent after @depthok.
 * @theyspent: the input to give if they spend anchor with their commit tx.
 * @otherspent: the input to give if they spend anchor otherwise.
 *
 * @depthok can be INPUT_NONE if it's our anchor (we don't time
 * ourselves out).
 */
struct watch *bitcoin_watch_anchor(const tal_t *ctx,
				   const struct peer *peer,
				   enum state_input depthok,
				   enum state_input timeout,
				   enum state_input unspent,
				   enum state_input theyspent,
				   enum state_input otherspent);

/**
 * bitcoin_unwatch_anchor_depth: remove depth watch for the anchor.
 * @ctx: context to tal the watch struct off.
 * @peer: the state data for this peer.
 * @depthok: the input to give when anchor reaches expected depth.
 * @timeout: the input to give if anchor doesn't reach depth in time.
 *
 * @depthok and @timeout must match bitcoin_watch_anchor() call.
 */
struct watch *bitcoin_unwatch_anchor_depth(const tal_t *ctx,
					   const struct peer *peer,
					   enum state_input depthok,
					   enum state_input timeout);

/**
 * bitcoin_watch_delayed: watch this (commit) tx, tell me when I can spend it
 * @ctx: the context to tal the watch off
 * @tx: the tx we're watching.
 * @canspend: the input to give when commit reaches spendable depth.
 *
 * Note that this tx may be malleated, as it's dual-signed.
 */
struct watch *bitcoin_watch_delayed(const tal_t *ctx,
				    const struct bitcoin_tx *tx,
				    enum state_input canspend);

/**
 * bitcoin_watch: watch this tx until it's "irreversible"
 * @ctx: the context to tal the watch off
 * @tx: the tx we're watching.
 * @done: the input to give when tx is completely buried.
 *
 * The tx should be immalleable by BIP62; once this fires we consider
 * the channel completely closed and stop watching (eg 100 txs down).
 */
struct watch *bitcoin_watch(const tal_t *ctx,
			    const struct bitcoin_tx *tx,
			    enum state_input done);

/**
 * bitcoin_watch_close: watch close tx until it's "irreversible"
 * @ctx: context to tal the watch struct off.
 * @peer: the state data for this peer.
 * @done: the input to give when tx is completely buried.
 *
 * This tx *is* malleable, since the other side can transmit theirs.
 */
struct watch *bitcoin_watch_close(const tal_t *ctx,
				  const struct peer *peer,
				  enum state_input done);

/**
 * htlc_outputs_our_commit: HTLC outputs from our commit tx to watch.
 * @ctx: context to tal the watch struct off.
 * @peer: the state data for this peer.
 * @tx: the commitment tx
 * @tous_timeout: input to give when a HTLC output to us times out.
 * @tothem_spent: input to give when a HTLC output to them is spent.
 * @tothem_timeout: input to give when a HTLC output to them times out.
 */
struct htlc_watch *htlc_outputs_our_commit(const tal_t *ctx,
					   const struct peer *peer,
					   const struct bitcoin_tx *tx,
					   enum state_input tous_timeout,
					   enum state_input tothem_spent,
					   enum state_input tothem_timeout);

/**
 * htlc_outputs_their_commit: HTLC outputs from their commit tx to watch.
 * @ctx: context to tal the watch struct off.
 * @peer: the state data for this peer.
 * @tx: the commitment tx
 * @tous_timeout: input to give when a HTLC output to us times out.
 * @tothem_spent: input to give when a HTLC output to them is spent.
 * @tothem_timeout: input to give when a HTLC output to them times out.
 */
struct htlc_watch *htlc_outputs_their_commit(const tal_t *ctx,
					     const struct peer *peer,
					     const struct bitcoin_event *tx,
					     enum state_input tous_timeout,
					     enum state_input tothem_spent,
					     enum state_input tothem_timeout);

/**
 * htlc_unwatch: stop watching an HTLC
 * @ctx: context to tal the watch struct off.
 * @htlc: the htlc to stop watching
 * @all_done: input to give if we're not watching any anymore.
 */
struct htlc_unwatch *htlc_unwatch(const tal_t *ctx,
				  const struct htlc *htlc,
				  enum state_input all_done);

/**
 * htlc_unwatch_all: stop watching all HTLCs
 * @ctx: context to tal the watch struct off.
 * @peer: the state data for this peer.
 */
struct htlc_unwatch *htlc_unwatch_all(const tal_t *ctx,
				      const struct peer *peer);

/**
 * htlc_spend_watch: watch our spend of an HTLC
 * @ctx: context to tal the watch struct off.
 * @tx: the commitment tx
 * @cmd: the command data.
 * @done: input to give when it's completely buried.
 */
struct htlc_spend_watch *htlc_spend_watch(const tal_t *ctx,
					  const struct bitcoin_tx *tx,
					  const struct command *cmd,
					  enum state_input done);

/**
 * htlc_spend_unwatch: stop watching an HTLC spend
 * @ctx: context to tal the watch struct off.
 * @htlc: the htlc to stop watching
 * @all_done: input to give if we're not watching anything anymore.
 */
struct htlc_spend_watch *htlc_spend_unwatch(const tal_t *ctx,
					    const struct htlc *htlc,
					    enum state_input all_done);
/* Create a bitcoin anchor tx. */
struct bitcoin_tx *bitcoin_anchor(const tal_t *ctx,
				  const struct peer *peer);

/* Create a bitcoin close tx. */
struct bitcoin_tx *bitcoin_close(const tal_t *ctx,
				 const struct peer *peer);

/* Create a bitcoin spend tx (to spend our commit's outputs) */
struct bitcoin_tx *bitcoin_spend_ours(const tal_t *ctx,
				      const struct peer *peer);

/* Create a bitcoin spend tx (to spend their commit's outputs) */
struct bitcoin_tx *bitcoin_spend_theirs(const tal_t *ctx,
					const struct peer *peer,
					const struct bitcoin_event *btc);

/* Create a bitcoin steal tx (to steal all their commit's outputs) */
struct bitcoin_tx *bitcoin_steal(const tal_t *ctx,
				 const struct peer *peer,
				 struct bitcoin_event *btc);

/* Create our commit tx */
struct bitcoin_tx *bitcoin_commit(const tal_t *ctx,
				  const struct peer *peer);

/* Create a HTLC refund collection */
struct bitcoin_tx *bitcoin_htlc_timeout(const tal_t *ctx,
					const struct peer *peer,
					const struct htlc *htlc);

/* Create a HTLC collection */
struct bitcoin_tx *bitcoin_htlc_spend(const tal_t *ctx,
				      const struct peer *peer,
				      const struct htlc *htlc);

struct htlc_rval *r_value_from_cmd(const tal_t *ctx,
				   const struct peer *peer,
				   const struct htlc *htlc);
struct htlc_rval *bitcoin_r_value(const tal_t *ctx, const struct htlc *htlc);
struct htlc_rval *r_value_from_pkt(const tal_t *ctx, const Pkt *pkt);

#endif /* LIGHTNING_STATE_H */
