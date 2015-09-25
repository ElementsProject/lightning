#ifndef LIGHTNING_STATE_H
#define LIGHTNING_STATE_H
#include <state_types.h>
#include <stdbool.h>
#include <ccan/tal/tal.h>

/*
 * This is the core state machine.
 *
 * Calling the state machine with an input simply returns the new state,
 * and populates the "effect" struct with what it wants done.
 */
extern char cmd_requeue;

struct state_effect {
	/* Transaction to broadcast. */
	struct bitcoin_tx *broadcast;

	/* Packet to send. */
	Pkt *send;

	/* Event to watch for. */
	struct watch *watch;

	/* Events to no longer watch for. */
	struct watch *unwatch;

	/* Defer an input. */
	enum state_input defer;

	/* Complete a command. */
	enum state_input complete;
	/* NULL on success, &cmd_requeue on requeue, otherwise
	 * command-specific fail information. */
	void *complete_data;

	/* Stop taking packets? commands? */
	bool stop_packets, stop_commands;

	/* Set a timeout for close tx. */
	enum state_input close_timeout;

	/* Error received from other side. */
	Pkt *in_error;

	/* FIXME: More to come (for accept_*) */
};

/* Initialize the above struct. */
void state_effect_init(struct state_effect *effect);

static inline bool state_is_error(enum state s)
{
	return s >= STATE_ERR_ANCHOR_TIMEOUT && s <= STATE_ERR_INTERNAL;
}

struct state_data;

static bool input_is_pkt(enum state_input input)
{
	return input <= PKT_ERROR;
}

union input {
	Pkt *pkt;
	struct command *cmd;
	struct bitcoin_event *btc;
};

enum state state(const enum state state, const struct state_data *sdata,
		 const enum state_input input, const union input *idata,
		 struct state_effect *effect);

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

/* Create various kinds of packets, allocated off @ctx */
Pkt *pkt_open(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_anchor(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_open_commit_sig(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_open_complete(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_htlc_update(const tal_t *ctx, const struct state_data *sdata, void *data);
Pkt *pkt_htlc_fulfill(const tal_t *ctx, const struct state_data *sdata, void *data);
Pkt *pkt_htlc_timedout(const tal_t *ctx, const struct state_data *sdata, void *data);
Pkt *pkt_htlc_routefail(const tal_t *ctx, const struct state_data *sdata, void *data);
Pkt *pkt_update_accept(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_update_signature(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_update_complete(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_err(const tal_t *ctx, const char *msg);
Pkt *pkt_close(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_close_complete(const tal_t *ctx, const struct state_data *sdata);
Pkt *pkt_close_ack(const tal_t *ctx, const struct state_data *sdata);
Pkt *unexpected_pkt(const tal_t *ctx, enum state_input input);

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(struct state_effect *effect,
		     const struct state_data *sdata,
		     const Pkt *pkt);

Pkt *accept_pkt_anchor(struct state_effect *effect,
		       const struct state_data *sdata,
		       const Pkt *pkt);

Pkt *accept_pkt_open_commit_sig(struct state_effect *effect,
				const struct state_data *sdata, const Pkt *pkt);
	
Pkt *accept_pkt_htlc_update(struct state_effect *effect,
			    const struct state_data *sdata, const Pkt *pkt,
			    Pkt **decline);

Pkt *accept_pkt_htlc_routefail(struct state_effect *effect,
			       const struct state_data *sdata, const Pkt *pkt);

Pkt *accept_pkt_htlc_timedout(struct state_effect *effect,
			      const struct state_data *sdata, const Pkt *pkt);

Pkt *accept_pkt_htlc_fulfill(struct state_effect *effect,
			      const struct state_data *sdata, const Pkt *pkt);

Pkt *accept_pkt_update_accept(struct state_effect *effect,
			      const struct state_data *sdata, const Pkt *pkt);

Pkt *accept_pkt_update_complete(struct state_effect *effect,
				const struct state_data *sdata, const Pkt *pkt);

Pkt *accept_pkt_update_signature(struct state_effect *effect,
				 const struct state_data *sdata,
				 const Pkt *pkt);

Pkt *accept_pkt_close(struct state_effect *effect,
		      const struct state_data *sdata, const Pkt *pkt);

Pkt *accept_pkt_close_complete(struct state_effect *effect,
			       const struct state_data *sdata, const Pkt *pkt);

Pkt *accept_pkt_simultaneous_close(struct state_effect *effect,
				   const struct state_data *sdata,
				   const Pkt *pkt);

Pkt *accept_pkt_close_ack(struct state_effect *effect,
			  const struct state_data *sdata, const Pkt *pkt);

/**
 * bitcoin_watch_anchor: create a watch for the anchor.
 * @ctx: context to tal the watch struct off.
 * @sdata: the state data for this peer.
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
				   const struct state_data *sdata,
				   enum state_input depthok,
				   enum state_input timeout,
				   enum state_input unspent,
				   enum state_input theyspent,
				   enum state_input otherspent);

/**
 * bitcoin_unwatch_anchor_depth: remove depth watch for the anchor.
 * @ctx: context to tal the watch struct off.
 * @sdata: the state data for this peer.
 * @depthok: the input to give when anchor reaches expected depth.
 * @timeout: the input to give if anchor doesn't reach depth in time.
 *
 * @depthok and @timeout must match bitcoin_watch_anchor() call.
 */
struct watch *bitcoin_unwatch_anchor_depth(const tal_t *ctx,
					   const struct state_data *sdata,
					   enum state_input depthok,
					   enum state_input timeout);

/**
 * bitcoin_watch_delayed: watch this (commit) tx, tell me when I can spend it
 * @effect: the context to tal the watch off
 * @tx: the tx we're watching.
 * @canspend: the input to give when commit reaches spendable depth.
 *
 * Note that this tx may be malleated, as it's dual-signed.
 */
struct watch *bitcoin_watch_delayed(const struct state_effect *effect,
				    const struct bitcoin_tx *tx,
				    enum state_input canspend);

/**
 * bitcoin_watch: watch this tx until it's "irreversible"
 * @effect: the context to tal the watch off
 * @tx: the tx we're watching.
 * @done: the input to give when tx is completely buried.
 *
 * The tx should be immalleable by BIP62; once this fires we consider
 * the channel completely closed and stop watching (eg 100 txs down).
 */
struct watch *bitcoin_watch(const struct state_effect *effect,
			    const struct bitcoin_tx *tx,
			    enum state_input done);

/**
 * bitcoin_watch_close: watch close tx until it's "irreversible"
 * @ctx: context to tal the watch struct off.
 * @sdata: the state data for this peer.
 * @done: the input to give when tx is completely buried.
 *
 * This tx *is* malleable, since the other side can transmit theirs.
 */
struct watch *bitcoin_watch_close(const tal_t *ctx,
				  const struct state_data *sdata,
				  enum state_input done);


/* Create a bitcoin anchor tx. */
struct bitcoin_tx *bitcoin_anchor(const tal_t *ctx,
				  const struct state_data *sdata);

/* Create a bitcoin close tx. */
struct bitcoin_tx *bitcoin_close(const tal_t *ctx,
				 const struct state_data *sdata);

/* Create a bitcoin spend tx (to spend our commit's outputs) */
struct bitcoin_tx *bitcoin_spend_ours(const tal_t *ctx,
				      const struct state_data *sdata);

/* Create a bitcoin spend tx (to spend their commit's outputs) */
struct bitcoin_tx *bitcoin_spend_theirs(const tal_t *ctx,
					const struct state_data *sdata);

/* Create a bitcoin steal tx (to steal all their commit's outputs) */
struct bitcoin_tx *bitcoin_steal(const tal_t *ctx,
				 const struct state_data *sdata,
				 struct bitcoin_event *btc);

/* Create our commit tx */
struct bitcoin_tx *bitcoin_commit(const tal_t *ctx,
				  const struct state_data *sdata);

#endif /* LIGHTNING_STATE_H */
