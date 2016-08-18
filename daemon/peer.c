#include "bitcoind.h"
#include "chaintopology.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "controlled_time.h"
#include "cryptopkt.h"
#include "dns.h"
#include "find_p2sh_out.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "onion.h"
#include "output_to_htlc.h"
#include "packets.h"
#include "pay.h"
#include "payment.h"
#include "peer.h"
#include "permute_tx.h"
#include "protobuf_convert.h"
#include "pseudorand.h"
#include "remove_dust.h"
#include "routing.h"
#include "secrets.h"
#include "state.h"
#include "timeout.h"
#include "utils.h"
#include "wallet.h"
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

struct json_connecting {
	/* This owns us, so we're freed after command_fail or command_success */
	struct command *cmd;
	const char *name, *port;
	struct anchor_input *input;
};

static bool command_htlc_fail(struct peer *peer, struct htlc *htlc);
static bool command_htlc_fulfill(struct peer *peer, struct htlc *htlc);
static void try_commit(struct peer *peer);

void peer_add_their_commit(struct peer *peer,
			   const struct sha256_double *txid, u64 commit_num)
{
	struct their_commit *tc = tal(peer, struct their_commit);
	tc->txid = *txid;
	tc->commit_num = commit_num;
	list_add_tail(&peer->their_commits, &tc->list);
}

/* Create a bitcoin close tx, using last signature they sent. */
static const struct bitcoin_tx *bitcoin_close(struct peer *peer)
{
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature our_close_sig;

	close_tx = peer_create_close_tx(peer, peer->closing.their_fee);

	our_close_sig.stype = SIGHASH_ALL;
	peer_sign_mutual_close(peer, close_tx, &our_close_sig.sig);

	close_tx->input[0].witness
		= bitcoin_witness_2of2(close_tx->input,
				       peer->dstate->secpctx,
				       peer->closing.their_sig,
				       &our_close_sig,
				       &peer->remote.commitkey,
				       &peer->local.commitkey);

	return close_tx;
}

/* Create a bitcoin spend tx (to spend our commit's outputs) */
static const struct bitcoin_tx *bitcoin_spend_ours(struct peer *peer)
{
	u8 *witnessscript;
	const struct bitcoin_tx *commit = peer->local.commit->tx;
	struct bitcoin_signature sig;
	struct bitcoin_tx *tx;
	unsigned int p2wsh_out;
	uint64_t fee;

	/* The redeemscript for a commit tx is fairly complex. */
	witnessscript = bitcoin_redeem_secret_or_delay(peer,
						       peer->dstate->secpctx,
						      &peer->local.finalkey,
						      &peer->remote.locktime,
						      &peer->remote.finalkey,
						      &peer->local.commit->revocation_hash);

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(peer, 1, 1);
	tx->input[0].txid = peer->local.commit->txid;
	p2wsh_out = find_p2wsh_out(commit, witnessscript);
	tx->input[0].index = p2wsh_out;
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->remote.locktime);
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &commit->output[p2wsh_out].amount);

	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
						       peer->dstate->secpctx,
						       &peer->local.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 176 from an example run. */
	assert(measure_tx_cost(tx) == 83 * 4);

	fee = fee_by_feerate(83 + 176 / 4, get_feerate(peer->dstate));

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > commit->output[p2wsh_out].amount
	    || is_dust(commit->output[p2wsh_out].amount - fee))
		fatal("Amount of %"PRIu64" won't cover fee %"PRIu64,
		      commit->output[p2wsh_out].amount, fee);

	tx->output[0].amount = commit->output[p2wsh_out].amount - fee;

	sig.stype = SIGHASH_ALL;
	peer_sign_spend(peer, tx, witnessscript, &sig.sig);

	tx->input[0].witness = bitcoin_witness_secret(tx,
						      peer->dstate->secpctx,
						      NULL, 0, &sig,
						      witnessscript);

	return tx;
}

/* Sign and return our commit tx */
static const struct bitcoin_tx *bitcoin_commit(struct peer *peer)
{
	struct bitcoin_signature sig;

	/* Can't be signed already, and can't have scriptsig! */
	assert(peer->local.commit->tx->input[0].script_length == 0);
	assert(!peer->local.commit->tx->input[0].witness);

	sig.stype = SIGHASH_ALL;
	peer_sign_ourcommit(peer, peer->local.commit->tx, &sig.sig);

	peer->local.commit->tx->input[0].witness
		= bitcoin_witness_2of2(peer->local.commit->tx->input,
				       peer->dstate->secpctx,
				       peer->local.commit->sig,
				       &sig,
				       &peer->remote.commitkey,
				       &peer->local.commitkey);

	return peer->local.commit->tx;
}

static u64 commit_tx_fee(const struct bitcoin_tx *commit, u64 anchor_satoshis)
{
	uint64_t i, total = 0;

	for (i = 0; i < commit->output_count; i++)
		total += commit->output[i].amount;

	assert(anchor_satoshis >= total);
	return anchor_satoshis - total;
}

struct peer *find_peer(struct lightningd_state *dstate, const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list) {
		if (peer->id && pubkey_eq(peer->id, id))
			return peer;
	}
	return NULL;
}

static struct peer *find_peer_json(struct lightningd_state *dstate,
			      const char *buffer,
			      jsmntok_t *peeridtok)
{
	struct pubkey peerid;

	if (!pubkey_from_hexstr(dstate->secpctx,
				buffer + peeridtok->start,
				peeridtok->end - peeridtok->start, &peerid))
		return NULL;

	return find_peer(dstate, &peerid);
}

static bool peer_uncommitted_changes(const struct peer *peer)
{
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (htlc_has(h, HTLC_REMOTE_F_PENDING))
			return true;
	}
	return false;
}

static void remote_changes_pending(struct peer *peer)
{
	if (!peer->commit_timer) {
		log_debug(peer->log, "remote_changes_pending: adding timer");
		peer->commit_timer = new_reltimer(peer->dstate, peer,
						  peer->dstate->config.commit_time,
						  try_commit, peer);
	} else
		log_debug(peer->log, "remote_changes_pending: timer already exists");
}

static void peer_update_complete(struct peer *peer)
{
	log_debug(peer->log, "peer_update_complete");
	if (peer->commit_jsoncmd) {
		command_success(peer->commit_jsoncmd,
				null_response(peer->commit_jsoncmd));
		peer->commit_jsoncmd = NULL;
	}

	/* Have we got more changes in the meantime? */
	if (peer_uncommitted_changes(peer)) {
		log_debug(peer->log, "peer_update_complete: more changes!");
		remote_changes_pending(peer);
	}
}

void peer_open_complete(struct peer *peer, const char *problem)
{
	if (problem)
		log_unusual(peer->log, "peer open failed: %s", problem);
	else {
		struct lightningd_state *dstate = peer->dstate;
		struct node *n;

		log_debug(peer->log, "peer open complete");
		assert(!peer->nc);
		n = get_node(dstate, peer->id);
		if (!n)
			n = new_node(dstate, peer->id);
		peer->nc = add_connection(dstate,
					  get_node(dstate, &dstate->id), n,
					  dstate->config.fee_base,
					  dstate->config.fee_per_satoshi,
					  dstate->config.min_htlc_expiry,
					  dstate->config.min_htlc_expiry);
	}
}

static void set_peer_state(struct peer *peer, enum state newstate,
			   const char *caller)
{
	log_debug(peer->log, "%s: %s => %s", caller,
		  state_name(peer->state), state_name(newstate));
	peer->state = newstate;
}

static void peer_breakdown(struct peer *peer)
{
	if (peer->commit_jsoncmd) {
		command_fail(peer->commit_jsoncmd, "peer breakdown");
		peer->commit_jsoncmd = NULL;
	}
	
	/* If we have a closing tx, use it. */
	if (peer->closing.their_sig) {
		log_unusual(peer->log, "Peer breakdown: sending close tx");
		broadcast_tx(peer, bitcoin_close(peer));
	/* If we have a signed commit tx (maybe not if we just offered
	 * anchor, or they supplied anchor). */
	} else if (peer->local.commit->sig) {
		log_unusual(peer->log, "Peer breakdown: sending commit tx");
		broadcast_tx(peer, bitcoin_commit(peer));
	} else {
		log_info(peer->log, "Peer breakdown: nothing to do");
		/* We close immediately. */
		set_peer_state(peer, STATE_CLOSED, __func__);
		io_wake(peer);
	}
}

/* All unrevoked commit txs must have no HTLCs in them. */
static bool committed_to_htlcs(const struct peer *peer)
{
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (htlc_is_dead(h))
			continue;
		return true;
	}
	return false;
}

static struct io_plan *peer_close(struct io_conn *conn, struct peer *peer)
{
	/* Tell writer to wrap it up (may have to xmit first) */
	io_wake(peer);
	/* We do nothing more. */
	return io_wait(conn, NULL, io_never, NULL);
}

/* Communication failed: send err (if non-NULL), then dump to chain and close. */
static bool peer_comms_err(struct peer *peer, Pkt *err)
{
	if (err)
		queue_pkt_err(peer, err);

	set_peer_state(peer, STATE_ERR_BREAKDOWN, __func__);
	peer_breakdown(peer);
	return false;
}

void peer_unexpected_pkt(struct peer *peer, const Pkt *pkt)
{
	const char *p;

	log_unusual(peer->log, "Received unexpected pkt %u (%s)",
		    pkt->pkt_case, pkt_name(pkt->pkt_case));

	if (pkt->pkt_case != PKT__PKT_ERROR)
		return;

	/* Check packet for weird chars. */
	for (p = pkt->error->problem; *p; p++) {
		if (cisprint(*p))
			continue;

		p = tal_hexstr(peer, pkt->error->problem,
			       strlen(pkt->error->problem));
		log_unusual(peer->log, "Error pkt (hex) %s", p);
		tal_free(p);
		return;
	}
	log_unusual(peer->log, "Error pkt '%s'", pkt->error->problem);
}

/* Unexpected packet received: stop listening, start breakdown procedure. */
static bool peer_received_unexpected_pkt(struct peer *peer, const Pkt *pkt)
{
	peer_unexpected_pkt(peer, pkt);
	return peer_comms_err(peer, pkt_err_unexpected(peer, pkt));
}

static void route_htlc_onwards(struct peer *peer,
			       struct htlc *htlc,
			       u64 msatoshis,
			       const BitcoinPubkey *pb_id,
			       const u8 *rest_of_route)
{
	struct pubkey id;
	struct peer *next;

	log_debug_struct(peer->log, "Forwarding HTLC %s", struct sha256, &htlc->rhash);
	log_add(peer->log, " (id %"PRIu64")", htlc->id);
	
	if (!proto_to_pubkey(peer->dstate->secpctx, pb_id, &id)) {
		log_unusual(peer->log,
			    "Malformed pubkey for HTLC %"PRIu64, htlc->id);
		command_htlc_fail(peer, htlc);
		return;
	}

	next = find_peer(peer->dstate, &id);
	if (!next || !next->nc) {
		log_unusual(peer->log, "Can't route HTLC %"PRIu64": no %speer ",
			    htlc->id, next ? "ready " : "");
		log_add_struct(peer->log, "%s", struct pubkey, &id);
		if (!peer->dstate->dev_never_routefail)
			command_htlc_fail(peer, htlc);
		return;
	}

	/* Offered fee must be sufficient. */
	if (htlc->msatoshis - msatoshis < connection_fee(next->nc, msatoshis)) {
		log_unusual(peer->log,
			    "Insufficient fee for HTLC %"PRIu64
			    ": %"PRIi64" on %"PRIu64,
			    htlc->id, htlc->msatoshis - msatoshis,
			    msatoshis);
		command_htlc_fail(peer, htlc);
		return;
	}

	log_debug_struct(peer->log, "HTLC forward to %s",
			 struct pubkey, next->id);

	/* This checks the HTLC itself is possible. */
	if (!command_htlc_add(next, msatoshis,
			      abs_locktime_to_blocks(&htlc->expiry)
			      - next->nc->delay,
			      &htlc->rhash, htlc, rest_of_route)) {
		command_htlc_fail(peer, htlc);
		return;
	}
}

static void their_htlc_added(struct peer *peer, struct htlc *htlc)
{
	RouteStep *step;
	const u8 *rest_of_route;
	struct payment *payment;

	if (abs_locktime_is_seconds(&htlc->expiry)) {
		log_unusual(peer->log, "HTLC %"PRIu64" is in seconds", htlc->id);
		command_htlc_fail(peer, htlc);
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) <=
	    get_block_height(peer->dstate) + peer->dstate->config.min_htlc_expiry) {
		log_unusual(peer->log, "HTLC %"PRIu64" expires too soon:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_fail(peer, htlc);
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) >
	    get_block_height(peer->dstate) + peer->dstate->config.max_htlc_expiry) {
		log_unusual(peer->log, "HTLC %"PRIu64" expires too far:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_fail(peer, htlc);
		return;
	}

	step = onion_unwrap(peer, htlc->routing, tal_count(htlc->routing),
			    &rest_of_route);
	if (!step) {
		log_unusual(peer->log, "Bad onion, failing HTLC %"PRIu64,
			    htlc->id);
		command_htlc_fail(peer,	htlc);
		return;
	}

	switch (step->next_case) {
	case ROUTE_STEP__NEXT_END:
		payment = find_payment(peer->dstate, &htlc->rhash);
		if (!payment) {
			log_unusual(peer->log, "No payment for HTLC %"PRIu64,
				    htlc->id);
			log_add_struct(peer->log, " rhash=%s",
				       struct sha256, &htlc->rhash);
			if (unlikely(!peer->dstate->dev_never_routefail))
				command_htlc_fail(peer,	htlc);
			goto free_rest;
		}
			
		if (htlc->msatoshis != payment->msatoshis) {
			log_unusual(peer->log, "Short payment for HTLC %"PRIu64
				    ": %"PRIu64" not %"PRIu64 " satoshi!",
				    htlc->id,
				    htlc->msatoshis,
				    payment->msatoshis);
			command_htlc_fail(peer, htlc);
			return;
		}

		log_info(peer->log, "Immediately resolving HTLC %"PRIu64,
			 htlc->id);

		assert(!htlc->r);
		htlc->r = tal_dup(htlc, struct rval, &payment->r);
		command_htlc_fulfill(peer, htlc);
		goto free_rest;

	case ROUTE_STEP__NEXT_BITCOIN:
		route_htlc_onwards(peer, htlc, step->amount, step->bitcoin,
				   rest_of_route);
		goto free_rest;
	default:
		log_info(peer->log, "Unknown step type %u", step->next_case);
		command_htlc_fail(peer, htlc);
		goto free_rest;
	}

free_rest:
	tal_free(rest_of_route);
}

static void our_htlc_failed(struct peer *peer, struct htlc *htlc)
{
	if (htlc->src)
		command_htlc_fail(htlc->src->peer, htlc->src);
	else
		complete_pay_command(peer, htlc);
}

static void our_htlc_fulfilled(struct peer *peer, struct htlc *htlc,
			       const struct rval *preimage)
{
	if (htlc->src) {
		assert(!htlc->src->r);
		htlc->src->r = tal_dup(htlc->src, struct rval, htlc->r);
		command_htlc_fulfill(htlc->src->peer, htlc->src);
	} else {
		complete_pay_command(peer, htlc);
	}
}

static void adjust_cstate_side(struct channel_state *cstate,
			       struct htlc *h,
			       enum htlc_state old, enum htlc_state new,
			       enum htlc_side side)
{
	int oldf = htlc_state_flags(old), newf = htlc_state_flags(new);
	bool old_committed, new_committed;
	
	/* We applied changes to staging_cstate when we first received 
	 * add/remove packet, so we could make sure it was valid.  Don't
	 * do that again. */
	if (old == SENT_ADD_HTLC || old == RCVD_REMOVE_HTLC
	    || old == RCVD_ADD_HTLC || old == SENT_REMOVE_HTLC)
		return;
	
	old_committed = (oldf & HTLC_FLAG(side, HTLC_F_COMMITTED));
	new_committed = (newf & HTLC_FLAG(side, HTLC_F_COMMITTED));

	if (old_committed && !new_committed) {
		if (h->r)
			cstate_fulfill_htlc(cstate, h);
		else
			cstate_fail_htlc(cstate, h);
	} else if (!old_committed && new_committed) {
		/* FIXME: This can happen; see BOLT */
		if (!cstate_add_htlc(cstate, h))
			fatal("Could not afford htlc");
	}
}

/* We apply changes to staging_cstate when we first PENDING, so we can
 * make sure they're valid.  So here we change the staging_cstate on
 * the revocation receive (ie. when acked). */
static void adjust_cstates(struct peer *peer, struct htlc *h,
			   enum htlc_state old, enum htlc_state new)
{
	adjust_cstate_side(peer->remote.staging_cstate, h, old, new, REMOTE);
	adjust_cstate_side(peer->local.staging_cstate, h, old, new, LOCAL);
}

static void check_both_committed(struct peer *peer, struct htlc *h)
{
	if (!htlc_has(h, HTLC_ADDING) && !htlc_has(h, HTLC_REMOVING))
		log_debug(peer->log,
			  "Both committed to %s of %s HTLC %"PRIu64 "(%s)",
			  h->state == SENT_ADD_ACK_REVOCATION
			  || h->state == RCVD_ADD_ACK_REVOCATION ? "ADD"
			  : h->r ? "FULFILL" : "FAIL",
			  htlc_owner(h) == LOCAL ? "our" : "their",
			  h->id, htlc_state_name(h->state));

	switch (h->state) {
	case RCVD_REMOVE_ACK_REVOCATION:
		/* If it was fulfilled, we handled it immediately. */
		if (!h->r)
			our_htlc_failed(peer, h);
		break;
	case RCVD_ADD_ACK_REVOCATION:
		their_htlc_added(peer, h);
		break;
	default:
		break;
	}
}

struct state_table {
	enum htlc_state from, to;
};

static bool htlcs_changestate(struct peer *peer,
			      const struct state_table *table, size_t n)
{
	struct htlc_map_iter it;
	struct htlc *h;
	bool changed = false;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		size_t i;
		for (i = 0; i < n; i++) {
			if (h->state == table[i].from) {
				adjust_cstates(peer, h,
					       table[i].from, table[i].to);
				htlc_changestate(h, table[i].from, table[i].to);
				check_both_committed(peer, h);
				changed = true;
			}
		}
	}
	return changed;
}

/* This is the io loop while we're negotiating closing tx. */
static bool closing_pkt_in(struct peer *peer, const Pkt *pkt)
{
	const CloseSignature *c = pkt->close_signature;
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature theirsig;

	assert(peer->state == STATE_MUTUAL_CLOSING);

	if (pkt->pkt_case != PKT__PKT_CLOSE_SIGNATURE)
		return peer_received_unexpected_pkt(peer, pkt);

	log_info(peer->log, "closing_pkt_in: they offered close fee %"PRIu64,
		 c->close_fee);

	/* BOLT #2:
	 *
	 * The sender MUST set `close_fee` lower than or equal to the fee of the
	 * final commitment transaction, and MUST set `close_fee` to an even
	 * number of satoshis.
	 */
	if ((c->close_fee & 1)
	    || c->close_fee > commit_tx_fee(peer->remote.commit->tx,
					    peer->anchor.satoshis)) {
		return peer_comms_err(peer, pkt_err(peer, "Invalid close fee"));
	}

	/* FIXME: Don't accept tiny fee at all? */

	/* BOLT #2:
	   ... otherwise it SHOULD propose a
	   value strictly between the received `close_fee` and its
	   previously-sent `close_fee`.
	*/
	if (peer->closing.their_sig) {
		/* We want more, they should give more. */
		if (peer->closing.our_fee > peer->closing.their_fee) {
			if (c->close_fee <= peer->closing.their_fee)
				return peer_comms_err(peer,
						      pkt_err(peer, "Didn't increase close fee"));
		} else {
			if (c->close_fee >= peer->closing.their_fee)
				return peer_comms_err(peer,
						      pkt_err(peer, "Didn't decrease close fee"));
		}
	}

	/* BOLT #2:
	 *
	 * The receiver MUST check `sig` is valid for the close
	 * transaction with the given `close_fee`, and MUST fail the
	 * connection if it is not. */
	theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(peer->dstate->secpctx, c->sig, &theirsig.sig))
		return peer_comms_err(peer,
				      pkt_err(peer, "Invalid signature format"));

	close_tx = peer_create_close_tx(peer, c->close_fee);
	if (!check_tx_sig(peer->dstate->secpctx, close_tx, 0,
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->remote.commitkey, &theirsig))
		return peer_comms_err(peer,
				      pkt_err(peer, "Invalid signature"));

	tal_free(peer->closing.their_sig);
	peer->closing.their_sig = tal_dup(peer,
					  struct bitcoin_signature, &theirsig);
	peer->closing.their_fee = c->close_fee;

	if (peer->closing.our_fee != peer->closing.their_fee) {
		/* BOLT #2:
		 *
		 * If the receiver agrees with the fee, it SHOULD reply with a
		 * `close_signature` with the same `close_fee` value,
		 * otherwise it SHOULD propose a value strictly between the
		 * received `close_fee` and its previously-sent `close_fee`.
		 */

		/* Adjust our fee to close on their fee. */
		u64 sum;

		/* Beware overflow! */
		sum = (u64)peer->closing.our_fee + peer->closing.their_fee;

		peer->closing.our_fee = sum / 2;
		if (peer->closing.our_fee & 1)
			peer->closing.our_fee++;

		log_info(peer->log, "accept_pkt_close_sig: we change to %"PRIu64,
			 peer->closing.our_fee);

		queue_pkt_close_signature(peer);
	}

	/* Note corner case: we may *now* agree with them! */
	if (peer->closing.our_fee == peer->closing.their_fee) {
		log_info(peer->log, "accept_pkt_close_sig: we agree");
		/* BOLT #2:
		 *
		 * Once a node has sent or received a `close_signature` with
		 * matching `close_fee` it SHOULD close the connection and
		 * SHOULD sign and broadcast the final closing transaction.
		 */
		broadcast_tx(peer, bitcoin_close(peer));
		return false;
	}

	return true;
}

/* We can get update_commit in both normal and shutdown states. */
static Pkt *handle_pkt_commit(struct peer *peer, const Pkt *pkt)
{
	Pkt *err;
	struct sha256 preimage;
	struct commit_info *ci;
	/* FIXME: We can actually merge these two... */
	static const struct state_table commit_changes[] = {
		{ RCVD_ADD_REVOCATION, RCVD_ADD_ACK_COMMIT },
		{ RCVD_REMOVE_HTLC, RCVD_REMOVE_COMMIT },
		{ RCVD_ADD_HTLC, RCVD_ADD_COMMIT },
		{ RCVD_REMOVE_REVOCATION, RCVD_REMOVE_ACK_COMMIT }
	};
	static const struct state_table revocation_changes[] = {
		{ RCVD_ADD_ACK_COMMIT, SENT_ADD_ACK_REVOCATION },
		{ RCVD_REMOVE_COMMIT, SENT_REMOVE_REVOCATION },
		{ RCVD_ADD_COMMIT, SENT_ADD_REVOCATION },
		{ RCVD_REMOVE_ACK_COMMIT, SENT_REMOVE_ACK_REVOCATION }
	};

	ci = new_commit_info(peer, peer->local.commit->commit_num + 1);
	ci->sig = tal(ci, struct bitcoin_signature);
	err = accept_pkt_commit(peer, pkt, ci->sig);
	if (err)
		return err;

	/* BOLT #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (!htlcs_changestate(peer, commit_changes, ARRAY_SIZE(commit_changes)))
		return pkt_err(peer, "Empty commit");

	/* Create new commit info for this commit tx. */
	ci->revocation_hash = peer->local.next_revocation_hash;

	/* BOLT #2:
	 *
	 * A receiving node MUST apply all local acked and unacked
	 * changes except unacked fee changes to the local commitment
	 */
	/* (We already applied them to staging_cstate as we went) */
	ci->cstate = copy_cstate(ci, peer->local.staging_cstate);
	ci->tx = create_commit_tx(ci, peer, &ci->revocation_hash,
				  ci->cstate, LOCAL);
	bitcoin_txid(ci->tx, &ci->txid);

	/* BOLT #2:
	 *
	 * A receiving node MUST apply all local acked and unacked changes
	 * except unacked fee changes to the local commitment, then it MUST
	 * check `sig` is valid for that transaction.
	 */
	if (!check_tx_sig(peer->dstate->secpctx,
			  ci->tx, 0,
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->remote.commitkey,
			  ci->sig))
		return pkt_err(peer, "Bad signature");

	/* Switch to the new commitment. */
	tal_free(peer->local.commit);
	peer->local.commit = ci;
	peer_get_revocation_hash(peer, ci->commit_num + 1,
				 &peer->local.next_revocation_hash);
	peer->their_commitsigs++;

	/* Now, send the revocation. */

	/* We have their signature on the current one, right? */
	assert(peer->local.commit->sig);
	assert(peer->local.commit->commit_num > 0);

	if (!htlcs_changestate(peer, revocation_changes,
			       ARRAY_SIZE(revocation_changes)))
		fatal("sent revoke with no changes");

	peer_get_revocation_preimage(peer, peer->local.commit->commit_num - 1,
				     &preimage);

	/* Fire off timer if this ack caused new changes */
	if (peer_uncommitted_changes(peer))
		remote_changes_pending(peer);

	queue_pkt_revocation(peer, &preimage, &peer->local.next_revocation_hash);
	return NULL;
}

static Pkt *handle_pkt_htlc_add(struct peer *peer, const Pkt *pkt)
{
	struct htlc *htlc;
	Pkt *err;

	err = accept_pkt_htlc_add(peer, pkt, &htlc);
	if (err)
		return err;
	assert(htlc->state == RCVD_ADD_HTLC);
	
	/* BOLT #2:
	 *
	 * A node MUST NOT offer `amount_msat` it cannot pay for in
	 * the remote commitment transaction at the current `fee_rate` (see
	 * "Fee Calculation" ).  A node SHOULD fail the connection if
	 * this occurs.
	 */
	if (!cstate_add_htlc(peer->local.staging_cstate, htlc)) {
		tal_free(htlc);
		return pkt_err(peer, "Cannot afford %"PRIu64" milli-satoshis"
			       " in our commitment tx",
			       htlc->msatoshis);
	}
	return NULL;
}
	
static Pkt *handle_pkt_htlc_fail(struct peer *peer, const Pkt *pkt)
{
	struct htlc *htlc;
	Pkt *err;

	err = accept_pkt_htlc_fail(peer, pkt, &htlc);
	if (err)
		return err;

	cstate_fail_htlc(peer->local.staging_cstate, htlc);

	/* BOLT #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	htlc_changestate(htlc, SENT_ADD_ACK_REVOCATION, RCVD_REMOVE_HTLC);
	return NULL;
}

static Pkt *handle_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt)
{
	struct htlc *htlc;
	Pkt *err;

	err = accept_pkt_htlc_fulfill(peer, pkt, &htlc);
	if (err)
		return err;
	
	/* We can relay this upstream immediately. */
	our_htlc_fulfilled(peer, htlc, htlc->r);

	/* BOLT #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	cstate_fulfill_htlc(peer->local.staging_cstate, htlc);
	htlc_changestate(htlc, SENT_ADD_ACK_REVOCATION, RCVD_REMOVE_HTLC);
	return NULL;
}

static Pkt *handle_pkt_revocation(struct peer *peer, const Pkt *pkt)
{
	Pkt *err;
	static const struct state_table changes[] = {
		{ SENT_ADD_COMMIT, RCVD_ADD_REVOCATION },
		{ SENT_REMOVE_ACK_COMMIT, RCVD_REMOVE_ACK_REVOCATION },
		{ SENT_ADD_ACK_COMMIT, RCVD_ADD_ACK_REVOCATION },
		{ SENT_REMOVE_COMMIT, RCVD_REMOVE_REVOCATION }
	};

	err = accept_pkt_revocation(peer, pkt);
	if (err)
		return err;

	/* BOLT #2:
	 *
	 * The receiver of `update_revocation`... MUST add the remote
	 * unacked changes to the set of local acked changes.
	 */
	if (!htlcs_changestate(peer, changes, ARRAY_SIZE(changes)))
		fatal("Revocation received but we made empty commitment?");

	return NULL;
}	

static void peer_calculate_close_fee(struct peer *peer)
{
	/* Use actual worst-case length of close tx: based on BOLT#02's
	 * commitment tx numbers, but only 1 byte for output count */
	const uint64_t txsize = 41 + 221 + 10 + 32 + 32;
	uint64_t maxfee;

	peer->closing.our_fee
		= fee_by_feerate(txsize, get_feerate(peer->dstate));

	/* BOLT #2:
	 * The sender MUST set `close_fee` lower than or equal to the
	 * fee of the final commitment transaction, and MUST set
	 * `close_fee` to an even number of satoshis.
	 */
	maxfee = commit_tx_fee(peer->local.commit->tx, peer->anchor.satoshis);
	if (peer->closing.our_fee > maxfee) {
		/* This could only happen if the fee rate dramatically */
		log_unusual(peer->log,
			    "Closing fee %"PRIu64" exceeded commit fee %"PRIu64", reducing.",
			    peer->closing.our_fee, maxfee);
		peer->closing.our_fee = maxfee;

		/* This can happen if actual commit txfee is odd. */
		if (peer->closing.our_fee & 1)
			peer->closing.our_fee--;
	}
	assert(!(peer->closing.our_fee & 1));
}

/* This is the io loop while we're shutdown. */
static bool shutdown_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err = NULL;

	assert(peer->state == STATE_SHUTDOWN
	       || peer->state == STATE_SHUTDOWN_COMMITTING);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_REVOCATION:
		if (peer->state == STATE_SHUTDOWN)
			err = pkt_err_unexpected(peer, pkt);
		else {
			err = handle_pkt_revocation(peer, pkt);
			if (!err) {
				set_peer_state(peer, STATE_SHUTDOWN, __func__);
				peer_update_complete(peer);
			}
		}
		break;

	case PKT__PKT_UPDATE_ADD_HTLC:
		/* BOLT #2:
		 * 
		 * A node MUST NOT send a `update_add_htlc` after a
		 * `close_shutdown` */
		if (peer->closing.their_script)
			err = pkt_err(peer, "Update during shutdown");
		else
			err = handle_pkt_htlc_add(peer, pkt);
		break;
			
	case PKT__PKT_CLOSE_SHUTDOWN:
		/* BOLT #2:
		 * 
		 * A node... MUST NOT send more than one `close_shutdown`. */
		if (peer->closing.their_script)
			err = pkt_err_unexpected(peer, pkt);
		else
			err = accept_pkt_close_shutdown(peer, pkt);
		break;
			
	case PKT__PKT_UPDATE_FULFILL_HTLC:
		err = handle_pkt_htlc_fulfill(peer, pkt);
		break;
	case PKT__PKT_UPDATE_FAIL_HTLC:
		err = handle_pkt_htlc_fail(peer, pkt);
		break;
	case PKT__PKT_UPDATE_COMMIT:
		err = handle_pkt_commit(peer, pkt);
		break;
	case PKT__PKT_ERROR:
		peer_unexpected_pkt(peer, pkt);
		return peer_comms_err(peer, NULL);

	case PKT__PKT_AUTH:
	case PKT__PKT_OPEN:
	case PKT__PKT_OPEN_ANCHOR:
	case PKT__PKT_OPEN_COMMIT_SIG:
	case PKT__PKT_OPEN_COMPLETE:
	case PKT__PKT_CLOSE_SIGNATURE:
	default:
		peer_unexpected_pkt(peer, pkt);
		err = pkt_err_unexpected(peer, pkt);
		break;
	}

	if (err)
		return peer_comms_err(peer, err);

	if (!committed_to_htlcs(peer)) {
		set_peer_state(peer, STATE_MUTUAL_CLOSING, __func__);
		peer_calculate_close_fee(peer);
		queue_pkt_close_signature(peer);
	}

	return true;
}

static void peer_start_shutdown(struct peer *peer)
{
	assert(peer->state == STATE_SHUTDOWN
	       || peer->state == STATE_SHUTDOWN_COMMITTING);

	/* If they started close, we might not have sent ours. */
	if (!peer->closing.our_script) {
		u8 *redeemscript = bitcoin_redeem_single(peer,
							 peer->dstate->secpctx,
							 &peer->local.finalkey);

		peer->closing.our_script = scriptpubkey_p2sh(peer, redeemscript);
		tal_free(redeemscript);
		/* BOLT #2:
		 *
		 * A node SHOULD send a `close_shutdown` (if it has
		 * not already) after receiving `close_shutdown`.
		 */
		queue_pkt_close_shutdown(peer);
	}

	/* Catch case where we've exchanged and had no HTLCs anyway. */
	if (peer->closing.our_script && peer->closing.their_script
	    && !committed_to_htlcs(peer)) {
		set_peer_state(peer, STATE_MUTUAL_CLOSING, __func__);
		peer_calculate_close_fee(peer);
		queue_pkt_close_signature(peer);
	}
}
	
/* This is the io loop while we're in normal mode. */
static bool normal_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err = NULL;

	assert(peer->state == STATE_NORMAL
	       || peer->state == STATE_NORMAL_COMMITTING);

	switch (pkt->pkt_case) {
	case PKT_UPDATE_ADD_HTLC:
		err = handle_pkt_htlc_add(peer, pkt);
		break;
		
	case PKT_UPDATE_FULFILL_HTLC:
		err = handle_pkt_htlc_fulfill(peer, pkt);
		break;

	case PKT_UPDATE_FAIL_HTLC:
		err = handle_pkt_htlc_fail(peer, pkt);
		break;

	case PKT_UPDATE_COMMIT:
		err = handle_pkt_commit(peer, pkt);
		break;

	case PKT_CLOSE_SHUTDOWN:
		err = accept_pkt_close_shutdown(peer, pkt);
		if (err)
			break;
		if (peer->state == STATE_NORMAL)
			set_peer_state(peer, STATE_SHUTDOWN, __func__);
		else {
			assert(peer->state == STATE_NORMAL_COMMITTING);
			set_peer_state(peer, STATE_SHUTDOWN_COMMITTING,
				       __func__);
		}

		peer_start_shutdown(peer);
		return true;

	case PKT_UPDATE_REVOCATION:
		if (peer->state == STATE_NORMAL_COMMITTING) {
			err = handle_pkt_revocation(peer, pkt);
			if (!err) {
				peer_update_complete(peer);
				set_peer_state(peer, STATE_NORMAL, __func__);
			}
			break;
		}
		/* Fall thru. */
	default:
		return peer_received_unexpected_pkt(peer, pkt);
	}	

	if (err) {
		return peer_comms_err(peer, err);
	}

	return true;
}

static void state_single(struct peer *peer,
			 const enum state_input input,
			 const Pkt *pkt)
{
	const struct bitcoin_tx *broadcast;
	enum state newstate;
	size_t old_outpkts = tal_count(peer->outpkt);

	newstate = state(peer, input, pkt, &broadcast);
	set_peer_state(peer, newstate, input_name(input));

	/* If we added uncommitted changes, we should have set them to send. */
	if (peer_uncommitted_changes(peer))
		assert(peer->commit_timer);
	
	if (tal_count(peer->outpkt) > old_outpkts) {
		Pkt *outpkt = peer->outpkt[old_outpkts];
		log_add(peer->log, " (out %s)", pkt_name(outpkt->pkt_case));
	}
	if (broadcast)
		broadcast_tx(peer, broadcast);

	if (state_is_error(peer->state)) {
		/* Breakdown is common, others less so. */
		if (peer->state != STATE_ERR_BREAKDOWN)
			log_broken(peer->log, "Entered error state %s",
				   state_name(peer->state));
		peer_breakdown(peer);

		/* Start output if not running already; it will close conn. */
		io_wake(peer);
	}
}

static void state_event(struct peer *peer, 
			const enum state_input input,
			const Pkt *pkt)
{
	if (!state_is_opening(peer->state)) {
		log_unusual(peer->log,
			    "Unexpected input %s while state %s",
			    input_name(input), state_name(peer->state));
	} else {
		state_single(peer, input, pkt);
	}
}

/* Create a HTLC fulfill transaction for onchain.tx[out_num]. */
static const struct bitcoin_tx *htlc_fulfill_tx(const struct peer *peer,
						unsigned int out_num)
{
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	const struct htlc *htlc = peer->onchain.htlcs[out_num];
	const u8 *wscript = peer->onchain.wscripts[out_num];
	struct bitcoin_signature sig;
	u64 fee, satoshis;

	assert(htlc->r);

	tx->input[0].index = out_num;
	tx->input[0].txid = peer->onchain.txid;
	satoshis = htlc->msatoshis / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's their HTLC, and that we collected it via rval. */
	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
						       peer->dstate->secpctx,
						       &peer->local.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	log_debug(peer->log, "Pre-witness txlen = %zu\n",
		  measure_tx_cost(tx) / 4);

	assert(measure_tx_cost(tx) == 83 * 4);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 539 from an example run. */
	fee = fee_by_feerate(83 + 539 / 4, get_feerate(peer->dstate));

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > satoshis || is_dust(satoshis - fee))
		fatal("HTLC fulfill amount of %"PRIu64" won't cover fee %"PRIu64,
		      satoshis, fee);

	tx->output[0].amount = satoshis - fee;

	sig.stype = SIGHASH_ALL;
	peer_sign_htlc_fulfill(peer, tx, wscript, &sig.sig);

	tx->input[0].witness = bitcoin_witness_htlc(tx, peer->dstate->secpctx,
						    htlc->r, &sig, wscript);

	log_debug(peer->log, "tx cost for htlc fulfill tx: %zu",
		  measure_tx_cost(tx));

	return tx;
}

/* FIXME: Reason! */
static bool command_htlc_fail(struct peer *peer, struct htlc *htlc)
{
	/* If onchain, nothing we can do. */
	if (!state_can_remove_htlc(peer->state))
		return false;

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	cstate_fail_htlc(peer->remote.staging_cstate, htlc);

	htlc_changestate(htlc, RCVD_ADD_ACK_REVOCATION, SENT_REMOVE_HTLC);

	remote_changes_pending(peer);

	queue_pkt_htlc_fail(peer, htlc);
	return true;
}

/* BOLT #onchain:
 *
 * If the node receives... a redemption preimage for an unresolved *commitment
 * tx* output it was offered, it MUST *resolve* the output by spending it using
 * the preimage.
 */
static bool fulfill_onchain(struct peer *peer, struct htlc *htlc)
{
	size_t i;

	for (i = 0; i < tal_count(peer->onchain.htlcs); i++) {
		if (peer->onchain.htlcs[i] == htlc) {
			/* Already irrevocably resolved? */
			if (peer->onchain.resolved[i])
				return false;
			peer->onchain.resolved[i]
				= htlc_fulfill_tx(peer, i);
			broadcast_tx(peer, peer->onchain.resolved[i]);
			return true;
		}
	}
	fatal("Unknown HTLC to fulfill onchain");
}

static bool command_htlc_fulfill(struct peer *peer, struct htlc *htlc)
{
	if (peer->state == STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL
	    || peer->state == STATE_CLOSE_ONCHAIN_OUR_UNILATERAL) {
		return fulfill_onchain(peer, htlc);
	}

	if (!state_can_remove_htlc(peer->state))
		return false;

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	cstate_fulfill_htlc(peer->remote.staging_cstate, htlc);

	htlc_changestate(htlc, RCVD_ADD_ACK_REVOCATION, SENT_REMOVE_HTLC);

	remote_changes_pending(peer);

	queue_pkt_htlc_fulfill(peer, htlc);
	return true;
}

struct htlc *command_htlc_add(struct peer *peer, u64 msatoshis,
			      unsigned int expiry,
			      const struct sha256 *rhash,
			      struct htlc *src,
			      const u8 *route)
{
	struct channel_state *cstate;
	struct abs_locktime locktime;
	struct htlc *htlc;

	if (!blocks_to_abs_locktime(expiry, &locktime)) {
		log_unusual(peer->log, "add_htlc: fail: bad expiry %u", expiry);
		return NULL;
	}

	if (expiry < get_block_height(peer->dstate) + peer->dstate->config.min_htlc_expiry) {
		log_unusual(peer->log, "add_htlc: fail: expiry %u is too soon",
			    expiry);
		return NULL;
	}

	if (expiry > get_block_height(peer->dstate) + peer->dstate->config.max_htlc_expiry) {
		log_unusual(peer->log, "add_htlc: fail: expiry %u is too far",
			    expiry);
		return NULL;
	}

	/* BOLT #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 300 HTLCs in the remote commitment transaction.
	 */
	if (peer->remote.staging_cstate->side[OURS].num_htlcs == 300) {
		log_unusual(peer->log, "add_htlc: fail: already at limit");
		return NULL;
	}

	if (!state_can_add_htlc(peer->state)) {
		log_unusual(peer->log, "add_htlc: fail: peer state %s",
			    state_name(peer->state));
		return NULL;
	}

	htlc = peer_new_htlc(peer, peer->htlc_id_counter,
			     msatoshis, rhash, expiry, route, tal_count(route),
			     src, SENT_ADD_HTLC);

	/* FIXME: BOLT is not correct here: we should say IFF we cannot
	 * afford it in remote at its own current proposed fee-rate. */
	/* BOLT #2:
	 *
	 * A node MUST NOT offer `amount_msat` it cannot pay for in
	 * the remote commitment transaction at the current `fee_rate`
	 */
	cstate = copy_cstate(peer, peer->remote.staging_cstate);
	if (!cstate_add_htlc(cstate, htlc)) {
		log_unusual(peer->log, "add_htlc: fail: Cannot afford %"PRIu64
			    " milli-satoshis in their commit tx",
			    msatoshis);
		return tal_free(htlc);
	}
	tal_free(cstate);

	cstate = copy_cstate(peer, peer->local.staging_cstate);
	if (!cstate_add_htlc(cstate, htlc)) {
		log_unusual(peer->log, "add_htlc: fail: Cannot afford %"PRIu64
			    " milli-satoshis in our commit tx",
			    msatoshis);
		return tal_free(htlc);
	}
	tal_free(cstate);

	/* BOLT #2:
	 *
	 * The sending node MUST add the HTLC addition to the unacked
	 * changeset for its remote commitment
	 */
	if (!cstate_add_htlc(peer->remote.staging_cstate, htlc))
		fatal("Could not add HTLC?");

	remote_changes_pending(peer);

	queue_pkt_htlc_add(peer, htlc);

	/* Make sure we never offer the same one twice. */
	peer->htlc_id_counter++;

	return htlc;
}

static struct io_plan *pkt_out(struct io_conn *conn, struct peer *peer)
{
	Pkt *out;
	size_t n = tal_count(peer->outpkt);

	if (n == 0) {
		/* We close the connection once we've sent everything. */
		if (!state_can_io(peer->state)) {
			log_debug(peer->log, "pkt_out: no IO possible, closing");
			return io_close(conn);
		}
		return io_out_wait(conn, peer, pkt_out, peer);
	}

	if (peer->fake_close || !peer->output_enabled)
		return io_out_wait(conn, peer, pkt_out, peer);

	out = peer->outpkt[0];
	memmove(peer->outpkt, peer->outpkt + 1, (sizeof(*peer->outpkt)*(n-1)));
	tal_resize(&peer->outpkt, n-1);
	return peer_write_packet(conn, peer, out, pkt_out);
}

static struct io_plan *pkt_in(struct io_conn *conn, struct peer *peer)
{
	bool keep_going;

	/* We ignore packets if they tell us to, or we're closing already */
	if (peer->fake_close || !state_can_io(peer->state))
		keep_going = true;
	else if (state_is_normal(peer->state))
		keep_going = normal_pkt_in(peer, peer->inpkt);
	else if (state_is_shutdown(peer->state))
		keep_going = shutdown_pkt_in(peer, peer->inpkt);
	else if (peer->state == STATE_MUTUAL_CLOSING)
		keep_going = closing_pkt_in(peer, peer->inpkt);
	else {
		state_event(peer, peer->inpkt->pkt_case, peer->inpkt);
		keep_going = true;
	}

	peer->inpkt = tal_free(peer->inpkt);
	if (keep_going)
		return peer_read_packet(conn, peer, pkt_in);
	else
		return peer_close(conn, peer);
}

/* Crypto is on, we are live. */
static struct io_plan *peer_crypto_on(struct io_conn *conn, struct peer *peer)
{
	peer_secrets_init(peer);

	peer_get_revocation_hash(peer, 0, &peer->local.next_revocation_hash);

	assert(peer->state == STATE_INIT);

	state_event(peer, peer->local.offer_anchor, NULL);

	return io_duplex(conn,
			 peer_read_packet(conn, peer, pkt_in),
			 pkt_out(conn, peer));
}

static void destroy_peer(struct peer *peer)
{
	if (peer->conn)
		io_close(peer->conn);
	list_del_from(&peer->dstate->peers, &peer->list);
}

static void peer_disconnect(struct io_conn *conn, struct peer *peer)
{
	log_info(peer->log, "Disconnected");

	/* No longer connected. */
	peer->conn = NULL;

	/* Not even set up yet?  Simply free.*/
	if (peer->state == STATE_INIT) {
		tal_free(peer);
		return;
	}

	/* Completely dead?  Free it now. */
	if (peer->state == STATE_CLOSED) {
		io_break(peer);
		return;
	}

	/* This is an unexpected close. */
	if (!state_is_onchain(peer->state) && !state_is_error(peer->state)) {
		/* FIXME: Try to reconnect. */
		set_peer_state(peer, STATE_ERR_BREAKDOWN, "peer_disconnect");
		peer_breakdown(peer);
	}
}

static void do_commit(struct peer *peer, struct command *jsoncmd)
{
	struct commit_info *ci;
	static const struct state_table changes[] = {
		{ SENT_ADD_HTLC, SENT_ADD_COMMIT },
		{ SENT_REMOVE_REVOCATION, SENT_REMOVE_ACK_COMMIT },
		{ SENT_ADD_REVOCATION, SENT_ADD_ACK_COMMIT},
		{ SENT_REMOVE_HTLC, SENT_REMOVE_COMMIT}
	};

	/* We can have changes we suggested, or changes they suggested. */
	if (!peer_uncommitted_changes(peer)) {
		log_debug(peer->log, "do_commit: no changes to commit");
		if (jsoncmd)
			command_fail(jsoncmd, "no changes to commit");
		return;
	}

	log_debug(peer->log, "do_commit: sending commit command");

	assert(state_can_commit(peer->state));
	assert(!peer->commit_jsoncmd);

	peer->commit_jsoncmd = jsoncmd;
	ci = new_commit_info(peer, peer->remote.commit->commit_num + 1);

	assert(!peer->their_prev_revocation_hash);
	peer->their_prev_revocation_hash
		= tal_dup(peer, struct sha256,
			  &peer->remote.commit->revocation_hash);

	/* BOLT #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (!htlcs_changestate(peer, changes, ARRAY_SIZE(changes)))
		fatal("sent commit with no changes");

	/* Create new commit info for this commit tx. */
	ci->revocation_hash = peer->remote.next_revocation_hash;
	/* BOLT #2:
	 *
	 * A sending node MUST apply all remote acked and unacked
	 * changes except unacked fee changes to the remote commitment
	 * before generating `sig`. */
	ci->cstate = copy_cstate(ci, peer->remote.staging_cstate);
	ci->tx = create_commit_tx(ci, peer, &ci->revocation_hash,
				  ci->cstate, REMOTE);
	bitcoin_txid(ci->tx, &ci->txid);

	log_debug(peer->log, "Signing tx for %u/%u msatoshis, %u/%u htlcs (%u non-dust)",
		  ci->cstate->side[OURS].pay_msat,
		  ci->cstate->side[THEIRS].pay_msat,
		  ci->cstate->side[OURS].num_htlcs,
		  ci->cstate->side[THEIRS].num_htlcs,
		  ci->cstate->num_nondust);
	log_add_struct(peer->log, " (txid %s)", struct sha256_double, &ci->txid);

	ci->sig = tal(ci, struct bitcoin_signature);
	ci->sig->stype = SIGHASH_ALL;
	peer_sign_theircommit(peer, ci->tx, &ci->sig->sig);

	/* Switch to the new commitment. */
	tal_free(peer->remote.commit);
	peer->remote.commit = ci;

	peer_add_their_commit(peer, &ci->txid, ci->commit_num);
	
	queue_pkt_commit(peer);
	if (peer->state == STATE_SHUTDOWN) {
		set_peer_state(peer, STATE_SHUTDOWN_COMMITTING, __func__);
	} else {
		assert(peer->state == STATE_NORMAL);
		set_peer_state(peer, STATE_NORMAL_COMMITTING, __func__);
	}
}

static void try_commit(struct peer *peer)
{
	peer->commit_timer = NULL;

	if (state_can_commit(peer->state))
		do_commit(peer, NULL);
	else {
		/* FIXME: try again when we receive revocation, rather
		 * than using timer! */
		log_debug(peer->log, "try_commit: state=%s, re-queueing timer",
			  state_name(peer->state));
		
		remote_changes_pending(peer);
	}
}

struct commit_info *new_commit_info(const tal_t *ctx, u64 commit_num)
{
	struct commit_info *ci = tal(ctx, struct commit_info);
	ci->commit_num = commit_num;
	ci->tx = NULL;
	ci->cstate = NULL;
	ci->sig = NULL;
	return ci;
}

static struct peer *new_peer(struct lightningd_state *dstate,
			     struct io_conn *conn,
			     int addr_type, int addr_protocol,
			     enum state_input offer_anchor,
			     const char *in_or_out)
{
	struct peer *peer = tal(dstate, struct peer);

	assert(offer_anchor == CMD_OPEN_WITH_ANCHOR
	       || offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);

	/* FIXME: Stop listening if too many peers? */
	list_add(&dstate->peers, &peer->list);

	peer->state = STATE_INIT;
	peer->id = NULL;
	peer->dstate = dstate;
	peer->addr.type = addr_type;
	peer->addr.protocol = addr_protocol;
	peer->io_data = NULL;
	peer->secrets = NULL;
	list_head_init(&peer->watches);
	peer->outpkt = tal_arr(peer, Pkt *, 0);
	peer->commit_jsoncmd = NULL;
	list_head_init(&peer->outgoing_txs);
	list_head_init(&peer->pay_commands);
	list_head_init(&peer->their_commits);
	peer->anchor.ok_depth = -1;
	peer->their_commitsigs = 0;
	peer->cur_commit.watch = NULL;
	peer->closing.their_sig = NULL;
	peer->closing.our_script = NULL;
	peer->closing.their_script = NULL;
	peer->onchain.tx = NULL;
	peer->onchain.resolved = NULL;
	peer->onchain.htlcs = NULL;
	peer->onchain.wscripts = NULL;
	peer->commit_timer = NULL;
	peer->nc = NULL;
	peer->their_prev_revocation_hash = NULL;
	/* Make it different from other node (to catch bugs!), but a
	 * round number for simple eyeballing. */
	peer->htlc_id_counter = pseudorand(1ULL << 32) * 1000;

	/* If we free peer, conn should be closed, but can't be freed
	 * immediately so don't make peer a parent. */
	peer->conn = conn;
	peer->fake_close = false;
	peer->output_enabled = true;
	io_set_finish(conn, peer_disconnect, peer);
	
	peer->local.offer_anchor = offer_anchor;
	if (!blocks_to_rel_locktime(dstate->config.locktime_blocks,
				    &peer->local.locktime))
		fatal("Could not convert locktime_blocks");
	peer->local.mindepth = dstate->config.anchor_confirms;
	/* FIXME: Make this dynamic! */
	peer->local.commit_fee_rate
		= get_feerate(peer->dstate)
		* peer->dstate->config.commitment_fee_percent / 100;
	peer->local.commit = peer->remote.commit = NULL;
	peer->local.staging_cstate = peer->remote.staging_cstate = NULL;

	htlc_map_init(&peer->htlcs);
	
	/* FIXME: Attach IO logging for this peer. */
	tal_add_destructor(peer, destroy_peer);

	peer->addr.addrlen = sizeof(peer->addr.saddr);
	if (getpeername(io_conn_fd(conn), &peer->addr.saddr.s,
			&peer->addr.addrlen) != 0) {
		log_unusual(dstate->base_log,
			    "Could not get address for peer: %s",
			    strerror(errno));
		return tal_free(peer);
	}

	peer->log = new_log(peer, dstate->log_record, "%s%s:%s:",
			    log_prefix(dstate->base_log), in_or_out,
			    netaddr_name(peer, &peer->addr));

	log_debug(peer->log, "Using fee rate %"PRIu64,
		  peer->local.commit_fee_rate);
	return peer;
}

/* Unused for the moment. */
#if 0
static u64 peer_commitsigs_received(struct peer *peer)
{
	return peer->their_commitsigs;
}

static u64 peer_revocations_received(struct peer *peer)
{
	/* How many preimages we've received. */
	return -peer->their_preimages.min_index;
}
#endif

static void htlc_destroy(struct htlc *htlc)
{
	if (!htlc_map_del(&htlc->peer->htlcs, htlc))
		fatal("Could not find htlc to destroy");
}

struct htlc *peer_new_htlc(struct peer *peer, 
			   u64 id,
			   u64 msatoshis,
			   const struct sha256 *rhash,
			   u32 expiry,
			   const u8 *route,
			   size_t routelen,
			   struct htlc *src,
			   enum htlc_state state)
{
	struct htlc *h = tal(peer, struct htlc);
	h->peer = peer;
	assert(state == SENT_ADD_HTLC || state == RCVD_ADD_HTLC);
	h->state = state;
	h->id = id;
	h->msatoshis = msatoshis;
	h->rhash = *rhash;
	h->r = NULL;
	if (!blocks_to_abs_locktime(expiry, &h->expiry))
		fatal("Invalid HTLC expiry %u", expiry);
	h->routing = tal_dup_arr(h, u8, route, routelen, 0);
	h->src = src;
	if (htlc_owner(h) == LOCAL) {
		if (src) {
			h->deadline = abs_locktime_to_blocks(&src->expiry)
				- peer->dstate->config.deadline_blocks;
		} else
			/* If we're paying, give it a little longer. */
			h->deadline = expiry
				+ peer->dstate->config.min_htlc_expiry;
	} else {
		assert(htlc_owner(h) == REMOTE);
	}
	htlc_map_add(&peer->htlcs, h);
	tal_add_destructor(h, htlc_destroy);

	return h;
}

static struct io_plan *crypto_on_out(struct io_conn *conn,
				     struct lightningd_state *dstate,
				     struct io_data *iod,
				     const struct pubkey *id,
				     struct json_connecting *connect)
{
	/* Initiator currently funds channel */
	struct peer *peer = new_peer(dstate, conn, SOCK_STREAM, IPPROTO_TCP,
				     CMD_OPEN_WITH_ANCHOR, "out");
	if (!peer) {
		command_fail(connect->cmd, "Failed to make peer for %s:%s",
			     connect->name, connect->port);
		return io_close(conn);
	}
	peer->io_data = tal_steal(peer, iod);
	peer->id = tal_dup(peer, struct pubkey, id);
	peer->anchor.input = tal_steal(peer, connect->input);

	command_success(connect->cmd, null_response(connect));
	return peer_crypto_on(conn, peer);
}

static struct io_plan *peer_connected_out(struct io_conn *conn,
					  struct lightningd_state *dstate,
					  struct json_connecting *connect)
{
	log_debug(dstate->base_log, "Connected out to %s:%s",
		  connect->name, connect->port);

	return peer_crypto_setup(conn, dstate, NULL, crypto_on_out, connect);
}

static struct io_plan *crypto_on_in(struct io_conn *conn,
				    struct lightningd_state *dstate,
				    struct io_data *iod,
				    const struct pubkey *id,
				    void *unused)
{
	/* Initiator currently funds channel */
	struct peer *peer = new_peer(dstate, conn, SOCK_STREAM, IPPROTO_TCP,
				     CMD_OPEN_WITHOUT_ANCHOR, "in");
	if (!peer)
		return io_close(conn);

	peer->io_data = tal_steal(peer, iod);
	peer->id = tal_dup(peer, struct pubkey, id);
	return peer_crypto_on(conn, peer);
}

static struct io_plan *peer_connected_in(struct io_conn *conn,
					 struct lightningd_state *dstate)
{
	/* FIXME: log incoming address. */
	log_debug(dstate->base_log, "Connected in");

	return peer_crypto_setup(conn, dstate, NULL, crypto_on_in, NULL);
}

static int make_listen_fd(struct lightningd_state *dstate,
			  int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		log_debug(dstate->base_log, "Failed to create %u socket: %s",
			  domain, strerror(errno));
		return -1;
	}

	if (addr) {
		int on = 1;

		/* Re-use, please.. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
			log_unusual(dstate->base_log,
				    "Failed setting socket reuse: %s",
				    strerror(errno));

		if (bind(fd, addr, len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed to bind on %u socket: %s",
				    domain, strerror(errno));
			goto fail;
		}
	}

	if (listen(fd, 5) != 0) {
		log_unusual(dstate->base_log,
			    "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
		goto fail;
	}
	return fd;

fail:
	close_noerr(fd);
	return -1;
}

void setup_listeners(struct lightningd_state *dstate, unsigned int portnum)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;
	u16 listen_port;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(portnum);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(dstate, AF_INET6, portnum ? &addr6 : NULL,
			     sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
		} else {
			addr.sin_port = in6.sin6_port;
			listen_port = ntohs(addr.sin_port);
			log_info(dstate->base_log,
				 "Creating IPv6 listener on port %u",
				 listen_port);
			io_new_listener(dstate, fd1, peer_connected_in, dstate);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(dstate, AF_INET,
			     addr.sin_port ? &addr : NULL, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
		} else {
			listen_port = ntohs(addr.sin_port);
			log_info(dstate->base_log,
				 "Creating IPv4 listener on port %u",
				 listen_port);
			io_new_listener(dstate, fd2, peer_connected_in, dstate);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal("Could not bind to a network address");
}

static void peer_failed(struct lightningd_state *dstate,
			struct json_connecting *connect)
{
	/* FIXME: Better diagnostics! */
	command_fail(connect->cmd, "Failed to connect to peer %s:%s",
		     connect->name, connect->port);
}

static void json_connect(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct json_connecting *connect;
	jsmntok_t *host, *port, *txtok;
	struct bitcoin_tx *tx;
	int output;
	size_t txhexlen;

	if (!json_get_params(buffer, params,
			     "host", &host,
			     "port", &port,
			     "tx", &txtok,
			     NULL)) {
		command_fail(cmd, "Need host, port and tx to a wallet address");
		return;
	}

	connect = tal(cmd, struct json_connecting);
	connect->cmd = cmd;
	connect->name = tal_strndup(connect, buffer + host->start,
				    host->end - host->start);
	connect->port = tal_strndup(connect, buffer + port->start,
				    port->end - port->start);
	connect->input = tal(connect, struct anchor_input);

	txhexlen = txtok->end - txtok->start;
	tx = bitcoin_tx_from_hex(connect->input, buffer + txtok->start,
				 txhexlen);
	if (!tx) {
		command_fail(cmd, "'%.*s' is not a valid transaction",
			     txtok->end - txtok->start,
			     buffer + txtok->start);
		return;
	}

	bitcoin_txid(tx, &connect->input->txid);

	/* Find an output we know how to spend. */
	connect->input->w = NULL;
	for (output = 0; output < tx->output_count; output++) {
		connect->input->w
			= wallet_can_spend(cmd->dstate, &tx->output[output]);
		if (connect->input->w)
			break;
	}
	if (!connect->input->w) {
		command_fail(cmd, "Tx doesn't send to wallet address");
		return;
	}

	connect->input->index = output;
	connect->input->amount = tx->output[output].amount;
	if (!dns_resolve_and_connect(cmd->dstate, connect->name, connect->port,
				     peer_connected_out, peer_failed, connect)) {
		command_fail(cmd, "DNS failed");
		return;
	}
}

const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to a {host} at {port} offering anchor of {satoshis}",
	"Returns an empty result on success"
};

/* Have any of our HTLCs passed their deadline? */
static bool any_deadline_past(struct peer *peer)
{
	u32 height = get_block_height(peer->dstate);
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (htlc_is_dead(h))
			continue;
		if (htlc_owner(h) != LOCAL)
			continue;
		if (height >= h->deadline) {
			log_unusual_struct(peer->log,
					   "HTLC %s deadline has passed",
					   struct htlc, h);
			return true;
		}
	}
	return false;
}			      

static void check_htlc_expiry(struct peer *peer)
{
	u32 height = get_block_height(peer->dstate);
	struct htlc_map_iter it;
	struct htlc *h;

	/* Check their currently still-existing htlcs for expiry */
	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		assert(!abs_locktime_is_seconds(&h->expiry));

		/* Only their consider HTLCs which are completely locked in. */
		if (h->state != RCVD_ADD_ACK_REVOCATION)
			continue;

		/* We give it an extra block, to avoid the worst of the
		 * inter-node timing issues. */
		if (height <= abs_locktime_to_blocks(&h->expiry))
			continue;

		/* This can fail only if we're in an error state. */
		if (!command_htlc_fail(peer, h))
			return;
	}

	/* BOLT #2:
	 *
	 * A node MUST NOT offer a HTLC after this deadline, and MUST
	 * fail the connection if an HTLC which it offered is in
	 * either node's current commitment transaction past this
	 * deadline.
	 */

	/* To save logic elsewhere (ie. to avoid signing a new commit with a
	 * past-deadline HTLC) we also check staged HTLCs.
	 */
	if (!state_is_normal(peer->state))
		return;

	if (any_deadline_past(peer)) {
		set_peer_state(peer, STATE_ERR_BREAKDOWN, __func__);
		peer_breakdown(peer);
	}
}

static enum watch_result anchor_depthchange(struct peer *peer,
					    unsigned int depth,
					    const struct sha256_double *txid,
					    void *unused)
{
	/* Still waiting for it to reach depth? */
	if (state_is_opening(peer->state)) {
		if ((int)depth >= peer->anchor.ok_depth) {
			state_event(peer, BITCOIN_ANCHOR_DEPTHOK, NULL);
			peer->anchor.ok_depth = -1;
		}
	} else if (depth == 0)
		/* FIXME: Report losses! */
		fatal("Funding transaction was unspent!");

	/* Since this gets called on every new block, check HTLCs here. */
	check_htlc_expiry(peer);
	return KEEP_WATCHING;
}

static bool outputscript_eq(const struct bitcoin_tx_output *out,
			    size_t i, const u8 *script)
{
	if (out[i].script_length != tal_count(script))
		return false;
	return memcmp(out[i].script, script, out[i].script_length) == 0;
}

/* This tx is their commitment;
 * fill in onchain.htlcs[], wscripts[], to_us_idx and to_them_idx */
static bool map_onchain_outputs(struct peer *peer,
				const struct sha256 *rhash,
				const struct bitcoin_tx *tx,
				enum htlc_side side,
				unsigned int commit_num)
{
	u8 *to_us, *to_them, *to_them_wscript, *to_us_wscript;
	struct htlc_output_map *hmap;
	size_t i;

	peer->onchain.to_us_idx = peer->onchain.to_them_idx = -1;
	peer->onchain.htlcs = tal_arr(tx, struct htlc *, tx->output_count);
	peer->onchain.wscripts = tal_arr(tx, const u8 *, tx->output_count);

	to_us = commit_output_to_us(tx, peer, rhash, side, &to_us_wscript);
	to_them = commit_output_to_them(tx, peer, rhash, side,
					&to_them_wscript);

	/* Now generate the wscript hashes for every possible HTLC. */
	hmap = get_htlc_output_map(tx, peer, rhash, side, commit_num);

	for (i = 0; i < tx->output_count; i++) {
		log_debug(peer->log, "%s: output %zi", __func__, i);
		if (peer->onchain.to_us_idx == -1
		    && outputscript_eq(tx->output, i, to_us)) {
			log_add(peer->log, " -> to us");
			peer->onchain.htlcs[i] = NULL;
			peer->onchain.wscripts[i] = to_us_wscript;
			peer->onchain.to_us_idx = i;
			continue;
		}
		if (peer->onchain.to_them_idx == -1
		    && outputscript_eq(tx->output, i, to_them)) {
			log_add(peer->log, " -> to them");
			peer->onchain.htlcs[i] = NULL;
			peer->onchain.wscripts[i] = to_them_wscript;
			peer->onchain.to_them_idx = i;
			continue;
		}
		/* Must be an HTLC output */
		peer->onchain.htlcs[i] = txout_get_htlc(hmap,
					  tx->output[i].script,
					  tx->output[i].script_length,
					  peer->onchain.wscripts+i);
		if (!peer->onchain.htlcs[i]) {
			log_add(peer->log, "no HTLC found");
			goto fail;
		}
		tal_steal(peer->onchain.htlcs, peer->onchain.htlcs[i]);
		tal_steal(peer->onchain.wscripts, peer->onchain.wscripts[i]);
		log_add(peer->log, "HTLC %"PRIu64, peer->onchain.htlcs[i]->id);
	}
	tal_free(hmap);
	return true;

fail:
	tal_free(hmap);
	return false;
}

static bool is_mutual_close(const struct peer *peer,
			    const struct bitcoin_tx *tx)
{
	const u8 *ours, *theirs;

	ours = peer->closing.our_script;
	theirs = peer->closing.their_script;
	/* If we don't know the closing scripts, can't have signed them. */
	if (!ours || !theirs)
		return false;

	if (tx->output_count != 2)
		return false;

	/* Without knowing fee amounts, can't determine order.  Check both. */
	if (scripteq(tx->output[0].script, tx->output[0].script_length,
		     ours, tal_count(ours))
	    && scripteq(tx->output[1].script, tx->output[1].script_length,
			theirs, tal_count(theirs)))
		return true;

	if (scripteq(tx->output[0].script, tx->output[0].script_length,
		     theirs, tal_count(theirs))
	    && scripteq(tx->output[1].script, tx->output[1].script_length,
			ours, tal_count(ours)))
		return true;

	return false;
}

/* Create a HTLC refund collection for onchain.tx output out_num. */
static const struct bitcoin_tx *htlc_timeout_tx(const struct peer *peer,
						unsigned int out_num)
{
	const struct htlc *htlc = peer->onchain.htlcs[out_num];
	const u8 *wscript = peer->onchain.wscripts[out_num];
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	struct bitcoin_signature sig;
	u64 fee, satoshis;

	/* We must set locktime so HTLC expiry can OP_CHECKLOCKTIMEVERIFY */
	tx->lock_time = htlc->expiry.locktime;
	tx->input[0].index = out_num;
	tx->input[0].txid = peer->onchain.txid;
	satoshis = htlc->msatoshis / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's our HTLC, and that we collected it via timeout. */
	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
						       peer->dstate->secpctx,
						       &peer->local.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	log_unusual(peer->log, "Pre-witness txlen = %zu\n",
		    measure_tx_cost(tx) / 4);

	assert(measure_tx_cost(tx) == 83 * 4);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 539 from an example run. */
	fee = fee_by_feerate(83 + 539 / 4, get_feerate(peer->dstate));

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > satoshis || is_dust(satoshis - fee))
		fatal("HTLC refund amount of %"PRIu64" won't cover fee %"PRIu64,
		      satoshis, fee);

	tx->output[0].amount = satoshis - fee;

	sig.stype = SIGHASH_ALL;
	peer_sign_htlc_refund(peer, tx, wscript, &sig.sig);

	tx->input[0].witness = bitcoin_witness_htlc(tx, peer->dstate->secpctx,
						    NULL, &sig, wscript);

	log_unusual(peer->log, "tx cost for htlc timeout tx: %zu",
		    measure_tx_cost(tx));

	return tx;
}

static void reset_onchain_closing(struct peer *peer)
{
	if (peer->onchain.tx) {
		/* FIXME: Log old txid */
		log_unusual(peer->log, "New anchor spend, forgetting old");
		peer->onchain.tx = tal_free(peer->onchain.tx);
		peer->onchain.resolved = NULL;
		peer->onchain.htlcs = NULL;
		peer->onchain.wscripts = NULL;
	}
}

static const struct bitcoin_tx *irrevocably_resolved(struct peer *peer)
{
	/* We can't all be irrevocably resolved until the commit tx is,
	 * so just mark that as resolving us. */
	return peer->onchain.tx;
}

/* We've spent an HTLC output to get our funds back.  There's still a 
 * chance that they could also spend the HTLC output (using the preimage),
 * so we need to wait for some confirms.
 *
 * However, we don't want to wait too long: our upstream will get upset if
 * their HTLC has timed out and we don't close it.  So we wait one less
 * than the HTLC timeout difference.
 */
static enum watch_result our_htlc_timeout_depth(struct peer *peer,
						unsigned int depth,
						const struct sha256_double *txid,
						struct htlc *htlc)
{
	if (depth == 0)
		return KEEP_WATCHING;
	if (depth + 1 < peer->dstate->config.min_htlc_expiry)
		return KEEP_WATCHING;
	our_htlc_failed(peer, htlc);
	return DELETE_WATCH;
}

static enum watch_result our_htlc_depth(struct peer *peer,
					unsigned int depth,
					const struct sha256_double *txid,
					enum htlc_side whose_commit,
					unsigned int out_num)
{
	struct htlc *h = peer->onchain.htlcs[out_num];
	u32 height;

	/* Must be in a block. */
	if (depth == 0)
		return KEEP_WATCHING;

	height = get_block_height(peer->dstate);

	/* BOLT #onchain:
	 *
	 * If the *commitment tx* is the other node's, the output is
	 * considered *timed out* once the HTLC is expired.  If the
	 * *commitment tx* is this node's, the output is considered *timed
	 * out* once the HTLC is expired, AND the output's
	 * `OP_CHECKSEQUENCEVERIFY` delay has passed.
	 */
	if (height < abs_locktime_to_blocks(&h->expiry))
		return KEEP_WATCHING;

	if (whose_commit == LOCAL) {
		if (depth < rel_locktime_to_blocks(&peer->remote.locktime))
			return KEEP_WATCHING;
	}

	/* BOLT #onchain:
	 *
	 * If the output has *timed out* and not been *resolved*, the node
	 * MUST *resolve* the output by spending it.
	 */
	/* FIXME: we should simply delete this watch if HTLC is fulfilled. */
	if (!peer->onchain.resolved[out_num]) {
		peer->onchain.resolved[out_num]	= htlc_timeout_tx(peer, out_num);
		watch_tx(peer->onchain.resolved[out_num],
			 peer,
			 peer->onchain.resolved[out_num],
			 our_htlc_timeout_depth, h);
		broadcast_tx(peer, peer->onchain.resolved[out_num]);
	}
	return DELETE_WATCH;
}

static enum watch_result our_htlc_depth_theircommit(struct peer *peer,
						    unsigned int depth,
						    const struct sha256_double *txid,
						    ptrint_t *out_num)
{
	return our_htlc_depth(peer, depth, txid, REMOTE, ptr2int(out_num));
}

static enum watch_result our_htlc_depth_ourcommit(struct peer *peer,
						  unsigned int depth,
						  const struct sha256_double *txid,
						  ptrint_t *out_num)
{
	return our_htlc_depth(peer, depth, txid, LOCAL, ptr2int(out_num));
}

static enum watch_result their_htlc_depth(struct peer *peer,
					  unsigned int depth,
					  const struct sha256_double *txid,
					  ptrint_t *out_num)
{
	u32 height;
	const struct htlc *htlc = peer->onchain.htlcs[ptr2int(out_num)];

	/* Must be in a block. */
	if (depth == 0)
		return KEEP_WATCHING;

	height = get_block_height(peer->dstate);

	/* BOLT #onchain:
	 *
	 * Otherwise, if the output HTLC has expired, it is considered
	 * *irrevocably resolved*.
	 */
	if (height < abs_locktime_to_blocks(&htlc->expiry))
		return KEEP_WATCHING;

	peer->onchain.resolved[ptr2int(out_num)] = irrevocably_resolved(peer);
	return DELETE_WATCH;
}

static enum watch_result our_main_output_depth(struct peer *peer,
					       unsigned int depth,
					       const struct sha256_double *txid,
					       void *unused)
{
	/* Not past CSV timeout? */
	if (depth < rel_locktime_to_blocks(&peer->remote.locktime))
		return KEEP_WATCHING;

	assert(peer->onchain.to_us_idx != -1);

	/* BOLT #onchain:
	 *
	 * 1. _A's main output_: A node SHOULD spend this output to a
	 *    convenient address.  This avoids having to remember the
	 *    complicated witness script associated with that particular
	 *    channel for later spending. ... If the output is spent (as
	 *    recommended), the output is *resolved* by the spending
	 *    transaction
	 */
	peer->onchain.resolved[peer->onchain.to_us_idx]
		= bitcoin_spend_ours(peer);
	broadcast_tx(peer, peer->onchain.resolved[peer->onchain.to_us_idx]);
	return DELETE_WATCH;
}

/* Any of our HTLCs we didn't have in our commitment tx, but they did,
 * we can't fail until we're sure our commitment tx will win. */
static enum watch_result our_unilateral_depth(struct peer *peer,
					      unsigned int depth,
					      const struct sha256_double *txid,
					      void *unused)
{
	struct htlc_map_iter it;
	struct htlc *h;

	if (depth < peer->dstate->config.min_htlc_expiry)
		return KEEP_WATCHING;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (htlc_owner(h) == LOCAL
		    && !htlc_has(h, HTLC_LOCAL_F_COMMITTED)
		    && htlc_has(h, HTLC_REMOTE_F_COMMITTED)) {
			log_debug(peer->log,
				  "%s:failing uncommitted htlc %"PRIu64,
				  __func__, h->id);
			our_htlc_failed(peer, h);
		}
	}
	return DELETE_WATCH;
}

static enum watch_result our_htlc_spent(struct peer *peer,
					const struct bitcoin_tx *tx,
					size_t input_num,
					struct htlc *h)
{
	struct sha256 sha;
	struct rval preimage;

	/* BOLT #onchain:
	 *
	 * If a node sees a redemption transaction...the node MUST extract the
	 * preimage from the transaction input witness.  This is either to
	 * prove payment (if this node originated the payment), or to redeem
	 * the corresponding incoming HTLC from another peer.
	 */

	/* This is the form of all HTLC spends. */
	if (!tx->input[input_num].witness
	    || tal_count(tx->input[input_num].witness) != 3
	    || tal_count(tx->input[input_num].witness[1]) != sizeof(preimage))
		fatal("Impossible HTLC spend for %"PRIu64, h->id);
	
	/* Our timeout tx has all-zeroes, so we can distinguish it. */
	if (memeqzero(tx->input[input_num].witness[1], sizeof(preimage)))
		/* They might try to race us. */
		return KEEP_WATCHING;

	memcpy(&preimage, tx->input[input_num].witness[1], sizeof(preimage));
	sha256(&sha, &preimage, sizeof(preimage));

	/* FIXME: This could happen with a ripemd collision, since
	 * script.c only checks that ripemd matches... */
	if (!structeq(&sha, &h->rhash))
		fatal("HTLC redeemed with incorrect r value?");

	log_unusual(peer->log, "Peer redeemed HTLC %"PRIu64" on-chain",
		    h->id);
	log_add_struct(peer->log, " using rvalue %s", struct rval, &preimage);

	our_htlc_fulfilled(peer, h, &preimage);

	/* BOLT #onchain:
	 *
	 * If a node sees a redemption transaction, the output is considered
	 * *irrevocably resolved*... Note that we don't care about the fate of
	 * the redemption transaction itself once we've extracted the
	 * preimage; the knowledge is not revocable.
	 */
	peer->onchain.resolved[tx->input[input_num].index]
		= irrevocably_resolved(peer);
	return DELETE_WATCH;
}

static void resolve_our_htlc(struct peer *peer,
			     unsigned int out_num,
			     enum watch_result (*cb)(struct peer *peer,
						     unsigned int depth,
						     const struct sha256_double*,
						     ptrint_t *out_num))
{
	/* BOLT #onchain:
	 *
	 * A node MUST watch for spends of *commitment tx* outputs for HTLCs
	 * it offered; each one must be *resolved* by a timeout transaction
	 * (the node pays back to itself) or redemption transaction (the other
	 * node provides the redemption preimage).
	 */
	watch_txo(peer->onchain.tx, peer, &peer->onchain.txid, out_num,
		  our_htlc_spent, peer->onchain.htlcs[out_num]);
	watch_txid(peer->onchain.tx, peer,
		   &peer->onchain.txid, cb, int2ptr(out_num));
}

static void resolve_their_htlc(struct peer *peer, unsigned int out_num)
{
	/* BOLT #onchain:
	 *
	 * If the node ... already knows... a redemption preimage for an
	 * unresolved *commitment tx* output it was offered, it MUST *resolve*
	 * the output by spending it using the preimage.
	 */
	if (peer->onchain.htlcs[out_num]->r) {
		peer->onchain.resolved[out_num]	= htlc_fulfill_tx(peer, out_num);
		broadcast_tx(peer, peer->onchain.resolved[out_num]);
	} else {
		/* BOLT #onchain:
		 *
		 * Otherwise, if the output HTLC has expired, it is considered
		 * *irrevocably resolved*.
		 */
		watch_tx(peer->onchain.tx, peer, peer->onchain.tx,
			 their_htlc_depth, int2ptr(out_num));
	}	
}

/* BOLT #onchain:
 *
 * When node A sees its own *commitment tx*:
 */
static void resolve_our_unilateral(struct peer *peer)
{
	unsigned int i;
	const struct bitcoin_tx *tx = peer->onchain.tx;

	/* This only works because we always watch for a long time before
	 * freeing peer, by which time this has resolved.  We could create
	 * resolved[] entries for these uncommitted HTLCs, too. */
	watch_tx(tx, peer, tx, our_unilateral_depth, NULL);

	for (i = 0; i < tx->output_count; i++) {
		/* BOLT #onchain:
		 *
		 * 1. _A's main output_: A node SHOULD spend this output to a
		 *    convenient address. ... A node MUST wait until the
		 *    `OP_CHECKSEQUENCEVERIFY` delay has passed (as specified
		 *    by the other node's `open_channel` `delay` field) before
		 *    spending the output.
		 */
		if (i == peer->onchain.to_us_idx)
			watch_tx(tx, peer, tx, our_main_output_depth, NULL);

		/* BOLT #onchain:
		 *
		 * 2. _B's main output_: No action required, this output is
		 *    considered *resolved* by the *commitment tx*.
		 */
		else if (i == peer->onchain.to_them_idx)
			peer->onchain.resolved[i] = tx;

		/* BOLT #onchain:
		 *
		 * 3. _A's offered HTLCs_: See On-chain HTLC Handling: Our
		 *    Offers below.
		 */
		else if (htlc_owner(peer->onchain.htlcs[i]) == LOCAL)
			resolve_our_htlc(peer, i, our_htlc_depth_ourcommit);

		/* BOLT #onchain:
		 *
		 * 4. _B's offered HTLCs_: See On-chain HTLC Handling: Their
		 *    Offers below.
		 */
		else
			resolve_their_htlc(peer, i);
	}
}

/* BOLT #onchain:
 *
 * Similarly, when node A sees a *commitment tx* from B:
 */
static void resolve_their_unilateral(struct peer *peer)
{
	unsigned int i;
	const struct bitcoin_tx *tx = peer->onchain.tx;

	for (i = 0; i < tx->output_count; i++) {
		/* BOLT #onchain:
		 *
		 * 1. _A's main output_: No action is required; this is a
		 *    simple P2WPKH output.  This output is considered
		 *    *resolved* by the *commitment tx*.
		 */
		if (i == peer->onchain.to_us_idx)
			peer->onchain.resolved[i] = tx;
		/* BOLT #onchain:
		 *
		 * 2. _B's main output_: No action required, this output is
		 *    considered *resolved* by the *commitment tx*.
		 */
		else if (i == peer->onchain.to_them_idx)
			peer->onchain.resolved[i] = tx;
		/* BOLT #onchain:
		 *
		 * 3. _A's offered HTLCs_: See On-chain HTLC Handling: Our
		 * Offers below.
		 */
		else if (htlc_owner(peer->onchain.htlcs[i]) == LOCAL)
			resolve_our_htlc(peer, i, our_htlc_depth_theircommit);
		/*
		 * 4. _B's offered HTLCs_: See On-chain HTLC Handling: Their
		 * Offers below.
		 */
		else
			resolve_their_htlc(peer, i);
	}
}

static void resolve_mutual_close(struct peer *peer)
{
	unsigned int i;

	/* BOLT #onchain:
	 *
	 * A node doesn't need to do anything else as it has already agreed to
	 * the output, which is sent to its specified scriptpubkey (see BOLT
	 * #2 "4.1: Closing initiation: close_shutdown").
	 */
	for (i = 0; i < peer->onchain.tx->output_count; i++)
		peer->onchain.resolved[i] = irrevocably_resolved(peer);

	/* No HTLCs. */
	peer->onchain.htlcs = tal_arrz(peer->onchain.tx,
				       struct htlc *,
				       peer->onchain.tx->output_count);
}

/* Called every time the tx spending the funding tx changes depth. */
static enum watch_result check_for_resolution(struct peer *peer,
					      unsigned int depth,
					      const struct sha256_double *txid,
					      void *unused)
{
	size_t i, n = tal_count(peer->onchain.resolved);
	size_t forever = peer->dstate->config.forever_confirms;
		
	/* BOLT #onchain:
	 *
	 * A node MUST *resolve* all outputs as specified below, and MUST be
	 * prepared to resolve them multiple times in case of blockchain
	 * reorganizations.
	 */
	for (i = 0; i < n; i++)
		if (!peer->onchain.resolved[i])
			return KEEP_WATCHING;

	/* BOLT #onchain:
	 *
	 * Outputs which are *resolved* by a transaction are considered
	 * *irrevocably resolved* once they are included in a block at least
	 * 100 deep on the most-work blockchain.
	 */
	if (depth < forever)
		return KEEP_WATCHING;

	for (i = 0; i < n; i++) {
		struct sha256_double txid;

		bitcoin_txid(peer->onchain.resolved[i], &txid);
		if (get_tx_depth(peer->dstate, &txid) < forever)
			return KEEP_WATCHING;
	}

	/* BOLT #onchain:
	 *
	 * A node MUST monitor the blockchain for transactions which spend any
	 * output which is not *irrevocably resolved* until all outputs are
	 * *irrevocably resolved*.
	 */
	set_peer_state(peer, STATE_CLOSED, "check_for_resolution");

	/* It's theoretically possible that peer is still writing output */
	if (!peer->conn)
		io_break(peer);
	else
		io_wake(peer);

	return DELETE_WATCH;
}

static bool find_their_old_tx(struct peer *peer, 
			      const struct sha256_double *txid,
			      u64 *idx)
{
	/* FIXME: Don't keep these in memory, search db here. */
	struct their_commit *tc;

	log_debug_struct(peer->log, "Finding txid %s", struct sha256_double,
			 txid);
	list_for_each(&peer->their_commits, tc, list) {
		if (structeq(&tc->txid, txid)) {
			*idx = tc->commit_num;
			return true;
		}
	}
	return false;
}

static void resolve_their_steal(struct peer *peer,
				const struct sha256 *revocation_preimage)
{
	int i, n;
	const struct bitcoin_tx *tx = peer->onchain.tx;
	struct bitcoin_tx *steal_tx;
	size_t wsize = 0;
	u64 input_total = 0, fee;

	/* Create steal_tx: don't need to steal to_us output */
	if (peer->onchain.to_us_idx == -1)
		steal_tx = bitcoin_tx(tx, tx->output_count, 1);
	else
		steal_tx = bitcoin_tx(tx, tx->output_count - 1, 1);
	n = 0;

	log_debug(peer->log, "Analyzing tx to steal:");
	for (i = 0; i < tx->output_count; i++) {
		/* BOLT #onchain:
		 * 1. _A's main output_: No action is required; this is a
		 *    simple P2WPKH output.  This output is considered
		 *    *resolved* by the *commitment tx*.
		 */
		if (i == peer->onchain.to_us_idx) {
			log_debug(peer->log, "%i is to-us, ignoring", i);
			peer->onchain.resolved[i] = tx;
			continue;
		}

		/* BOLT #onchain:
		 *
		 * 2. _B's main output_: The node MUST *resolve* this by
		 * spending using the revocation preimage.
		 *
		 * 3. _A's offered HTLCs_: The node MUST *resolve* this by
		 * spending using the revocation preimage.
		 *
		 * 4. _B's offered HTLCs_: The node MUST *resolve* this by
		 * spending using the revocation preimage.
		 */
		peer->onchain.resolved[i] = steal_tx;

		/* Connect it up. */
		steal_tx->input[n].txid = peer->onchain.txid;
		steal_tx->input[n].index = i;
		steal_tx->input[n].amount = tal_dup(steal_tx, u64,
						    &tx->output[i].amount);
		/* Track witness size, for fee. */
		wsize += tal_count(peer->onchain.wscripts[n]);
		input_total += tx->output[i].amount;
		n++;
	}
	assert(n == steal_tx->input_count);

	fee = get_feerate(peer->dstate)
		* (measure_tx_cost(steal_tx) + wsize) / 1000;

	if (fee > input_total || is_dust(input_total - fee)) {
		log_unusual(peer->log, "Not worth stealing tiny amount %"PRIu64,
			    input_total);
		/* Consider them all resolved by steal tx. */
		for (i = 0; i < tal_count(peer->onchain.resolved); i++)
			peer->onchain.resolved[i] = tx;
		tal_free(steal_tx);
		return;
	}
	steal_tx->output[0].amount = input_total - fee;
	steal_tx->output[0].script = scriptpubkey_p2sh(steal_tx,
				 bitcoin_redeem_single(steal_tx,
						       peer->dstate->secpctx,
						       &peer->local.finalkey));
	steal_tx->output[0].script_length = tal_count(steal_tx->output[0].script);

	/* Now, we can sign them all (they're all of same form). */
	for (i = 0; i < n; i++) {
		struct bitcoin_signature sig;

		sig.stype = SIGHASH_ALL;
		peer_sign_steal_input(peer, steal_tx, i,
				      peer->onchain.wscripts[i],
				      &sig.sig);

		steal_tx->input[i].witness
			= bitcoin_witness_secret(steal_tx,
						 peer->dstate->secpctx,
						 revocation_preimage,
						 sizeof(*revocation_preimage),
						 &sig,
						 peer->onchain.wscripts[i]);
	}

	broadcast_tx(peer, steal_tx);
}

static struct sha256 *get_rhash(struct peer *peer, u64 commit_num,
				struct sha256 *rhash)
{
	struct sha256 preimage;

	/* Previous revoked tx? */
	if (shachain_get_hash(&peer->their_preimages,
			      0xFFFFFFFFFFFFFFFFL - commit_num,
			      &preimage)) {
		sha256(rhash, &preimage, sizeof(preimage));
		return tal_dup(peer, struct sha256, &preimage);
	}

	/* Current tx? */
	if (commit_num == peer->remote.commit->commit_num) {
		*rhash = peer->remote.commit->revocation_hash;
		return NULL;
	}

	/* Last tx, but we haven't got revoke for it yet? */
	assert(commit_num == peer->remote.commit->commit_num-1);
	*rhash = *peer->their_prev_revocation_hash;
	return NULL;
}
	
/* We assume the tx is valid!  Don't do a blockchain.info and feed this
 * invalid transactions! */
static enum watch_result anchor_spent(struct peer *peer,
				      const struct bitcoin_tx *tx,
				      size_t input_num,
				      void *unused)
{
	Pkt *err;
	enum state newstate;
	struct htlc_map_iter it;
	struct htlc *h;
	u64 commit_num;

	assert(input_num < tx->input_count);

	/* We only ever sign single-input txs. */
	if (input_num != 0) {
		log_broken(peer->log, "Anchor spend by non-single input tx");
		goto unknown_spend;
	}

	/* We may have been following a different spend.  Forget it. */
	reset_onchain_closing(peer);

	peer->onchain.tx = tal_steal(peer, tx);
	bitcoin_txid(tx, &peer->onchain.txid);

	/* If we have any HTLCs we're not committed to yet, fail them now. */
	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (h->state == SENT_ADD_HTLC) {
			our_htlc_failed(peer, h);
		}
	}

	/* We need to resolve every output. */
	peer->onchain.resolved
		= tal_arrz(tx, const struct bitcoin_tx *, tx->output_count);

	/* A mutual close tx. */
	if (is_mutual_close(peer, tx)) {
		newstate = STATE_CLOSE_ONCHAIN_MUTUAL;
		err = NULL;
		resolve_mutual_close(peer);
	/* Our unilateral */
	} else if (structeq(&peer->local.commit->txid,
			    &peer->onchain.txid)) {
		newstate = STATE_CLOSE_ONCHAIN_OUR_UNILATERAL;
		/* We're almost certainly closed to them by now. */
		err = pkt_err(peer, "Our own unilateral close tx seen");
		if (!map_onchain_outputs(peer,
					 &peer->local.commit->revocation_hash,
					 tx, LOCAL,
					 peer->local.commit->commit_num)) {
			log_broken(peer->log,
				   "Can't resolve own anchor spend %"PRIu64"!",
				   commit_num);
			goto unknown_spend;
		}
		resolve_our_unilateral(peer);
	/* Must be their unilateral */
	} else if (find_their_old_tx(peer, &peer->onchain.txid,
				     &commit_num)) {
		struct sha256 *preimage, rhash;

		preimage = get_rhash(peer, commit_num, &rhash);
		if (!map_onchain_outputs(peer, &rhash, tx, REMOTE, commit_num)) {
			/* Should not happen */
			log_broken(peer->log,
				   "Can't resolve known anchor spend %"PRIu64"!",
				   commit_num);
			goto unknown_spend;
		}
		if (preimage) {
			newstate = STATE_CLOSE_ONCHAIN_CHEATED;
			err = pkt_err(peer, "Revoked transaction seen");
			resolve_their_steal(peer, preimage);
		} else {
			newstate = STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL;
			err = pkt_err(peer, "Unilateral close tx seen");
			resolve_their_unilateral(peer);
		}
	} else {
		/* FIXME: Log harder! */
		log_broken(peer->log,
			   "Unknown anchor spend!  Funds may be lost!");
		goto unknown_spend;
	}

	/* BOLT #onchain:
	 *
	 * A node MAY send a descriptive error packet in this case.
	 */
	if (err && state_can_io(peer->state))
		queue_pkt_err(peer, err);

	set_peer_state(peer, newstate, "anchor_spent");

	/* If we've just closed connection, make output close it. */
	io_wake(peer);
	
	/* BOLT #onchain:
	 *
	 * A node SHOULD fail the connection if it is not already
	 * closed when it sees the funding transaction spent.
	 */
	assert(!state_can_io(peer->state));

	assert(peer->onchain.resolved != NULL);
	watch_tx(tx, peer, tx, check_for_resolution, NULL);

	return KEEP_WATCHING;

unknown_spend:
	/* BOLT #onchain:
	 *
	 * A node SHOULD report an error to the operator if it
	 * sees a transaction spend the funding transaction
	 * output which does not fall into one of these
	 * categories (mutual close, unilateral close, or
	 * cheating attempt).  Such a transaction implies its
	 * private key has leaked, and funds may be lost.
	 */
	set_peer_state(peer, STATE_ERR_INFORMATION_LEAK, "anchor_spent");
	return DELETE_WATCH;
}

static void anchor_timeout(struct peer *peer)
{
	/* FIXME: We could just forget timeout once we're not opening. */
	if (state_is_opening(peer->state))
		state_event(peer, BITCOIN_ANCHOR_TIMEOUT, NULL);
}

void peer_watch_anchor(struct peer *peer,
		       int depth,
		       enum state_input depthok,
		       enum state_input timeout)
{
	/* We assume this. */
	assert(depthok == BITCOIN_ANCHOR_DEPTHOK);
	assert(timeout == BITCOIN_ANCHOR_TIMEOUT || timeout == INPUT_NONE);

	peer->anchor.ok_depth = depth;
	watch_txid(peer, peer, &peer->anchor.txid, anchor_depthchange, NULL);
	watch_txo(peer, peer, &peer->anchor.txid, 0, anchor_spent, NULL);

	/* For anchor timeout, expect 20 minutes per block, +2 hours.
	 *
	 * Probability(no block in time N) = e^(-N/600).
	 * Thus for 1 block, P = e^(-(7200+1*1200)/600) = 0.83 in a million.
	 *
	 * Glenn Willen says, if we want to know how many 10-minute intervals for
	 * a 1 in a million chance of spurious failure for N blocks, put
	 * this into http://www.wolframalpha.com:
	 *
	 *   e^(-x) * sum x^i / fact(i), i=0 to N < 1/1000000
	 * 
	 * N=20: 51
	 * N=10: 35
	 * N=8:  31
	 * N=6:  28
	 * N=4:  24
	 * N=3:  22
	 * N=2:  20
	 *
	 * So, our formula of 12 + N*2 holds for N <= 20 at least.
	 */
	if (timeout != INPUT_NONE)
		new_reltimer(peer->dstate, peer,
			     time_from_sec(7200 + 20*peer->anchor.ok_depth),
			     anchor_timeout, peer);
}

struct bitcoin_tx *peer_create_close_tx(struct peer *peer, u64 fee)
{
	struct channel_state cstate;

	/* We don't need a deep copy here, just fee levels. */
	cstate = *peer->local.staging_cstate;
	if (!force_fee(&cstate, fee)) {
		log_unusual(peer->log,
			    "peer_create_close_tx: can't afford fee %"PRIu64,
			    fee);
		return NULL;
	}

	log_debug(peer->log,
		  "creating close-tx with fee %"PRIu64" amounts %u/%u to ",
		  fee,
		  cstate.side[OURS].pay_msat / 1000,
		  cstate.side[THEIRS].pay_msat / 1000);
	log_add_struct(peer->log, "%s", struct pubkey, &peer->local.finalkey);
	log_add_struct(peer->log, "/%s", struct pubkey, &peer->remote.finalkey);

 	return create_close_tx(peer->dstate->secpctx, peer,
			       peer->closing.our_script,
			       peer->closing.their_script,
			       &peer->anchor.txid,
			       peer->anchor.index,
			       peer->anchor.satoshis,
			       cstate.side[OURS].pay_msat / 1000,
			       cstate.side[THEIRS].pay_msat / 1000);
}

/* Creation the bitcoin anchor tx, spending output user provided. */
void bitcoin_create_anchor(struct peer *peer)
{
	u64 fee;
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	size_t i;

	/* We must be offering anchor for us to try creating it */
	assert(peer->local.offer_anchor);

	tx->output[0].script = scriptpubkey_p2wsh(tx, peer->anchor.witnessscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Add input script length.  FIXME: This is normal case, not exact. */
	fee = fee_by_feerate(measure_tx_cost(tx)/4 + 1+73 + 1+33 + 1,
			     get_feerate(peer->dstate));
	if (fee >= peer->anchor.input->amount)
		/* FIXME: Report an error here!
		 * We really should set this when they do command, but
		 * we need to modify state to allow immediate anchor
		 * creation: using estimate_fee is a convenient workaround. */
		fatal("Amount %"PRIu64" below fee %"PRIu64,
		      peer->anchor.input->amount, fee);

	tx->output[0].amount = peer->anchor.input->amount - fee;

	tx->input[0].txid = peer->anchor.input->txid;
	tx->input[0].index = peer->anchor.input->index;
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &peer->anchor.input->amount);

	wallet_add_signed_input(peer->dstate, peer->anchor.input->w, tx, 0);

	bitcoin_txid(tx, &peer->anchor.txid);
	peer->anchor.tx = tx;
	peer->anchor.index = 0;
	/* We'll need this later, when we're told to broadcast it. */
	peer->anchor.satoshis = tx->output[0].amount;

	/* To avoid malleation, all inputs must be segwit! */
	for (i = 0; i < tx->input_count; i++)
		assert(tx->input[i].witness);
}

/* We didn't end up broadcasting the anchor: we don't need to do anything
 * to "release" TXOs, since we have our own internal wallet now. */
void bitcoin_release_anchor(struct peer *peer, enum state_input done)
{
}

/* Get the bitcoin anchor tx. */
const struct bitcoin_tx *bitcoin_anchor(struct peer *peer)
{
	return peer->anchor.tx;
}

/* Sets up the initial cstate and commit tx for both nodes: false if
 * insufficient funds. */
bool setup_first_commit(struct peer *peer)
{
	assert(!peer->local.commit->tx);
	assert(!peer->remote.commit->tx);

	/* Revocation hashes already filled in, from pkt_open */
	peer->local.commit->cstate = initial_cstate(peer,
						     peer->anchor.satoshis,
						     peer->local.commit_fee_rate,
						     peer->local.offer_anchor
						     == CMD_OPEN_WITH_ANCHOR ?
						     OURS : THEIRS);
	if (!peer->local.commit->cstate)
		return false;

	peer->remote.commit->cstate = initial_cstate(peer,
						     peer->anchor.satoshis,
						     peer->remote.commit_fee_rate,
						     peer->local.offer_anchor
						     == CMD_OPEN_WITH_ANCHOR ?
						     OURS : THEIRS);
	if (!peer->remote.commit->cstate)
		return false;

	peer->local.commit->tx = create_commit_tx(peer->local.commit,
						  peer,
						  &peer->local.commit->revocation_hash,
						  peer->local.commit->cstate,
						  LOCAL);
	bitcoin_txid(peer->local.commit->tx, &peer->local.commit->txid);

	peer->remote.commit->tx = create_commit_tx(peer->remote.commit,
						   peer,
						   &peer->remote.commit->revocation_hash,
						   peer->remote.commit->cstate,
						   REMOTE);
	bitcoin_txid(peer->remote.commit->tx, &peer->remote.commit->txid);

	peer->local.staging_cstate = copy_cstate(peer, peer->local.commit->cstate);
	peer->remote.staging_cstate = copy_cstate(peer, peer->remote.commit->cstate);

	return true;
}

static void json_add_abstime(struct json_result *response,
			     const char *id,
			     const struct abs_locktime *t)
{
	json_object_start(response, id);
	if (abs_locktime_is_seconds(t))
		json_add_num(response, "second", abs_locktime_to_seconds(t));
	else
		json_add_num(response, "block", abs_locktime_to_blocks(t));
	json_object_end(response);
}

static void json_add_pubkey(struct json_result *response,
			    secp256k1_context *secpctx,
			    const char *id,
			    const struct pubkey *key)
{
	u8 der[PUBKEY_DER_LEN];

	pubkey_to_der(secpctx, der, key);
	json_add_hex(response, id, der, sizeof(der));
}

static void json_add_htlcs(struct json_result *response,
			   const char *id,
			   struct peer *peer,
			   enum htlc_side owner)
{
	struct htlc_map_iter it;
	struct htlc *h;
	const struct htlc_map *htlcs = &peer->htlcs;

	json_array_start(response, id);
	for (h = htlc_map_first(htlcs, &it); h; h = htlc_map_next(htlcs, &it)) {
		if (htlc_owner(h) != owner)
			continue;

		/* Ignore completed HTLCs. */
		if (htlc_is_dead(h))
			continue;

		json_object_start(response, NULL);
		json_add_u64(response, "msatoshis", h->msatoshis);
		json_add_abstime(response, "expiry", &h->expiry);
		json_add_hex(response, "rhash", &h->rhash, sizeof(h->rhash));
		json_add_string(response, "state", htlc_state_name(h->state));
		json_object_end(response);
	}
	json_array_end(response);
}

/* FIXME: add history command which shows all prior and current commit txs */

/* FIXME: Somehow we should show running DNS lookups! */
static void json_getpeers(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct peer *p;
	struct json_result *response = new_json_result(cmd);	

	json_object_start(response, NULL);
	json_array_start(response, "peers");
	list_for_each(&cmd->dstate->peers, p, list) {
		const struct channel_state *last;

		json_object_start(response, NULL);
		json_add_string(response, "name", log_prefix(p->log));
		json_add_string(response, "state", state_name(p->state));

		if (p->id)
			json_add_pubkey(response, cmd->dstate->secpctx,
					"peerid", p->id);

		json_add_bool(response, "connected", p->conn && !p->fake_close);

		/* FIXME: Report anchor. */

		if (!p->local.commit || !p->local.commit->cstate) {
			json_object_end(response);
			continue;
		}
		last = p->local.commit->cstate;

		json_add_num(response, "our_amount", last->side[OURS].pay_msat);
		json_add_num(response, "our_fee", last->side[OURS].fee_msat);
		json_add_num(response, "their_amount", last->side[THEIRS].pay_msat);
		json_add_num(response, "their_fee", last->side[THEIRS].fee_msat);
		json_add_htlcs(response, "our_htlcs", p, LOCAL);
		json_add_htlcs(response, "their_htlcs", p, REMOTE);
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

const struct json_command getpeers_command = {
	"getpeers",
	json_getpeers,
	"List the current peers",
	"Returns a 'peers' array"
};

/* To avoid freeing underneath ourselves, we free outside event loop. */
void cleanup_peers(struct lightningd_state *dstate)
{
	struct peer *peer, *next;

	list_for_each_safe(&dstate->peers, peer, next, list) {
		/* Deletes itself from list. */
		if (!peer->conn && peer->state == STATE_CLOSED)
			tal_free(peer);
	}
}

/* A zero-fee single route to this peer. */
static const u8 *dummy_single_route(const tal_t *ctx,
				    const struct peer *peer,
				    u64 msatoshis)
{
	struct node_connection **path = tal_arr(ctx, struct node_connection *, 0);
	return onion_create(ctx, peer->dstate->secpctx, path, msatoshis, 0);
}

static void json_newhtlc(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *msatoshistok, *expirytok, *rhashtok;
	unsigned int expiry;
	u64 msatoshis;
	struct sha256 rhash;
	struct json_result *response = new_json_result(cmd);
	struct htlc *htlc;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "msatoshis", &msatoshistok,
			     "expiry", &expirytok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need peerid, msatoshis, expiry and rhash");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!peer->remote.commit || !peer->remote.commit->cstate) {
		command_fail(cmd, "peer not fully established");
		return;
	}

	if (!json_tok_u64(buffer, msatoshistok, &msatoshis)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshistok->end - msatoshistok->start),
			     buffer + msatoshistok->start);
		return;
	}
	if (!json_tok_number(buffer, expirytok, &expiry)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(expirytok->end - expirytok->start),
			     buffer + expirytok->start);
		return;
	}

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&rhash, sizeof(rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 hash",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	htlc = command_htlc_add(peer, msatoshis, expiry, &rhash, NULL,
				dummy_single_route(cmd, peer, msatoshis));
	if (!htlc) {
		command_fail(cmd, "could not add htlc");
		return;
	}

	json_object_start(response, NULL);
	json_add_u64(response, "id", htlc->id);
	json_object_end(response);
	command_success(cmd, response);
}

/* FIXME: Use HTLC ids, not r values! */
const struct json_command newhtlc_command = {
	"newhtlc",
	json_newhtlc,
	"Offer {peerid} an HTLC worth {msatoshis} in {expiry} (block number) with {rhash}",
	"Returns { id: u64 } result on success"
};

static void json_fulfillhtlc(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *idtok, *rtok;
	u64 id;
	struct htlc *htlc;
	struct sha256 rhash;
	struct rval r;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "id", &idtok,
			     "r", &rtok,
			     NULL)) {
		command_fail(cmd, "Need peerid, id and r");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!peer->remote.commit || !peer->remote.commit->cstate) {
		command_fail(cmd, "peer not fully established");
		return;
	}

	if (!json_tok_u64(buffer, idtok, &id)) {
		command_fail(cmd, "'%.*s' is not a valid id",
			     (int)(idtok->end - idtok->start),
			     buffer + idtok->start);
		return;
	}

	if (!hex_decode(buffer + rtok->start,
			rtok->end - rtok->start,
			&r, sizeof(r))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 preimage",
			     (int)(rtok->end - rtok->start),
			     buffer + rtok->start);
		return;
	}

	htlc = htlc_get(&peer->htlcs, id, REMOTE);
	if (!htlc) {
		command_fail(cmd, "preimage htlc not found");
		return;
	}

	if (htlc->state != RCVD_ADD_ACK_REVOCATION) {
		command_fail(cmd, "htlc in state %s",
			     htlc_state_name(htlc->state));
		return;
	}

	sha256(&rhash, &r, sizeof(r));
	if (!structeq(&htlc->rhash, &rhash)) {
		command_fail(cmd, "preimage incorrect");
		return;
	}

	assert(!htlc->r);
	htlc->r = tal_dup(htlc, struct rval, &r);

	if (command_htlc_fulfill(peer, htlc))
		command_success(cmd, null_response(cmd));
	else
		command_fail(cmd,
			     "htlc_fulfill not possible in state %s",
			     state_name(peer->state));
}

const struct json_command fulfillhtlc_command = {
	"fulfillhtlc",
	json_fulfillhtlc,
	"Redeem htlc proposed by {peerid} of {id} using {r}",
	"Returns an empty result on success"
};

static void json_failhtlc(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *idtok;
	u64 id;
	struct htlc *htlc;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "id", &idtok,
			     NULL)) {
		command_fail(cmd, "Need peerid and id");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!peer->remote.commit || !peer->remote.commit->cstate) {
		command_fail(cmd, "peer not fully established");
		return;
	}

	if (!json_tok_u64(buffer, idtok, &id)) {
		command_fail(cmd, "'%.*s' is not a valid id",
			     (int)(idtok->end - idtok->start),
			     buffer + idtok->start);
		return;
	}

	htlc = htlc_get(&peer->htlcs, id, REMOTE);
	if (!htlc) {
		command_fail(cmd, "preimage htlc not found");
		return;
	}

	if (htlc->state != RCVD_ADD_ACK_REVOCATION) {
		command_fail(cmd, "htlc in state %s",
			     htlc_state_name(htlc->state));
		return;
	}

	if (command_htlc_fail(peer, htlc))
		command_success(cmd, null_response(cmd));
	else
		command_fail(cmd,
			     "htlc_fail not possible in state %s",
			     state_name(peer->state));
}

const struct json_command failhtlc_command = {
	"failhtlc",
	json_failhtlc,
	"Fail htlc proposed by {peerid} which has {id}",
	"Returns an empty result on success"
};

static void json_commit(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok;

	if (!json_get_params(buffer, params,
			    "peerid", &peeridtok,
			    NULL)) {
		command_fail(cmd, "Need peerid");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!peer->remote.commit || !peer->remote.commit->cstate) {
		command_fail(cmd, "peer not fully established");
		return;
	}

	if (!state_can_commit(peer->state)) {
		command_fail(cmd, "peer in state %s", state_name(peer->state));
		return;
	}

	do_commit(peer, cmd);
}
	
const struct json_command commit_command = {
	"commit",
	json_commit,
	"Commit all staged HTLC changes with {peerid}",
	"Returns an empty result on success"
};

static void json_close(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     NULL)) {
		command_fail(cmd, "Need peerid");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!state_is_normal(peer->state) && !state_is_opening(peer->state)) {
		command_fail(cmd, "Peer is already closing: state %s",
			     state_name(peer->state));
		return;
	}

	if (peer->state == STATE_NORMAL_COMMITTING)
		set_peer_state(peer, STATE_SHUTDOWN_COMMITTING, __func__);
	else
		set_peer_state(peer, STATE_SHUTDOWN, __func__);
	peer_start_shutdown(peer);
	command_success(cmd, null_response(cmd));
}
	
const struct json_command close_command = {
	"close",
	json_close,
	"Close the channel with peer {peerid}",
	"Returns an empty result on success"
};

static void json_disconnect(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     NULL)) {
		command_fail(cmd, "Need peerid");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!peer->conn) {
		command_fail(cmd, "Peer is already disconnected");
		return;
	}

	/* We don't actually close it, since for testing we want only
	 * one side to freak out.  We just ensure we ignore it. */
	log_debug(peer->log, "Pretending connection is closed");
	peer->fake_close = true;
	set_peer_state(peer, STATE_ERR_BREAKDOWN, "json_disconnect");
	peer_breakdown(peer);

	command_success(cmd, null_response(cmd));
}

static void json_signcommit(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok;
	u8 *linear;
	const struct bitcoin_tx *tx;
	struct json_result *response = new_json_result(cmd);

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     NULL)) {
		command_fail(cmd, "Need peerid");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!peer->local.commit->sig) {
		command_fail(cmd, "Peer has not given us a signature");
		return;
	}

	tx = bitcoin_commit(peer);
	linear = linearize_tx(cmd, tx);

	/* Clear witness for potential future uses. */
	tx->input[0].witness = tal_free(tx->input[0].witness);

	json_object_start(response, NULL);
	json_add_string(response, "tx",
			tal_hexstr(cmd, linear, tal_count(linear)));
	json_object_end(response);
	command_success(cmd, response);
}

static void json_output(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *enabletok;
	bool enable;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "enable", &enabletok,
			     NULL)) {
		command_fail(cmd, "Need peerid and enable");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (!peer->conn) {
		command_fail(cmd, "Peer is already disconnected");
		return;
	}

	if (!json_tok_bool(buffer, enabletok, &enable)) {
		command_fail(cmd, "enable must be true or false");
		return;
	}

	log_debug(peer->log, "dev-output: output %s",
		  enable ? "enabled" : "disabled");
	peer->output_enabled = enable;

	/* Flush any outstanding output */
	if (peer->output_enabled)
		io_wake(peer);
	
	command_success(cmd, null_response(cmd));
}
const struct json_command output_command = {
	"dev-output",
	json_output,
	"Enable/disable any messages to peer {peerid} depending on {enable}",
	"Returns an empty result on success"
};

const struct json_command disconnect_command = {
	"dev-disconnect",
	json_disconnect,
	"Force a disconned with peer {peerid}",
	"Returns an empty result on success"
};

const struct json_command signcommit_command = {
	"dev-signcommit",
	json_signcommit,
	"Sign and return the current commit with peer {peerid}",
	"Returns a hex string on success"
};
