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
#include "payment.h"
#include "peer.h"
#include "permute_tx.h"
#include "protobuf_convert.h"
#include "pseudorand.h"
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

#define FIXME_STUB(peer) do { log_broken((peer)->dstate->base_log, "%s:%u: Implement %s!", __FILE__, __LINE__, __func__); abort(); } while(0)

struct json_connecting {
	/* This owns us, so we're freed after command_fail or command_success */
	struct command *cmd;
	const char *name, *port;
	struct anchor_input *input;
};

struct peer *find_peer(struct lightningd_state *dstate, const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list) {
		if (peer->state != STATE_INIT && pubkey_eq(&peer->id, id))
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
	/* Not initialized yet? */
	if (!peer->remote.staging_cstate
	    || !peer->remote.commit
	    || !peer->remote.commit->cstate)
		return false;

	/* We could have proposed changes to their commit */
	return peer->remote.staging_cstate->changes
		!= peer->remote.commit->cstate->changes;
}

void peer_update_complete(struct peer *peer)
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
		n = get_node(dstate, &peer->id);
		if (!n)
			n = new_node(dstate, &peer->id);
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
	const struct commit_info *i;

	/* Before anchor exchange, we don't even have cstate. */
	if (!peer->local.commit || !peer->local.commit->cstate)
		return false;
	
	i = peer->local.commit;
	while (i && !i->revocation_preimage) {
		if (tal_count(i->cstate->side[OURS].htlcs))
			return true;
		if (tal_count(i->cstate->side[THEIRS].htlcs))
			return true;
		i = i->prev;
	}

	i = peer->remote.commit;
	while (i && !i->revocation_preimage) {
		if (tal_count(i->cstate->side[OURS].htlcs))
			return true;
		if (tal_count(i->cstate->side[THEIRS].htlcs))
			return true;
		i = i->prev;
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

/* Unexpected packet received: stop listening, start breakdown procedure. */
static bool peer_received_unexpected_pkt(struct peer *peer, const Pkt *pkt)
{
	peer_unexpected_pkt(peer, pkt);
	return peer_comms_err(peer, pkt_err_unexpected(peer, pkt));
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
	if (!proto_to_signature(c->sig, &theirsig.sig))
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

	/* FIXME: Dynamic fee! */
	return true;
}

/* This is the io loop while we're clearing. */
static bool clearing_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err = NULL;

	assert(peer->state == STATE_CLEARING
	       || peer->state == STATE_CLEARING_COMMITTING);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_REVOCATION:
		if (peer->state == STATE_CLEARING)
			err = pkt_err_unexpected(peer, pkt);
		else {
			err = accept_pkt_revocation(peer, pkt);
			if (!err) {
				set_peer_state(peer, STATE_CLEARING, __func__);
				peer_update_complete(peer);
			}
		}
		break;

	case PKT__PKT_UPDATE_ADD_HTLC:
		/* BOLT #2:
		 * 
		 * A node MUST NOT send a `update_add_htlc` after a
		 * `close_clearing` */
		if (peer->closing.their_script)
			err = pkt_err(peer, "Update during clearing");
		else
			err = accept_pkt_htlc_add(peer, pkt);
		break;
			
	case PKT__PKT_CLOSE_CLEARING:
		/* BOLT #2:
		 * 
		 * A node... MUST NOT send more than one `close_clearing`. */
		if (peer->closing.their_script)
			err = pkt_err_unexpected(peer, pkt);
		else
			err = accept_pkt_close_clearing(peer, pkt);
		break;
			
	case PKT__PKT_UPDATE_FULFILL_HTLC:
		err = accept_pkt_htlc_fulfill(peer, pkt);
		break;
	case PKT__PKT_UPDATE_FAIL_HTLC:
		err = accept_pkt_htlc_fail(peer, pkt);
		break;
	case PKT__PKT_UPDATE_COMMIT:
		err = accept_pkt_commit(peer, pkt);
		if (!err)
			queue_pkt_revocation(peer); 
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

static void peer_start_clearing(struct peer *peer)
{
	assert(peer->state == STATE_CLEARING
	       || peer->state == STATE_CLEARING_COMMITTING);

	/* If they started close, we might not have sent ours. */
	if (!peer->closing.our_script) {
		u8 *redeemscript = bitcoin_redeem_single(peer,
							 &peer->local.finalkey);

		peer->closing.our_script = scriptpubkey_p2sh(peer, redeemscript);
		tal_free(redeemscript);
		/* BOLT #2:
		 *
		 * A node SHOULD send a `close_clearing` (if it has
		 * not already) after receiving `close_clearing`.
		 */
		queue_pkt_close_clearing(peer);
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
		err = accept_pkt_htlc_add(peer, pkt);
		break;
		
	case PKT_UPDATE_FULFILL_HTLC:
		err = accept_pkt_htlc_fulfill(peer, pkt);
		break;

	case PKT_UPDATE_FAIL_HTLC:
		err = accept_pkt_htlc_fail(peer, pkt);
		break;

	case PKT_UPDATE_COMMIT:
		err = accept_pkt_commit(peer, pkt);
		if (!err)
			queue_pkt_revocation(peer);
		break;

	case PKT_CLOSE_CLEARING:
		err = accept_pkt_close_clearing(peer, pkt);
		if (err)
			break;
		if (peer->state == STATE_NORMAL)
			set_peer_state(peer, STATE_CLEARING, __func__);
		else {
			assert(peer->state == STATE_NORMAL_COMMITTING);
			set_peer_state(peer, STATE_CLEARING_COMMITTING,
				       __func__);
		}

		peer_start_clearing(peer);
		return true;

	case PKT_UPDATE_REVOCATION:
		if (peer->state == STATE_NORMAL_COMMITTING) {
			err = accept_pkt_revocation(peer, pkt);
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

/* FIXME: Reason! */
static bool command_htlc_fail(struct peer *peer, struct htlc *htlc)
{
	if (!state_can_remove_htlc(peer->state))
		return false;

	queue_pkt_htlc_fail(peer, htlc);
	return true;
}

static bool command_htlc_fulfill(struct peer *peer,
				 struct htlc *htlc,
				 const struct rval *r)
{
	if (!state_can_remove_htlc(peer->state))
		return false;

	queue_pkt_htlc_fulfill(peer, htlc, r);
	return true;
}

static bool command_htlc_add(struct peer *peer, u64 msatoshis,
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
		return false;
	}

	if (expiry < get_block_height(peer->dstate) + peer->dstate->config.min_htlc_expiry) {
		log_unusual(peer->log, "add_htlc: fail: expiry %u is too soon",
			    expiry);
		return false;
	}

	if (expiry > get_block_height(peer->dstate) + peer->dstate->config.max_htlc_expiry) {
		log_unusual(peer->log, "add_htlc: fail: expiry %u is too far",
			    expiry);
		return false;
	}

	/* FIXME: This is wrong: constraint on remote is sufficient. */
	/* BOLT #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 300 HTLCs in either commitment transaction.
	 */
	if (tal_count(peer->local.staging_cstate->side[OURS].htlcs) == 300
	    || tal_count(peer->remote.staging_cstate->side[OURS].htlcs) == 300) {
		log_unusual(peer->log, "add_htlc: fail: already at limit");
		return false;
	}

	if (!state_can_add_htlc(peer->state)) {
		log_unusual(peer->log, "add_htlc: fail: peer state %s",
			    state_name(peer->state));
		return false;
	}

	htlc = peer_new_htlc(peer, peer->htlc_id_counter,
			     msatoshis, rhash, expiry, route, tal_count(route),
			     src, OURS);

	/* FIXME: BOLT is not correct here: we should say IFF we cannot
	 * afford it in remote at its own current proposed fee-rate. */
	/* BOLT #2:
	 *
	 * A node MUST NOT offer `amount_msat` it cannot pay for in
	 * both commitment transactions at the current `fee_rate`
	 */
	cstate = copy_cstate(peer, peer->remote.staging_cstate);
	if (!cstate_add_htlc(cstate, htlc, OURS)) {
		log_unusual(peer->log, "add_htlc: fail: Cannot afford %"PRIu64
			    " milli-satoshis in their commit tx",
			    msatoshis);
		tal_free(htlc);
		return false;
	}
	tal_free(cstate);

	cstate = copy_cstate(peer, peer->local.staging_cstate);
	if (!cstate_add_htlc(cstate, htlc, OURS)) {
		log_unusual(peer->log, "add_htlc: fail: Cannot afford %"PRIu64
			    " milli-satoshis in our commit tx",
			    msatoshis);
		tal_free(htlc);
		return false;
	}
	tal_free(cstate);

	queue_pkt_htlc_add(peer, htlc);

	/* Make sure we never offer the same one twice. */
	peer->htlc_id_counter++;

	return true;
}

static struct io_plan *pkt_out(struct io_conn *conn, struct peer *peer)
{
	Pkt *out;
	size_t n = tal_count(peer->outpkt);

	if (n == 0) {
		/* We close the connection once we've sent everything. */
		if (!state_can_io(peer->state))
			return io_close(conn);
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
	else if (state_is_clearing(peer->state))
		keep_going = clearing_pkt_in(peer, peer->inpkt);
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
	queue_pkt_commit(peer);
	if (peer->state == STATE_CLEARING) {
		set_peer_state(peer, STATE_CLEARING_COMMITTING, __func__);
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

void remote_changes_pending(struct peer *peer)
{
	log_debug(peer->log, "remote_changes_pending: changes=%u",
		  peer->remote.staging_cstate->changes);
	if (!peer->commit_timer) {
		log_debug(peer->log, "remote_changes_pending: adding timer");
		peer->commit_timer = new_reltimer(peer->dstate, peer,
						  peer->dstate->config.commit_time,
						  try_commit, peer);
	} else
		log_debug(peer->log, "remote_changes_pending: timer already exists");
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
	peer->dstate = dstate;
	peer->addr.type = addr_type;
	peer->addr.protocol = addr_protocol;
	peer->io_data = NULL;
	peer->secrets = NULL;
	list_head_init(&peer->watches);
	peer->outpkt = tal_arr(peer, Pkt *, 0);
	peer->commit_jsoncmd = NULL;
	list_head_init(&peer->outgoing_txs);
	peer->close_watch_timeout = NULL;
	peer->anchor.watches = NULL;
	peer->cur_commit.watch = NULL;
	peer->closing.their_sig = NULL;
	peer->closing.our_script = NULL;
	peer->closing.their_script = NULL;
	peer->cleared = INPUT_NONE;
	peer->closing_onchain.tx = NULL;
	peer->closing_onchain.resolved = NULL;
	peer->closing_onchain.ci = NULL;
	peer->commit_timer = NULL;
	peer->nc = NULL;
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
	peer->local.commit_fee_rate = dstate->config.commitment_fee_rate;

	peer->local.commit = peer->remote.commit = NULL;
	peer->local.staging_cstate = peer->remote.staging_cstate = NULL;

	htlc_map_init(&peer->local.htlcs);
	htlc_map_init(&peer->remote.htlcs);
	
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

	return peer;
}

static void htlc_destroy(struct htlc *htlc)
{
	if (!htlc_map_del(&htlc->peer->local.htlcs, htlc)
	    && !htlc_map_del(&htlc->peer->remote.htlcs, htlc))
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
			   enum channel_side side)
{
	struct htlc *h = tal(peer, struct htlc);
	h->peer = peer;
	h->id = id;
	h->msatoshis = msatoshis;
	h->rhash = *rhash;
	if (!blocks_to_abs_locktime(expiry, &h->expiry))
		fatal("Invalid HTLC expiry %u", expiry);
	h->routing = tal_dup_arr(h, u8, route, routelen, 0);
	h->src = src;
	if (side == OURS)
		htlc_map_add(&peer->local.htlcs, h);
	else {
		assert(side == THEIRS);
		htlc_map_add(&peer->remote.htlcs, h);
	}
	tal_add_destructor(h, htlc_destroy);

	return h;
}

static struct io_plan *peer_connected_out(struct io_conn *conn,
					  struct lightningd_state *dstate,
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
	log_info(peer->log, "Connected out to %s:%s",
		 connect->name, connect->port);

	peer->anchor.input = tal_steal(peer, connect->input);

	command_success(connect->cmd, null_response(connect));
	return peer_crypto_setup(conn, peer, peer_crypto_on);
}

static struct io_plan *peer_connected_in(struct io_conn *conn,
					 struct lightningd_state *dstate)
{
	struct peer *peer = new_peer(dstate, conn, SOCK_STREAM, IPPROTO_TCP,
				     CMD_OPEN_WITHOUT_ANCHOR, "in");
	if (!peer)
		return io_close(conn);

	log_info(peer->log, "Peer connected in");
	return peer_crypto_setup(conn, peer, peer_crypto_on);
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

	if (!addr || bind(fd, addr, len) == 0) {
		if (listen(fd, 5) == 0)
			return fd;
		log_unusual(dstate->base_log,
			    "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
	} else
		log_debug(dstate->base_log, "Failed to bind on %u socket: %s",
			  domain, strerror(errno));

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

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(portnum);

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

static void complete_pay_command(struct peer *peer,
				 struct htlc *htlc,
				 const struct rval *rval)
{
	/* FIXME: implement. */
}

/* FIXME: Keep a timeout for each peer, in case they're unresponsive. */

/* FIXME: Make sure no HTLCs in any unrevoked commit tx are live. */

static void check_htlc_expiry(struct peer *peer)
{
	size_t i;
	u32 height = get_block_height(peer->dstate);

again:
	/* Check their currently still-existing htlcs for expiry:
	 * We eliminate them from staging as we go. */
	for (i = 0; i < tal_count(peer->remote.staging_cstate->side[THEIRS].htlcs); i++) {
		struct htlc *htlc = peer->remote.staging_cstate->side[THEIRS].htlcs[i];

		assert(!abs_locktime_is_seconds(&htlc->expiry));

		/* We give it an extra block, to avoid the worst of the
		 * inter-node timing issues. */
		if (height <= abs_locktime_to_blocks(&htlc->expiry))
			continue;

		/* This can fail only if we're in an error state. */
		if (!command_htlc_fail(peer, htlc))
			return;
		goto again;
	}
}

struct anchor_watch {
	struct peer *peer;
	enum state_input depthok;
	enum state_input timeout;

	/* If timeout != INPUT_NONE, this is the timer. */
	struct oneshot *timer;
};

static void anchor_depthchange(struct peer *peer, unsigned int depth,
			       const struct sha256_double *txid,
			       void *unused)
{
	struct anchor_watch *w = peer->anchor.watches;

	/* Still waiting for it to reach depth? */
	if (w->depthok != INPUT_NONE) {
		if (depth >= peer->local.mindepth) {
			enum state_input in = w->depthok;
			w->depthok = INPUT_NONE;
			/* We don't need the timeout timer any more. */
			w->timer = tal_free(w->timer);
			state_event(peer, in, NULL);
		}
	} else if (depth == 0)
		/* FIXME: Report losses! */
		fatal("Funding transaction was unspent!");

	/* Since this gets called on every new block, check HTLCs here. */
	check_htlc_expiry(peer);
}

/* Yay, segwit!  We can just compare txids, even though we don't have both
 * signatures. */
static bool txidmatch(const struct bitcoin_tx *tx,
		      const struct sha256_double *txid)
{
	struct sha256_double tx_txid;

	bitcoin_txid(tx, &tx_txid);
	return structeq(txid, &tx_txid);
}

static struct commit_info *find_commit(struct commit_info *ci,
				       const struct sha256_double *txid)
{
	while (ci) {
		if (txidmatch(ci->tx, txid))
			return ci;
		ci = ci->prev;
	}
	return NULL;
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

static struct htlc *htlc_by_index(const struct commit_info *ci, size_t index)
{
	if (ci->map[index] == -1)
		return NULL;

	/* First two are non-HTLC outputs to us, them. */
	assert(index >= 2);
	index -= 2;

	if (index < tal_count(ci->cstate->side[OURS].htlcs))
		return ci->cstate->side[OURS].htlcs[index];
	index -= tal_count(ci->cstate->side[OURS].htlcs);
	assert(index < tal_count(ci->cstate->side[THEIRS].htlcs));
	return ci->cstate->side[THEIRS].htlcs[index];
}

static bool htlc_is_ours(const struct commit_info *ci, size_t index)
{
	assert(index >= 2);
	index -= 2;

	return index < tal_count(ci->cstate->side[OURS].htlcs);
}

/* Create a HTLC refund collection */
static const struct bitcoin_tx *htlc_timeout_tx(const struct peer *peer,
						const struct commit_info *ci,
						unsigned int i)
{
	u8 *wscript;
	struct htlc *htlc;
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	struct bitcoin_signature sig;
	u64 fee, satoshis;

	htlc = htlc_by_index(ci, i);

	wscript = bitcoin_redeem_htlc_send(peer,
					   &peer->local.finalkey,
					   &peer->remote.finalkey,
					   &htlc->expiry,
					   &peer->remote.locktime,
					   &ci->revocation_hash,
					   &htlc->rhash);

	/* We must set locktime so HTLC expiry can OP_CHECKLOCKTIMEVERIFY */
	tx->lock_time = htlc->expiry.locktime;
	tx->input[0].index = 0;
	bitcoin_txid(ci->tx, &tx->input[0].txid);
	satoshis = htlc->msatoshis / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's our HTLC, and that we collected it via timeout. */
	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx, &peer->local.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	log_unusual(peer->log, "Pre-witness txlen = %zu\n",
		    measure_tx_cost(tx) / 4);

	assert(measure_tx_cost(tx) == 83 * 4);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 539 from an example run. */
	/* FIXME: Dynamic fees! */
	fee = fee_by_feerate(83 + 539 / 4,
			     peer->dstate->config.closing_fee_rate);

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > satoshis || is_dust_amount(satoshis - fee))
		fatal("HTLC refund amount of %"PRIu64" won't cover fee %"PRIu64,
		      satoshis, fee);

	tx->output[0].amount = satoshis - fee;

	sig.stype = SIGHASH_ALL;
	peer_sign_htlc_refund(peer, tx, wscript, &sig.sig);

	tx->input[0].witness = bitcoin_witness_htlc(tx, NULL, &sig, wscript);

	log_unusual(peer->log, "tx cost for htlc timeout tx: %zu",
		    measure_tx_cost(tx));

	return tx;
}

static void reset_onchain_closing(struct peer *peer)
{
	if (peer->closing_onchain.tx) {
		/* FIXME: Log old txid */
		log_unusual(peer->log, "New anchor spend, forgetting old");
		peer->closing_onchain.tx = tal_free(peer->closing_onchain.tx);
		peer->closing_onchain.resolved = NULL;
		peer->closing_onchain.ci = NULL;
	}
}

static const struct bitcoin_tx *irrevocably_resolved(struct peer *peer)
{
	/* We can't all be irrevocably resolved until the commit tx is,
	 * so just mark that as resolving us. */
	return peer->closing_onchain.tx;
}

static void connect_input(const struct commit_info *ci,
			  struct bitcoin_tx_input *input,
			  u32 index)
{
	bitcoin_txid(ci->tx, &input->txid);
	input->index = index;
	input->amount = tal_dup(ci, u64, &ci->tx->output[index].amount);
}

static void resolve_cheating(struct peer *peer)
{
	const struct bitcoin_tx *tx = peer->closing_onchain.tx;
	const struct commit_info *ci = peer->closing_onchain.ci;
	struct bitcoin_tx *steal_tx;
	u8 **wscripts;
	size_t i, n, num_to_steal;
	int *map;

	peer->closing_onchain.resolved
		= tal_arrz(tx, const struct bitcoin_tx *, tal_count(ci->map));
	
	/* BOLT #onchain:
	 *
	 * If a node sees a *commitment tx* for which it has a revocation
	 * preimage, it *resolves* the funding transaction output:
	 *
	 * 1. _A's main output_: No action is required; this is a
	 *    simple P2WPKH output.  This output is considered
	 *    *resolved* by the *commitment tx*.
	 */

	/* Their commit tx, so our output is [1], theirs in [0]. */
	peer->closing_onchain.resolved[1] = tx;
	
	/* BOLT #onchain:
	 *
	 * 2. _B's main output_: The node MUST *resolve* this by
	 * spending using the revocation preimage.
	 *
	 * 3. _A's offered HTLCs_: The node MUST *resolve* this by
	 * spending using the revocation preimage.
	 *
	 * 4. _B's offered HTLCs_: The node MUST *resolve* this by
	 * spending using the revocation preimage. */
	num_to_steal = 0;
	if (ci->map[0] == -1)
		peer->closing_onchain.resolved[0] = tx;
	else
		num_to_steal++;

	for (i = 2; i < tal_count(ci->map); i++)
		if (ci->map[i] == -1)
			peer->closing_onchain.resolved[i] = tx;
		else
			num_to_steal++;

	/* Nothing to steal? */
	if (num_to_steal == 0)
		return;

	/* BOLT #onchain:
	 *
	 * The node MAY use a single transaction to *resolve* all the
	 * outputs; due to the 450 HTLC-per-party limit (See BOLT #2:
	 * 3.2. Adding an HTLC) this can be done within a standard
	 * transaction.
	 */
	steal_tx = bitcoin_tx(peer, num_to_steal, 1);

	wscripts = tal_arr(steal_tx, u8 *, num_to_steal);

	n = 0;
	if (ci->map[0] != -1) {
		connect_input(ci, &steal_tx->input[n], ci->map[0]);
		peer->closing_onchain.resolved[0] = steal_tx;
		wscripts[n++]
			= bitcoin_redeem_secret_or_delay(wscripts,
							 &peer->remote.finalkey,
							 &peer->local.locktime,
							 &peer->local.finalkey,
							 &ci->revocation_hash);
	}

	for (i = 2; i < tal_count(ci->map); i++) {
		struct htlc *h;

		if (ci->map[i] == -1)
			continue;

		peer->closing_onchain.resolved[i] = steal_tx;

		connect_input(ci, &steal_tx->input[n], ci->map[i]);

		h = htlc_by_index(ci, i);
		if (!htlc_is_ours(ci, i)) {
			wscripts[n]
				= bitcoin_redeem_htlc_send(wscripts,
							   &peer->remote.finalkey,
							   &peer->local.finalkey,
							   &h->expiry,
							   &peer->local.locktime,
							   &ci->revocation_hash,
							   &h->rhash);
		} else {
			wscripts[n]
				= bitcoin_redeem_htlc_recv(wscripts,
							   &peer->remote.finalkey,
							   &peer->local.finalkey,
							   &h->expiry,
							   &peer->local.locktime,
							   &ci->revocation_hash,
							   &h->rhash);
		}
		n++;
	}
	assert(n == num_to_steal);

	/* This obscures the order in which HTLCs were received, at least. */
	map = tal_arr(steal_tx, int, num_to_steal);
	permute_inputs(steal_tx->input, steal_tx->input_count, map);

	/* Now, we can sign them all (they're all of same form). */
	for (n = 0; n < num_to_steal; n++) {
		struct bitcoin_signature sig;

		sig.stype = SIGHASH_ALL;
		peer_sign_steal_input(peer, steal_tx, map[n], wscripts[n], &sig.sig);

		steal_tx->input[map[n]].witness
			= bitcoin_witness_secret(steal_tx,
						 ci->revocation_preimage,
						 sizeof(*ci->revocation_preimage),
						 &sig,
						 wscripts[n]);
	}

	broadcast_tx(peer, steal_tx);
}

static void our_htlc_spent(struct peer *peer,
			   const struct bitcoin_tx *tx,
			   size_t input_num,
			   ptrint_t *pi)
{
	struct htlc *h;
	struct sha256 sha;
	struct rval preimage;
	size_t i = ptr2int(pi);

	/* It should be spending the HTLC we expect. */
	assert(peer->closing_onchain.ci->map[i] == tx->input[input_num].index);

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
		fatal("Impossible HTLC spend for %zu", i);
	
	/* Our timeout tx has all-zeroes, so we can distinguish it. */
	if (memeqzero(tx->input[input_num].witness[1], sizeof(preimage)))
		return;

	memcpy(&preimage, tx->input[input_num].witness[1], sizeof(preimage));
	sha256(&sha, &preimage, sizeof(preimage));

	h = htlc_by_index(peer->closing_onchain.ci, i);

	/* FIXME: This could happen with a ripemd collision, since
	 * script.c only checks that ripemd matches... */
	if (!structeq(&sha, &h->rhash))
		fatal("HTLC redeemed with incorrect r value?");

	log_unusual(peer->log, "Peer redeemed HTLC %zu on-chain using r value",
		    i);

	/* BOLT #onchain:
	 *
	 * If a node sees a redemption transaction, the output is considered
	 * *irrevocably resolved*... Note that we don't care about the fate of
	 * the redemption transaction itself once we've extracted the
	 * preimage; the knowledge is not revocable.
	 */
	peer->closing_onchain.resolved[i] = irrevocably_resolved(peer);
}

static void our_htlc_depth(struct peer *peer,
			   unsigned int depth,
			   const struct sha256_double *txid,
			   bool our_commit,
			   size_t i)
{
	struct htlc *h;
	u32 height;

	/* Must be in a block. */
	if (depth == 0)
		return;

	height = get_block_height(peer->dstate);
	h = htlc_by_index(peer->closing_onchain.ci, i);

	/* BOLT #onchain:
	 *
	 * If the *commitment tx* is the other node's, the output is
	 * considered *timed out* once the HTLC is expired.  If the
	 * *commitment tx* is this node's, the output is considered *timed
	 * out* once the HTLC is expired, AND the output's
	 * `OP_CHECKSEQUENCEVERIFY` delay has passed.
	 */

	if (height < abs_locktime_to_blocks(&h->expiry))
		return;

	if (our_commit) {
		if (depth < rel_locktime_to_blocks(&peer->remote.locktime))
			return;
	}

	/* BOLT #onchain:
	 *
	 * If the output has *timed out* and not been *resolved*, the node
	 * MUST *resolve* the output by spending it.
	 */
	if (!peer->closing_onchain.resolved[i]) {
		peer->closing_onchain.resolved[i]
			= htlc_timeout_tx(peer, peer->closing_onchain.ci, i);
		broadcast_tx(peer, peer->closing_onchain.resolved[i]);
	}
}

static void our_htlc_depth_ourcommit(struct peer *peer,
				     unsigned int depth,
				     const struct sha256_double *txid,
				     ptrint_t *i)
{
	our_htlc_depth(peer, depth, txid, true, ptr2int(i));
}

static void our_htlc_depth_theircommit(struct peer *peer,
				       unsigned int depth,
				       const struct sha256_double *txid,
				       ptrint_t *i)
{
	our_htlc_depth(peer, depth, txid, false, ptr2int(i));
}

static void resolve_our_htlcs(struct peer *peer,
			      const struct commit_info *ci,
			      const struct bitcoin_tx *tx,
			      const struct bitcoin_tx **resolved,
			      bool from_ourcommit,
			      size_t start, size_t num)
{
	size_t i;
	struct sha256_double txid;

	bitcoin_txid(tx, &txid);
	for (i = start; i < start + num; i++) {
		/* Doesn't exist?  Resolved by tx itself. */
		if (ci->map[i] == -1) {
			resolved[i] = tx;
			continue;
		}

		/* BOLT #onchain:
		 *
		 * A node MUST watch for spends of *commitment tx* outputs for
		 * HTLCs it offered; each one must be *resolved* by a timeout
		 * transaction (the node pays back to itself) or redemption
		 * transaction (the other node provides the redemption
		 * preimage).
		 */
		watch_txo(tx, peer, &txid, ci->map[i], our_htlc_spent,
			  int2ptr(i));
		watch_txid(tx, peer, &txid,
			   from_ourcommit
			   ? our_htlc_depth_ourcommit
			   : our_htlc_depth_theircommit,
			   int2ptr(i));
	}	
}

/* BOLT #onchain:
 *
 * If the node receives a redemption preimage for a *commitment tx* output it
 * was offered, it MUST *resolve* the output by spending it using the
 * preimage.  Otherwise, the other node could spend it once it as *timed out*
 * as above.
 */
bool resolve_one_htlc(struct peer *peer, u64 id, const struct rval *preimage)
{
	FIXME_STUB(peer);
}

static void their_htlc_depth(struct peer *peer,
			     unsigned int depth,
			     const struct sha256_double *txid,
			     ptrint_t *pi)
{
	u32 height;
	struct htlc *h;
	size_t i = ptr2int(pi);

	/* Must be in a block. */
	if (depth == 0)
		return;

	height = get_block_height(peer->dstate);
	h = htlc_by_index(peer->closing_onchain.ci, i);

	/* BOLT #onchain:
	 *
	 * Otherwise, if the output HTLC has expired, it is considered
	 * *irrevocably resolved*.
	 */

	if (height < abs_locktime_to_blocks(&h->expiry))
		return;

	peer->closing_onchain.resolved[i] = irrevocably_resolved(peer);
}

static void resolve_their_htlcs(struct peer *peer,
				const struct commit_info *ci,
				const struct bitcoin_tx *tx,
				const struct bitcoin_tx **resolved,
				size_t start, size_t num)
{
	size_t i;

	for (i = start; i < start + num; i++) {
		/* Doesn't exist?  Resolved by tx itself. */
		if (ci->map[i] == -1) {
			resolved[i] = tx;
			continue;
		}

		watch_tx(tx, peer, tx, their_htlc_depth, int2ptr(i));
	}	
}

static void our_main_output_depth(struct peer *peer,
				  unsigned int depth,
				  const struct sha256_double *txid,
				  void *unused)
{
	/* Not past CSV timeout? */
	if (depth < rel_locktime_to_blocks(&peer->remote.locktime))
		return;

	/* Already done?  (FIXME: Delete after first time) */
	if (peer->closing_onchain.resolved[0])
		return;

	/* BOLT #onchain:
	 *
	 * 1. _A's main output_: A node SHOULD spend this output to a
	 *    convenient address.  This avoids having to remember the
	 *    complicated witness script associated with that particular
	 *    channel for later spending. ... If the output is spent (as
	 *    recommended), the output is *resolved* by the spending
	 *    transaction
	 */
	peer->closing_onchain.resolved[0] = bitcoin_spend_ours(peer);
	broadcast_tx(peer, peer->closing_onchain.resolved[0]);
}

/* BOLT #onchain:
 *
 * When node A sees its own *commitment tx*:
 */
static void resolve_our_unilateral(struct peer *peer)
{
	const struct bitcoin_tx *tx = peer->closing_onchain.tx;
	const struct commit_info *ci = peer->closing_onchain.ci;
	size_t num_ours, num_theirs;

	peer->closing_onchain.resolved
		= tal_arrz(tx, const struct bitcoin_tx *, tal_count(ci->map));

	/* BOLT #onchain:
	 *
	 * 1. _A's main output_: A node SHOULD spend this output to a
	 *    convenient address. ... A node MUST wait until the
	 *    `OP_CHECKSEQUENCEVERIFY` delay has passed (as specified by the
	 *    other node's `open_channel` `delay` field) before spending the
	 *    output.
	 */
	watch_tx(tx, peer, tx, our_main_output_depth, NULL);

	/* BOLT #onchain:
	 *
	 * 2. _B's main output_: No action required, this output is considered
	 *    *resolved* by the *commitment tx*.
	 */
	peer->closing_onchain.resolved[1] = tx;

	num_ours = tal_count(ci->cstate->side[OURS].htlcs);
	num_theirs = tal_count(ci->cstate->side[THEIRS].htlcs);

	/* BOLT #onchain:
	 *
	 * 3. _A's offered HTLCs_: See On-chain HTLC Handling: Our Offers below.
	 */
	resolve_our_htlcs(peer, ci, tx,
			  peer->closing_onchain.resolved,
			  true, 2, num_ours);

	/* BOLT #onchain:
	 *
	 * 4. _B's offered HTLCs_: See On-chain HTLC Handling: Their
	 * Offers below.
	 */
	resolve_their_htlcs(peer, ci, tx,
			    peer->closing_onchain.resolved,
			    2 + num_ours, num_theirs);
}

/* BOLT #onchain:
 *
 * Similarly, when node A sees a *commitment tx* from B:
 */
static void resolve_their_unilateral(struct peer *peer)
{
	const struct bitcoin_tx *tx = peer->closing_onchain.tx;
	const struct commit_info *ci = peer->closing_onchain.ci;
	size_t num_ours, num_theirs;

	peer->closing_onchain.resolved
		= tal_arrz(tx, const struct bitcoin_tx *, tal_count(ci->map));

	/* BOLT #onchain:
	 *
	 * 1. _A's main output_: No action is required; this is a
	 *    simple P2WPKH output.  This output is considered
	 *    *resolved* by the *commitment tx*.
	 */
	peer->closing_onchain.resolved[1] = tx;

	/* BOLT #onchain:
	 *
	 * 2. _B's main output_: No action required, this output is
	 *    considered *resolved* by the *commitment tx*.
	 */
	peer->closing_onchain.resolved[0] = tx;

	num_ours = tal_count(ci->cstate->side[OURS].htlcs);
	num_theirs = tal_count(ci->cstate->side[THEIRS].htlcs);

	/* BOLT #onchain:
	 *
	 * 3. _A's offered HTLCs_: See On-chain HTLC Handling: Our Offers below.
	 */
	resolve_our_htlcs(peer, ci, tx,
			  peer->closing_onchain.resolved,
			  false, 2 + num_theirs, num_ours);

	/* BOLT #onchain:
	 *
	 * 4. _B's offered HTLCs_: See On-chain HTLC Handling: Their
	 * Offers below.
	 */
	resolve_their_htlcs(peer, ci, tx,
			    peer->closing_onchain.resolved,
			    2, num_theirs);
}

static void resolve_mutual_close(struct peer *peer)
{
	const struct bitcoin_tx *tx = peer->closing_onchain.tx;

	/* BOLT #onchain:
	 *
	 * A node doesn't need to do anything else as it has already agreed to
	 * the output, which is sent to its specified scriptpubkey (see BOLT
	 * #2 "4.1: Closing initiation: close_clearing").
	 */
	peer->closing_onchain.resolved
		= tal_arr(tx, const struct bitcoin_tx *, 0);
}

/* Called every time the tx spending the funding tx changes depth. */
static void check_for_resolution(struct peer *peer,
				 unsigned int depth,
				 const struct sha256_double *txid,
				 void *unused)
{
	size_t i, n = tal_count(peer->closing_onchain.resolved);
	size_t forever = peer->dstate->config.forever_confirms;
		
	/* BOLT #onchain:
	 *
	 * A node MUST *resolve* all outputs as specified below, and MUST be
	 * prepared to resolve them multiple times in case of blockchain
	 * reorganizations.
	 */
	for (i = 0; i < n; i++)
		if (!peer->closing_onchain.resolved[i])
			return;

	/* BOLT #onchain:
	 *
	 * Outputs which are *resolved* by a transaction are considered
	 * *irrevocably resolved* once they are included in a block at least
	 * 100 deep on the most-work blockchain.
	 */
	if (depth < forever)
		return;

	for (i = 0; i < n; i++) {
		struct sha256_double txid;

		bitcoin_txid(peer->closing_onchain.resolved[i], &txid);
		if (get_tx_depth(peer->dstate, &txid) < forever)
			return;
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
}
	    
/* We assume the tx is valid!  Don't do a blockchain.info and feed this
 * invalid transactions! */
static void anchor_spent(struct peer *peer,
			 const struct bitcoin_tx *tx,
			 size_t input_num,
			 void *unused)
{
	struct sha256_double txid;
	Pkt *err;
	enum state newstate;

	assert(input_num < tx->input_count);

	/* We only ever sign single-input txs. */
	if (input_num != 0)
		fatal("Anchor spend by non-single input tx");

	/* We may have been following a different spend.  Forget it. */
	reset_onchain_closing(peer);

	peer->closing_onchain.tx = tal_steal(peer, tx);
	bitcoin_txid(tx, &txid);

	peer->closing_onchain.ci = find_commit(peer->remote.commit, &txid);
	if (peer->closing_onchain.ci) {
		if (peer->closing_onchain.ci->revocation_preimage) {
			newstate = STATE_CLOSE_ONCHAIN_CHEATED;
			err = pkt_err(peer, "Revoked transaction seen");
			resolve_cheating(peer);
		} else {
			newstate = STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL;
			err = pkt_err(peer, "Unilateral close tx seen");
			resolve_their_unilateral(peer);
		}
	} else if (txidmatch(peer->local.commit->tx, &txid)) {
		newstate = STATE_CLOSE_ONCHAIN_OUR_UNILATERAL;
		/* We're almost certainly closed to them by now. */
		err = pkt_err(peer, "Our own unilateral close tx seen");
		peer->closing_onchain.ci = peer->local.commit;
		resolve_our_unilateral(peer);
	} else if (is_mutual_close(peer, tx)) {
		newstate = STATE_CLOSE_ONCHAIN_MUTUAL;
		err = NULL;
		resolve_mutual_close(peer);
	} else {
		/* BOLT #onchain:
		 *
		 * A node SHOULD report an error to the operator if it
		 * sees a transaction spend the funding transaction
		 * output which does not fall into one of these
		 * categories (mutual close, unilateral close, or
		 * cheating attempt).  Such a transaction implies its
		 * private key has leaked, and funds may be lost.
		 */
		/* FIXME: Log harder! */
		log_broken(peer->log, "Unknown tx spend!  Funds may be lost!");
		set_peer_state(peer,
			       STATE_ERR_INFORMATION_LEAK,
			       "anchor_spent");
		/* No longer call into the state machine. */
		peer->anchor.watches->depthok = INPUT_NONE;
		return;
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

	assert(peer->closing_onchain.resolved != NULL);
	watch_tx(tx, peer, tx, check_for_resolution, NULL);

	/* No longer call into the state machine. */
	peer->anchor.watches->depthok = INPUT_NONE;
}

static void anchor_timeout(struct anchor_watch *w)
{
	assert(w == w->peer->anchor.watches);
	state_event(w->peer, w->timeout, NULL);

	/* Freeing this gets rid of the other watches, and timer, too. */
	w->peer->anchor.watches = tal_free(w);
}

void peer_watch_anchor(struct peer *peer,
		       enum state_input depthok,
		       enum state_input timeout)
{
	struct anchor_watch *w;

	w = peer->anchor.watches = tal(peer, struct anchor_watch);

	w->peer = peer;
	w->depthok = depthok;
	w->timeout = timeout;

	watch_txid(w, peer, &peer->anchor.txid, anchor_depthchange, NULL);
	watch_txo(w, peer, &peer->anchor.txid, 0, anchor_spent, NULL);

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
	if (w->timeout != INPUT_NONE) {
		w->timer = new_reltimer(peer->dstate, w,
					time_from_sec(7200
						      + 20*peer->local.mindepth),
					anchor_timeout, w);
	} else
		w->timer = NULL;
}

void peer_unwatch_anchor_depth(struct peer *peer,
			       enum state_input depthok,
			       enum state_input timeout)
{
	assert(peer->anchor.watches);
	assert(peer->anchor.watches->depthok == depthok);
	peer->anchor.watches->depthok = INPUT_NONE;
}

uint64_t commit_tx_fee(const struct bitcoin_tx *commit, uint64_t anchor_satoshis)
{
	uint64_t i, total = 0;

	for (i = 0; i < commit->output_count; i++)
		total += commit->output[i].amount;

	assert(anchor_satoshis >= total);
	return anchor_satoshis - total;
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
		  "creating close-tx with fee %"PRIu64": to %02x%02x%02x%02x/%02x%02x%02x%02x, amounts %u/%u",
		  fee,
		  peer->local.finalkey.der[0], peer->local.finalkey.der[1],
		  peer->local.finalkey.der[2], peer->local.finalkey.der[3],
		  peer->remote.finalkey.der[0], peer->remote.finalkey.der[1],
		  peer->remote.finalkey.der[2], peer->remote.finalkey.der[3],
		  cstate.side[OURS].pay_msat / 1000,
		  cstate.side[THEIRS].pay_msat / 1000);

 	return create_close_tx(peer->dstate->secpctx, peer,
			       peer->closing.our_script,
			       peer->closing.their_script,
			       &peer->anchor.txid,
			       peer->anchor.index,
			       peer->anchor.satoshis,
			       cstate.side[OURS].pay_msat / 1000,
			       cstate.side[THEIRS].pay_msat / 1000);
}

void peer_calculate_close_fee(struct peer *peer)
{
	/* Use actual worst-case length of close tx: based on BOLT#02's
	 * commitment tx numbers, but only 1 byte for output count */
	const uint64_t txsize = 41 + 221 + 10 + 32 + 32;
	uint64_t maxfee;

	/* FIXME: Dynamic fee */
	peer->closing.our_fee
		= fee_by_feerate(txsize, peer->dstate->config.closing_fee_rate);

	/* BOLT #2:
	 * The sender MUST set `close_fee` lower than or equal to the
	 * fee of the final commitment transaction, and MUST set
	 * `close_fee` to an even number of satoshis.
	 */
	maxfee = commit_tx_fee(peer->local.commit->tx, peer->anchor.satoshis);
	if (peer->closing.our_fee > maxfee) {
		/* This shouldn't happen: we never accept a commit fee
		 * less than the min_rate, which is greater than the
		 * closing_fee_rate.  Also, our txsize estimate for
		 * the closing tx is 2 bytes smaller than the commitment tx. */
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

void peer_unexpected_pkt(struct peer *peer, const Pkt *pkt)
{
	const char *p;

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

/* Create a bitcoin close tx, using last signature they sent. */
const struct bitcoin_tx *bitcoin_close(struct peer *peer)
{
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature our_close_sig;

	close_tx = peer_create_close_tx(peer, peer->closing.their_fee);

	our_close_sig.stype = SIGHASH_ALL;
	peer_sign_mutual_close(peer, close_tx, &our_close_sig.sig);

	close_tx->input[0].witness
		= bitcoin_witness_2of2(close_tx->input,
				       peer->closing.their_sig,
				       &our_close_sig,
				       &peer->remote.commitkey,
				       &peer->local.commitkey);

	return close_tx;
}

/* Create a bitcoin spend tx (to spend our commit's outputs) */
const struct bitcoin_tx *bitcoin_spend_ours(struct peer *peer)
{
	u8 *witnessscript;
	const struct bitcoin_tx *commit = peer->local.commit->tx;
	struct bitcoin_signature sig;
	struct bitcoin_tx *tx;
	unsigned int p2wsh_out;
	uint64_t fee;

	/* The redeemscript for a commit tx is fairly complex. */
	witnessscript = bitcoin_redeem_secret_or_delay(peer,
						      &peer->local.finalkey,
						      &peer->remote.locktime,
						      &peer->remote.finalkey,
						      &peer->local.commit->revocation_hash);

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(peer, 1, 1);
	bitcoin_txid(commit, &tx->input[0].txid);
	p2wsh_out = find_p2wsh_out(commit, witnessscript);
	tx->input[0].index = p2wsh_out;
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->remote.locktime);
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &commit->output[p2wsh_out].amount);

	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx, &peer->local.finalkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 176 from an example run. */
	assert(measure_tx_cost(tx) == 83 * 4);

	/* FIXME: Dynamic fees! */
	fee = fee_by_feerate(83 + 176 / 4,
			     peer->dstate->config.closing_fee_rate);

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > commit->output[p2wsh_out].amount
	    || is_dust_amount(commit->output[p2wsh_out].amount - fee))
		fatal("Amount of %"PRIu64" won't cover fee %"PRIu64,
		      commit->output[p2wsh_out].amount, fee);

	tx->output[0].amount = commit->output[p2wsh_out].amount - fee;

	sig.stype = SIGHASH_ALL;
	peer_sign_spend(peer, tx, witnessscript, &sig.sig);

	tx->input[0].witness = bitcoin_witness_secret(tx, NULL, 0, &sig,
						      witnessscript);

	return tx;
}

/* Sign and return our commit tx */
const struct bitcoin_tx *bitcoin_commit(struct peer *peer)
{
	struct bitcoin_signature sig;

	/* Can't be signed already, and can't have scriptsig! */
	assert(peer->local.commit->tx->input[0].script_length == 0);
	assert(!peer->local.commit->tx->input[0].witness);

	sig.stype = SIGHASH_ALL;
	peer_sign_ourcommit(peer, peer->local.commit->tx, &sig.sig);

	peer->local.commit->tx->input[0].witness
		= bitcoin_witness_2of2(peer->local.commit->tx->input,
				       peer->local.commit->sig,
				       &sig,
				       &peer->remote.commitkey,
				       &peer->local.commitkey);

	return peer->local.commit->tx;
}

/* Now we can create anchor tx. */ 
static void got_feerate(struct lightningd_state *dstate,
			u64 rate, struct peer *peer)
{
	u64 fee;
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	size_t i;

	tx->output[0].script = scriptpubkey_p2wsh(tx, peer->anchor.witnessscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Add input script length.  FIXME: This is normal case, not exact. */
	fee = fee_by_feerate(measure_tx_cost(tx)/4 + 1+73 + 1+33 + 1, rate);
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
	
	state_event(peer, BITCOIN_ANCHOR_CREATED, NULL);
}

/* Creation the bitcoin anchor tx, spending output user provided. */
void bitcoin_create_anchor(struct peer *peer, enum state_input done)
{
	/* We must be offering anchor for us to try creating it */
	assert(peer->local.offer_anchor);

	assert(done == BITCOIN_ANCHOR_CREATED);
	bitcoind_estimate_fee(peer->dstate, got_feerate, peer);
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

void add_unacked(struct peer_visible_state *which,
		 const union htlc_staging *stage)
{
	size_t n = tal_count(which->commit->unacked_changes);
	tal_resize(&which->commit->unacked_changes, n+1);
	which->commit->unacked_changes[n] = *stage;
}

void add_acked_changes(union htlc_staging **acked,
		       const union htlc_staging *changes)
{
	size_t n_acked, n_changes;

	n_acked = tal_count(*acked);
	n_changes = tal_count(changes);
	tal_resize(acked, n_acked + n_changes);
	memcpy(*acked + n_acked, changes, n_changes * sizeof(*changes));
}

static const char *owner_name(enum channel_side side)
{
	return side == OURS ? "our" : "their";
}

static void route_htlc_onwards(struct peer *peer,
			       struct htlc *htlc,
			       u64 msatoshis,
			       const BitcoinPubkey *pb_id,
			       const u8 *rest_of_route)
{
	struct pubkey id;
	struct peer *next;

	if (!proto_to_pubkey(peer->dstate->secpctx, pb_id, &id)) {
		log_unusual(peer->log,
			    "Malformed pubkey for HTLC %"PRIu64, htlc->id);
		command_htlc_fail(peer, htlc);
		return;
	}

	next = find_peer(peer->dstate, &id);
	if (!next || !next->nc) {
		log_unusual(peer->log, "Can't route HTLC %"PRIu64, htlc->id);
		log_add_struct(peer->log, " no peer %s", struct pubkey, &id);
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
		command_htlc_fulfill(peer, htlc, &payment->r);
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
		complete_pay_command(peer, htlc, NULL);
}

/* When changes are committed to. */
void peer_both_committed_to(struct peer *peer,
			    const union htlc_staging *changes,
			    enum channel_side side)
{
	size_t i, n = tal_count(changes);

	/* All this, simply for debugging. */
	for (i = 0; i < n; i++) {
		u64 htlc_id;
		const char *type, *owner;

		switch (changes[i].type) {
		case HTLC_ADD:
			type = "ADD";
			htlc_id = changes[i].add.htlc->id;
			owner = owner_name(side);
			assert(cstate_htlc_by_id(peer->remote.commit->cstate, htlc_id,
						  side));
			assert(cstate_htlc_by_id(peer->local.commit->cstate, htlc_id,
						  side));
			goto print;
		case HTLC_FAIL:
			type = "FAIL";
			htlc_id = changes[i].fail.htlc->id;
			owner = owner_name(!side);
			assert(!cstate_htlc_by_id(peer->remote.commit->cstate, htlc_id,
						   !side));
			assert(!cstate_htlc_by_id(peer->local.commit->cstate, htlc_id,
						   !side));
			assert(cstate_htlc_by_id(peer->remote.commit->prev->cstate,
						  htlc_id, !side)
			       || cstate_htlc_by_id(peer->local.commit->prev->cstate,
						     htlc_id, !side));
			goto print;
		case HTLC_FULFILL:
			type = "FULFILL";
			htlc_id = changes[i].fulfill.htlc->id;
			owner = owner_name(!side);
			assert(!cstate_htlc_by_id(peer->remote.commit->cstate, htlc_id,
						   !side));
			assert(!cstate_htlc_by_id(peer->local.commit->cstate, htlc_id,
						   !side));
			assert(cstate_htlc_by_id(peer->remote.commit->prev->cstate,
						  htlc_id, !side)
			       || cstate_htlc_by_id(peer->local.commit->prev->cstate,
						     htlc_id, !side));
			goto print;
		}
		abort();
	print:
		log_debug(peer->log, "Both committed to %s of %s HTLC %"PRIu64,
			  type, owner, htlc_id);
	}

	/* We actually only respond to changes they made. */
	if (side == OURS)
		return;

	for (i = 0; i < n; i++) {
		switch (changes[i].type) {
		case HTLC_ADD:
			their_htlc_added(peer, changes[i].add.htlc);
			break;
		case HTLC_FULFILL:
			/* FIXME: resolve_one_htlc(peer, id, preimage); */
			break;
		case HTLC_FAIL:
			our_htlc_failed(peer, changes[i].fail.htlc);
			break;
		}
	}
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
						  &peer->local.finalkey,
						  &peer->remote.finalkey,
						  &peer->local.locktime,
						  &peer->remote.locktime,
						  &peer->anchor.txid,
						  peer->anchor.index,
						  peer->anchor.satoshis,
						  &peer->local.commit->revocation_hash,
						  peer->local.commit->cstate,
						  OURS,
						  &peer->local.commit->map);

	peer->remote.commit->tx = create_commit_tx(peer->remote.commit,
						   &peer->local.finalkey,
						   &peer->remote.finalkey,
						   &peer->local.locktime,
						   &peer->remote.locktime,
						   &peer->anchor.txid,
						   peer->anchor.index,
						   peer->anchor.satoshis,
						   &peer->remote.commit->revocation_hash,
						   peer->remote.commit->cstate,
						   THEIRS,
						   &peer->remote.commit->map);

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

static void json_add_htlcs(struct json_result *response,
			   const char *id,
			   const struct channel_oneside *side)
{
	size_t i;

	json_array_start(response, id);
	for (i = 0; i < tal_count(side->htlcs); i++) {
		json_object_start(response, NULL);
		json_add_u64(response, "msatoshis", side->htlcs[i]->msatoshis);
		json_add_abstime(response, "expiry", &side->htlcs[i]->expiry);
		json_add_hex(response, "rhash",
			     &side->htlcs[i]->rhash,
			     sizeof(side->htlcs[i]->rhash));
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

		/* This is only valid after crypto setup. */
		if (p->state != STATE_INIT)
			json_add_hex(response, "peerid",
				     p->id.der, sizeof(p->id.der));

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
		json_add_htlcs(response, "our_htlcs", &last->side[OURS]);
		json_add_htlcs(response, "their_htlcs", &last->side[THEIRS]);

		/* Any changes since then? */
		if (p->local.staging_cstate->changes != last->changes)
			json_add_num(response, "local_staged_changes",
				     p->local.staging_cstate->changes
				     - last->changes);
		if (p->remote.staging_cstate->changes
		    != p->remote.commit->cstate->changes)
			json_add_num(response, "remote_staged_changes",
				     p->remote.staging_cstate->changes
				     - p->remote.commit->cstate->changes);
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

/* A zero-fee single route to this peer. */
static const u8 *dummy_single_route(const tal_t *ctx,
				    const struct peer *peer,
				    u64 msatoshis)
{
	struct node_connection **path = tal_arr(ctx, struct node_connection *, 0);
	return onion_create(ctx, path, msatoshis, 0);
}

static void json_newhtlc(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *msatoshistok, *expirytok, *rhashtok;
	unsigned int expiry;
	u64 msatoshis;
	struct sha256 rhash;

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

	if (!command_htlc_add(peer, msatoshis, expiry, &rhash, NULL,
			      dummy_single_route(cmd, peer, msatoshis))) {
		command_fail(cmd, "could not add htlc");
		return;
	}

	command_success(cmd, null_response(cmd));
}

/* FIXME: Use HTLC ids, not r values! */
const struct json_command newhtlc_command = {
	"newhtlc",
	json_newhtlc,
	"Offer {peerid} an HTLC worth {msatoshis} in {expiry} (block number) with {rhash}",
	"Returns an empty result on success"
};

/* Looks for their HTLC, but must be committed. */
static struct htlc *find_their_committed_htlc(struct peer *peer,
					      const struct sha256 *rhash)
{
	/* Must be in last committed cstate. */
	if (!cstate_find_htlc(peer->remote.commit->cstate, rhash, THEIRS))
		return NULL;

	return cstate_find_htlc(peer->remote.staging_cstate, rhash, THEIRS);
}

static void json_fulfillhtlc(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *rtok;
	struct rval r;
	struct sha256 rhash;
	struct htlc *htlc;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "r", &rtok,
			     NULL)) {
		command_fail(cmd, "Need peerid and r");
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

	if (!hex_decode(buffer + rtok->start,
			rtok->end - rtok->start,
			&r, sizeof(r))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 preimage",
			     (int)(rtok->end - rtok->start),
			     buffer + rtok->start);
		return;
	}

	sha256(&rhash, &r, sizeof(r));

	htlc = find_their_committed_htlc(peer, &rhash);
	if (!htlc) {
		command_fail(cmd, "preimage htlc not found");
		return;
	}

	if (command_htlc_fulfill(peer, htlc, &r))
		command_success(cmd, null_response(cmd));
	else
		command_fail(cmd,
			     "htlc_fulfill not possible in state %s",
			     state_name(peer->state));
}

const struct json_command fulfillhtlc_command = {
	"fulfillhtlc",
	json_fulfillhtlc,
	"Redeem htlc proposed by {peerid} using {r}",
	"Returns an empty result on success"
};

static void json_failhtlc(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *rhashtok;
	struct sha256 rhash;
	struct htlc *htlc;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need peerid and rhash");
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

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&rhash, sizeof(rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 preimage",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	/* Look in peer->remote.staging_cstate->a, as that's where we'll 
	 * immediately remove it from: avoids double-handling. */
	htlc = find_their_committed_htlc(peer, &rhash);
	if (!htlc) {
		command_fail(cmd, "htlc not found");
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
	"Fail htlc proposed by {peerid} which has redeem hash {rhash}",
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
		set_peer_state(peer, STATE_CLEARING_COMMITTING, __func__);
	else
		set_peer_state(peer, STATE_CLEARING, __func__);
	peer_start_clearing(peer);
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
