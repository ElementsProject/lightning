#include "bitcoind.h"
#include "chaintopology.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "cryptopkt.h"
#include "db.h"
#include "dns.h"
#include "find_p2sh_out.h"
#include "invoice.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "netaddr.h"
#include "output_to_htlc.h"
#include "p2p_announce.h"
#include "packets.h"
#include "pay.h"
#include "peer.h"
#include "permute_tx.h"
#include "protobuf_convert.h"
#include "pseudorand.h"
#include "remove_dust.h"
#include "routing.h"
#include "secrets.h"
#include "sphinx.h"
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
#include <netdb.h>
#include <netinet/in.h>
#include <sodium/randombytes.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

struct json_connecting {
	/* This owns us, so we're freed after command_fail or command_success */
	struct command *cmd;
	const char *name, *port;
	struct anchor_input *input;
};

static bool command_htlc_set_fail(struct peer *peer, struct htlc *htlc,
				  enum fail_error error_code, const char *why);
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

	db_add_commit_map(peer, txid, commit_num);
}

/* Create a bitcoin close tx, using last signature they sent. */
static const struct bitcoin_tx *mk_bitcoin_close(const tal_t *ctx,
						 struct peer *peer)
{
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature our_close_sig;

	close_tx = peer_create_close_tx(ctx, peer, peer->closing.their_fee);

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
						      NULL, 0, &sig,
						      witnessscript);

	return tx;
}

/* Sign and local commit tx */
static void sign_commit_tx(struct peer *peer)
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

struct peer *find_peer_by_pkhash(struct lightningd_state *dstate, const u8 *pkhash)
{
	struct peer *peer;
	u8 addr[20];

	list_for_each(&dstate->peers, peer, list) {
		pubkey_hash160(addr, peer->id);
		if (memcmp(addr, pkhash, sizeof(addr)) == 0)
			return peer;
	}
	return NULL;
}

void debug_dump_peers(struct lightningd_state *dstate)
{
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list) {
		if (!peer->local.commit
		    || !peer->remote.commit)
			continue;
		log_debug_struct(peer->log, "our cstate: %s",
				 struct channel_state,
				 peer->local.commit->cstate);
		log_debug_struct(peer->log, "their cstate: %s",
				 struct channel_state,
				 peer->remote.commit->cstate);
	}
}

static struct peer *find_peer_json(struct lightningd_state *dstate,
			      const char *buffer,
			      jsmntok_t *peeridtok)
{
	struct pubkey peerid;

	if (!pubkey_from_hexstr(buffer + peeridtok->start,
				peeridtok->end - peeridtok->start, &peerid))
		return NULL;

	return find_peer(dstate, &peerid);
}

static bool peer_uncommitted_changes(const struct peer *peer)
{
	struct htlc_map_iter it;
	struct htlc *h;
	enum feechange_state i;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (htlc_has(h, HTLC_REMOTE_F_PENDING))
			return true;
	}
	/* Pending feechange we sent, or pending ack of theirs. */
	for (i = 0; i < ARRAY_SIZE(peer->feechanges); i++) {
		if (!peer->feechanges[i])
			continue;
		if (feechange_state_flags(i) & HTLC_REMOTE_F_PENDING)
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

/* FIXME: Split success and fail functions, roll state changes etc into
 * success case. */
static void peer_open_complete(struct peer *peer, const char *problem)
{
	if (problem) {
		log_unusual(peer->log, "peer open failed: %s", problem);
		if (peer->open_jsoncmd)  {
			command_fail(peer->open_jsoncmd, "%s", problem);
			peer->open_jsoncmd = NULL;
		}
	} else {
		log_debug(peer->log, "peer open complete");
		assert(!peer->nc);
		/* We're connected, so record it. */
		peer->nc = add_connection(peer->dstate,
					  &peer->dstate->id, peer->id,
					  peer->dstate->config.fee_base,
					  peer->dstate->config.fee_per_satoshi,
					  peer->dstate->config.min_htlc_expiry,
					  peer->dstate->config.min_htlc_expiry);
		if (peer->open_jsoncmd) {
			struct json_result *response;
			response = new_json_result(peer->open_jsoncmd);

			json_object_start(response, NULL);
			json_add_pubkey(response, "id", peer->id);
			json_object_end(response);
			command_success(peer->open_jsoncmd, response);
			peer->open_jsoncmd = NULL;
		}
	}
}

static void set_peer_state(struct peer *peer, enum state newstate,
			   const char *caller, bool db_commit)
{
	log_debug(peer->log, "%s: %s => %s", caller,
		  state_name(peer->state), state_name(newstate));
	peer->state = newstate;

	/* We can only route in normal state. */
	if (!state_is_normal(peer->state))
		peer->nc = tal_free(peer->nc);

	if (db_commit)
		db_update_state(peer);
}

static void peer_breakdown(struct peer *peer)
{
	if (peer->commit_jsoncmd) {
		command_fail(peer->commit_jsoncmd, "peer breakdown");
		peer->commit_jsoncmd = NULL;
	}

	/* FIXME: Reason. */
	if (peer->open_jsoncmd)  {
		command_fail(peer->open_jsoncmd, "peer breakdown");
		peer->open_jsoncmd = NULL;
	}

	/* If we have a closing tx, use it. */
	if (peer->closing.their_sig) {
		const struct bitcoin_tx *close = mk_bitcoin_close(peer, peer);
		log_unusual(peer->log, "Peer breakdown: sending close tx");
		broadcast_tx(peer, close, NULL);
		tal_free(close);
	/* If we have a signed commit tx (maybe not if we just offered
	 * anchor, or they supplied anchor, or no outputs to us). */
	} else if (peer->local.commit && peer->local.commit->sig) {
		log_unusual(peer->log, "Peer breakdown: sending commit tx");
		sign_commit_tx(peer);
		broadcast_tx(peer, peer->local.commit->tx, NULL);
	} else {
		log_info(peer->log, "Peer breakdown: nothing to do");
		/* We close immediately. */
		set_peer_state(peer, STATE_CLOSED, __func__, false);
		db_forget_peer(peer);
	}

	/* Always wake peer to close or flush packets. */
	io_wake(peer);
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

static void peer_calculate_close_fee(struct peer *peer)
{
	/* Use actual worst-case length of close tx: based on FIXME-OLD#02's
	 * commitment tx numbers, but only 1 byte for output count */
	const uint64_t txsize = 41 + 221 + 10 + 32 + 32;
	uint64_t maxfee;

	peer->closing.our_fee
		= fee_by_feerate(txsize, get_feerate(peer->dstate));

	/* FIXME-OLD #2:
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

static void start_closing_in_transaction(struct peer *peer)
{
	assert(!committed_to_htlcs(peer));

	set_peer_state(peer, STATE_MUTUAL_CLOSING, __func__, true);

	peer_calculate_close_fee(peer);
	peer->closing.closing_order = peer->order_counter++;
	db_update_our_closing(peer);
	queue_pkt_close_signature(peer);
}

static struct io_plan *peer_close(struct io_conn *conn, struct peer *peer)
{
	/* Tell writer to wrap it up (may have to xmit first) */
	io_wake(peer);
	/* We do nothing more. */
	return io_wait(conn, NULL, io_never, NULL);
}

void peer_fail(struct peer *peer, const char *caller)
{
	/* Don't fail twice. */
	if (state_is_error(peer->state) || state_is_onchain(peer->state))
		return;

	/* FIXME: Save state here? */
	set_peer_state(peer, STATE_ERR_BREAKDOWN, caller, false);
	peer_breakdown(peer);
}

/* Communication failed: send err (if non-NULL), then dump to chain and close. */
static bool peer_comms_err(struct peer *peer, Pkt *err)
{
	if (err)
		queue_pkt_err(peer, err);

	peer_fail(peer, __func__);
	return false;
}

static bool peer_database_err(struct peer *peer)
{
	return peer_comms_err(peer, pkt_err(peer, "database error"));
}

/* Unexpected packet received: stop listening, send error, start
 * breakdown procedure, return false. */
static bool peer_received_unexpected_pkt(struct peer *peer, const Pkt *pkt,
					 const char *where)
{
	const char *p;
	Pkt *err;

	log_unusual(peer->log, "%s: received unexpected pkt %u (%s) in %s",
		    where, pkt->pkt_case, pkt_name(pkt->pkt_case),
		    state_name(peer->state));

	if (pkt->pkt_case != PKT__PKT_ERROR) {
		err = pkt_err_unexpected(peer, pkt);
		goto out;
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST fail the connection if it receives an `err`
	 * message, and MUST NOT send an `err` message in this case.
	 * For other connection failures, a node SHOULD send an
	 * informative `err` message.
	 */
	err = NULL;

	/* Check packet for weird chars. */
	for (p = pkt->error->problem; *p; p++) {
		if (cisprint(*p))
			continue;

		p = tal_hexstr(peer, pkt->error->problem,
			       strlen(pkt->error->problem));
		log_unusual(peer->log, "Error pkt (hex) %s", p);
		tal_free(p);
		goto out;
	}
	log_unusual(peer->log, "Error pkt '%s'", pkt->error->problem);

out:
	return peer_comms_err(peer, err);
}

/* Creation the bitcoin anchor tx, spending output user provided. */
static bool bitcoin_create_anchor(struct peer *peer)
{
	struct bitcoin_tx *tx = bitcoin_tx(peer, 1, 1);
	size_t i;

	/* We must be offering anchor for us to try creating it */
	assert(peer->local.offer_anchor);

	tx->output[0].script = scriptpubkey_p2wsh(tx, peer->anchor.witnessscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	tx->output[0].amount = peer->anchor.input->out_amount;

	tx->input[0].txid = peer->anchor.input->txid;
	tx->input[0].index = peer->anchor.input->index;
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &peer->anchor.input->in_amount);

	if (!wallet_add_signed_input(peer->dstate,
				     &peer->anchor.input->walletkey,
				     tx, 0))
		return false;

	bitcoin_txid(tx, &peer->anchor.txid);
	peer->anchor.tx = tx;
	peer->anchor.index = 0;
	/* We'll need this later, when we're told to broadcast it. */
	peer->anchor.satoshis = tx->output[0].amount;

	/* To avoid malleation, all inputs must be segwit! */
	for (i = 0; i < tx->input_count; i++)
		assert(tx->input[i].witness);
	return true;
}

static bool open_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err;
	struct commit_info *ci;

	assert(peer->state == STATE_OPEN_WAIT_FOR_OPENPKT);

	if (pkt->pkt_case != PKT__PKT_OPEN)
		return peer_received_unexpected_pkt(peer, pkt, __func__);

	db_start_transaction(peer);
	ci = new_commit_info(peer, 0);

	err = accept_pkt_open(peer, pkt, &ci->revocation_hash,
			      &peer->remote.next_revocation_hash);
	if (err) {
		db_abort_transaction(peer);
		return peer_comms_err(peer, err);
	}

	db_set_visible_state(peer);

	/* Set up their commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->remote.commit = ci;

	/* Witness script for anchor. */
	peer->anchor.witnessscript
		= bitcoin_redeem_2of2(peer,
				      &peer->local.commitkey,
				      &peer->remote.commitkey);

	if (peer->local.offer_anchor) {
		if (!bitcoin_create_anchor(peer)) {
			db_abort_transaction(peer);
			err = pkt_err(peer, "Own anchor unavailable");
			return peer_comms_err(peer, err);
		}
		/* FIXME: Redundant with peer->local.offer_anchor? */
		peer->anchor.ours = true;

		/* This shouldn't happen! */
		if (!setup_first_commit(peer)) {
			db_abort_transaction(peer);
			err = pkt_err(peer, "Own anchor has insufficient funds");
			return peer_comms_err(peer, err);
		}
		set_peer_state(peer,  STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT,
			       __func__, true);
		if (db_commit_transaction(peer) != NULL)
			return peer_database_err(peer);
		queue_pkt_anchor(peer);
		return true;
	} else {
		set_peer_state(peer,  STATE_OPEN_WAIT_FOR_ANCHORPKT,
			       __func__, true);
		if (db_commit_transaction(peer) != NULL)
			return peer_database_err(peer);
		return true;
	}
}

static void funding_tx_failed(struct peer *peer,
			      int exitstatus,
			      const char *err)
{
	const char *str = tal_fmt(peer, "Broadcasting funding gave %i: %s",
				  exitstatus, err);

	peer_open_complete(peer, str);
	peer_breakdown(peer);
	queue_pkt_err(peer, pkt_err(peer, "Funding failed"));
}

static bool open_ouranchor_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err;

	if (pkt->pkt_case != PKT__PKT_OPEN_COMMIT_SIG)
		return peer_received_unexpected_pkt(peer, pkt, __func__);

	peer->local.commit->sig = tal(peer->local.commit,
				      struct bitcoin_signature);
	err = accept_pkt_open_commit_sig(peer, pkt,
					 peer->local.commit->sig);
	if (!err &&
	    !check_tx_sig(peer->local.commit->tx, 0,
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->remote.commitkey,
			  peer->local.commit->sig))
		err = pkt_err(peer, "Bad signature");

	if (err) {
		peer->local.commit->sig = tal_free(peer->local.commit->sig);
		return peer_comms_err(peer, err);
	}

	peer->their_commitsigs++;

	db_start_transaction(peer);
	db_set_anchor(peer);
	db_new_commit_info(peer, LOCAL, NULL);
	set_peer_state(peer,
		       STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE,
		       __func__, true);
	if (db_commit_transaction(peer) != NULL)
		return peer_database_err(peer);

	broadcast_tx(peer, peer->anchor.tx, funding_tx_failed);
	peer_watch_anchor(peer, peer->local.mindepth);
	return true;
}


static bool open_theiranchor_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err;
	const char *db_err;

	if (pkt->pkt_case != PKT__PKT_OPEN_ANCHOR)
		return peer_received_unexpected_pkt(peer, pkt, __func__);

	err = accept_pkt_anchor(peer, pkt);
	if (err) {
		peer_open_complete(peer, err->error->problem);
		return peer_comms_err(peer, err);
	}

	peer->anchor.ours = false;
	if (!setup_first_commit(peer)) {
		err = pkt_err(peer, "Insufficient funds for fee");
		peer_open_complete(peer, err->error->problem);
		return peer_comms_err(peer, err);
	}

	log_debug_struct(peer->log, "Creating sig for %s",
			 struct bitcoin_tx,
			 peer->remote.commit->tx);
	log_add_struct(peer->log, " using key %s",
		       struct pubkey, &peer->local.commitkey);

	peer->remote.commit->sig = tal(peer->remote.commit,
				       struct bitcoin_signature);
	peer->remote.commit->sig->stype = SIGHASH_ALL;
	peer_sign_theircommit(peer, peer->remote.commit->tx,
			      &peer->remote.commit->sig->sig);

	peer->remote.commit->order = peer->order_counter++;
	db_start_transaction(peer);
	db_set_anchor(peer);
	db_new_commit_info(peer, REMOTE, NULL);
	peer_add_their_commit(peer,
			      &peer->remote.commit->txid,
			      peer->remote.commit->commit_num);
	set_peer_state(peer, STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE,
		       __func__, true);
	db_err = db_commit_transaction(peer);
	if (db_err) {
		peer_open_complete(peer, db_err);
		return peer_database_err(peer);
	}

	queue_pkt_open_commit_sig(peer);
	peer_watch_anchor(peer, peer->local.mindepth);
	return true;
}

static bool open_wait_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err;
	const char *db_err;

	/* If they want to shutdown during this, we do mutual close dance. */
	if (pkt->pkt_case == PKT__PKT_CLOSE_SHUTDOWN) {
		err = accept_pkt_close_shutdown(peer, pkt);
		if (err)
			return peer_comms_err(peer, err);

		peer_open_complete(peer, "Shutdown request received");
		db_start_transaction(peer);
		db_set_their_closing_script(peer);
		start_closing_in_transaction(peer);
		if (db_commit_transaction(peer) != NULL)
			return peer_database_err(peer);

		return false;
	}

	switch (peer->state) {
	case STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE:
	case STATE_OPEN_WAIT_THEIRCOMPLETE:
		if (pkt->pkt_case != PKT__PKT_OPEN_COMPLETE)
			return peer_received_unexpected_pkt(peer, pkt, __func__);

		err = accept_pkt_open_complete(peer, pkt);
		if (err) {
			peer_open_complete(peer, err->error->problem);
			return peer_comms_err(peer, err);
		}

		db_start_transaction(peer);
		if (peer->state == STATE_OPEN_WAIT_THEIRCOMPLETE) {
			peer_open_complete(peer, NULL);
			set_peer_state(peer, STATE_NORMAL, __func__, true);
			announce_channel(peer->dstate, peer);
			sync_routing_table(peer->dstate, peer);
		} else {
			set_peer_state(peer, STATE_OPEN_WAIT_ANCHORDEPTH,
				       __func__, true);
		}

		db_err = db_commit_transaction(peer);
		if (db_err) {
			peer_open_complete(peer, db_err);
			return peer_database_err(peer);
		}
		return true;

	case STATE_OPEN_WAIT_ANCHORDEPTH:
		return peer_received_unexpected_pkt(peer, pkt, __func__);

	default:
		log_unusual(peer->log,
			    "%s: unexpected state %s",
			    __func__, state_name(peer->state));
		peer_fail(peer, __func__);
		return false;
	}
}

static void set_htlc_rval(struct peer *peer,
			  struct htlc *htlc, const struct rval *rval)
{
	assert(!htlc->r);
	assert(!htlc->fail);
	htlc->r = tal_dup(htlc, struct rval, rval);
	db_htlc_fulfilled(peer, htlc);
}

static void set_htlc_fail(struct peer *peer,
			  struct htlc *htlc, const void *fail, size_t len)
{
	assert(!htlc->r);
	assert(!htlc->fail);
	htlc->fail = tal_dup_arr(htlc, u8, fail, len, 0);
	db_htlc_failed(peer, htlc);
}

static void route_htlc_onwards(struct peer *peer,
			       struct htlc *htlc,
			       u64 msatoshi,
			       const u8 *pb_id,
			       const u8 *rest_of_route,
			       const struct peer *only_dest)
{
	struct peer *next;
	struct htlc *newhtlc;
	enum fail_error error_code;
	const char *err;

	if (!only_dest) {
		log_debug_struct(peer->log, "Forwarding HTLC %s",
				 struct sha256, &htlc->rhash);
		log_add(peer->log, " (id %"PRIu64")", htlc->id);
	}

	next = find_peer_by_pkhash(peer->dstate, pb_id);
	if (!next || !next->nc) {
		log_unusual(peer->log, "Can't route HTLC %"PRIu64": no %speer ",
			    htlc->id, next ? "ready " : "");
		if (!peer->dstate->dev_never_routefail)
			command_htlc_set_fail(peer, htlc, NOT_FOUND_404,
					      "Unknown peer");
		return;
	}

	if (only_dest && next != only_dest)
		return;

	/* Offered fee must be sufficient. */
	if ((s64)(htlc->msatoshi - msatoshi)
	    < connection_fee(next->nc, msatoshi)) {
		log_unusual(peer->log,
			    "Insufficient fee for HTLC %"PRIu64
			    ": %"PRIi64" on %"PRIu64,
			    htlc->id, htlc->msatoshi - msatoshi,
			    msatoshi);
		command_htlc_set_fail(peer, htlc, PAYMENT_REQUIRED_402,
				      "Insufficent fee");
		return;
	}

	log_debug_struct(peer->log, "HTLC forward to %s",
			 struct pubkey, next->id);

	/* This checks the HTLC itself is possible. */
	err = command_htlc_add(next, msatoshi,
			       abs_locktime_to_blocks(&htlc->expiry)
			       - next->nc->delay,
			       &htlc->rhash, htlc, rest_of_route,
			       &error_code, &newhtlc);
	if (err)
		command_htlc_set_fail(peer, htlc, error_code, err);
}

static void their_htlc_added(struct peer *peer, struct htlc *htlc,
			     struct peer *only_dest)
{
	struct invoice *invoice;
	struct privkey pk;
	struct onionpacket *packet;
	struct route_step *step = NULL;

	if (abs_locktime_is_seconds(&htlc->expiry)) {
		log_unusual(peer->log, "HTLC %"PRIu64" is in seconds", htlc->id);
		command_htlc_set_fail(peer, htlc, BAD_REQUEST_400,
				      "bad locktime");
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) <=
	    get_block_height(peer->dstate) + peer->dstate->config.min_htlc_expiry) {
		log_unusual(peer->log, "HTLC %"PRIu64" expires too soon:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_set_fail(peer, htlc, BAD_REQUEST_400,
				      "expiry too soon");
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) >
	    get_block_height(peer->dstate) + peer->dstate->config.max_htlc_expiry) {
		log_unusual(peer->log, "HTLC %"PRIu64" expires too far:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_set_fail(peer, htlc, BAD_REQUEST_400,
				      "expiry too far");
		return;
	}

	//FIXME: dirty trick to retrieve unexported state
	memcpy(&pk, peer->dstate->secret, sizeof(pk));
	packet = parse_onionpacket(peer,
				   htlc->routing, tal_count(htlc->routing));
	if (packet)
		step = process_onionpacket(packet, packet, &pk, htlc->rhash.u.u8,
					   sizeof(htlc->rhash));

	if (!step) {
		log_unusual(peer->log, "Bad onion, failing HTLC %"PRIu64,
			    htlc->id);
		command_htlc_set_fail(peer, htlc, BAD_REQUEST_400,
				      "invalid onion");
		goto free_packet;
	}

	switch (step->nextcase) {
	case ONION_END:
		if (only_dest)
			goto free_packet;
		invoice = find_unpaid(peer->dstate->invoices, &htlc->rhash);
		if (!invoice) {
			log_unusual(peer->log, "No invoice for HTLC %"PRIu64,
				    htlc->id);
			log_add_struct(peer->log, " rhash=%s",
				       struct sha256, &htlc->rhash);
			if (unlikely(!peer->dstate->dev_never_routefail))
				command_htlc_set_fail(peer, htlc,
						      UNAUTHORIZED_401,
						      "unknown rhash");
			goto free_packet;
		}

		if (htlc->msatoshi != invoice->msatoshi) {
			log_unusual(peer->log, "Short payment for '%s' HTLC %"PRIu64
				    ": %"PRIu64" not %"PRIu64 " satoshi!",
				    invoice->label,
				    htlc->id,
				    htlc->msatoshi,
				    invoice->msatoshi);
			command_htlc_set_fail(peer, htlc,
					      UNAUTHORIZED_401,
					      "incorrect amount");
			goto free_packet;
		}

		log_info(peer->log, "Immediately resolving '%s' HTLC %"PRIu64,
			 invoice->label, htlc->id);

		resolve_invoice(peer->dstate, invoice);
		set_htlc_rval(peer, htlc, &invoice->r);
		command_htlc_fulfill(peer, htlc);
		goto free_packet;

	case ONION_FORWARD:
		route_htlc_onwards(peer, htlc, step->hoppayload->amount, step->next->nexthop,
				   serialize_onionpacket(step, step->next), only_dest);
		goto free_packet;
	default:
		log_info(peer->log, "Unknown step type %u", step->nextcase);
		command_htlc_set_fail(peer, htlc, VERSION_NOT_SUPPORTED_505,
				      "unknown step type");
		goto free_packet;
	}

free_packet:
	tal_free(packet);
}

static void our_htlc_failed(struct peer *peer, struct htlc *htlc)
{
	assert(htlc_owner(htlc) == LOCAL);
	if (htlc->src) {
		set_htlc_fail(htlc->src->peer, htlc->src,
			      htlc->fail, tal_count(htlc->fail));
		command_htlc_fail(htlc->src->peer, htlc->src);
	} else
		complete_pay_command(peer->dstate, htlc);
}

static void our_htlc_fulfilled(struct peer *peer, struct htlc *htlc)
{
	if (htlc->src) {
		set_htlc_rval(htlc->src->peer, htlc->src, htlc->r);
		command_htlc_fulfill(htlc->src->peer, htlc->src);
	} else {
		complete_pay_command(peer->dstate, htlc);
	}
}

/* FIXME: Slow! */
static struct htlc *htlc_with_source(struct peer *peer, struct htlc *src)
{
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (h->src == src)
			return h;
	}
	return NULL;
}

/* peer has come back online: re-send any we have to send to them. */
static void retry_all_routing(struct peer *restarted_peer)
{
	struct peer *peer;
	struct htlc_map_iter it;
	struct htlc *h;

	/* Look for added htlcs from other peers which need to go here. */
	list_for_each(&restarted_peer->dstate->peers, peer, list) {
		if (peer == restarted_peer)
			continue;

		for (h = htlc_map_first(&peer->htlcs, &it);
		     h;
		     h = htlc_map_next(&peer->htlcs, &it)) {
			if (h->state != RCVD_ADD_ACK_REVOCATION)
				continue;
			if (htlc_with_source(peer, h))
				continue;
			their_htlc_added(peer, h, restarted_peer);
		}
	}

	/* Catch any HTLCs which are fulfilled, but the message got reset
	 * by reconnect. */
	for (h = htlc_map_first(&restarted_peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&restarted_peer->htlcs, &it)) {
		if (h->state != RCVD_ADD_ACK_REVOCATION)
			continue;
		if (h->r)
			command_htlc_fulfill(restarted_peer, h);
		else if (h->fail)
			command_htlc_fail(restarted_peer, h);
	}
}

static bool adjust_cstate_side(struct channel_state *cstate,
			       struct htlc *h,
			       enum htlc_state old, enum htlc_state new,
			       enum side side)
{
	int oldf = htlc_state_flags(old), newf = htlc_state_flags(new);
	bool old_committed, new_committed;

	/* We applied changes to staging_cstate when we first received
	 * add/remove packet, so we could make sure it was valid.  Don't
	 * do that again. */
	if (old == SENT_ADD_HTLC || old == RCVD_REMOVE_HTLC
	    || old == RCVD_ADD_HTLC || old == SENT_REMOVE_HTLC)
		return true;

	old_committed = (oldf & HTLC_FLAG(side, HTLC_F_COMMITTED));
	new_committed = (newf & HTLC_FLAG(side, HTLC_F_COMMITTED));

	if (old_committed && !new_committed) {
		if (h->r)
			cstate_fulfill_htlc(cstate, h);
		else
			cstate_fail_htlc(cstate, h);
	} else if (!old_committed && new_committed) {
		if (!cstate_add_htlc(cstate, h, false)) {
			log_broken_struct(h->peer->log,
					  "Cannot afford htlc %s",
					  struct htlc, h);
			log_add_struct(h->peer->log, " channel state %s",
				       struct channel_state, cstate);
			return false;
		}
	}
	return true;
}

/* We apply changes to staging_cstate when we first PENDING, so we can
 * make sure they're valid.  So here we change the staging_cstate on
 * the revocation receive (ie. when acked). */
static bool adjust_cstates(struct peer *peer, struct htlc *h,
			   enum htlc_state old, enum htlc_state new)
{
	return adjust_cstate_side(peer->remote.staging_cstate, h, old, new,
				  REMOTE)
		&& adjust_cstate_side(peer->local.staging_cstate, h, old, new,
				      LOCAL);
}

static void adjust_cstate_fee_side(struct channel_state *cstate,
				   const struct feechange *f,
				   enum feechange_state old,
				   enum feechange_state new,
				   enum side side)
{
	/* We applied changes to staging_cstate when we first received
	 * feechange packet, so we could make sure it was valid.  Don't
	 * do that again. */
	if (old == SENT_FEECHANGE || old == RCVD_FEECHANGE)
		return;

	/* Feechanges only ever get applied to the side which created them:
	 * ours gets applied when they ack, theirs gets applied when we ack. */
	if (side == LOCAL && new == RCVD_FEECHANGE_REVOCATION)
		adjust_fee(cstate, f->fee_rate);
	else if (side == REMOTE && new == SENT_FEECHANGE_REVOCATION)
		adjust_fee(cstate, f->fee_rate);
}

static void adjust_cstates_fee(struct peer *peer, const struct feechange *f,
			       enum feechange_state old,
			       enum feechange_state new)
{
	adjust_cstate_fee_side(peer->remote.staging_cstate, f, old, new, REMOTE);
	adjust_cstate_fee_side(peer->local.staging_cstate, f, old, new, LOCAL);
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
		if (h->fail)
			our_htlc_failed(peer, h);
		break;
	case RCVD_ADD_ACK_REVOCATION:
		their_htlc_added(peer, h, NULL);
		break;
	default:
		break;
	}
}

struct htlcs_table {
	enum htlc_state from, to;
};

struct feechanges_table {
	enum feechange_state from, to;
};

static const char *changestates(struct peer *peer,
				const struct htlcs_table *table,
				size_t n,
				const struct feechanges_table *ftable,
				size_t n_ftable,
				bool db_commit)
{
	struct htlc_map_iter it;
	struct htlc *h;
	bool changed = false;
	size_t i;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		for (i = 0; i < n; i++) {
			if (h->state == table[i].from) {
				if (!adjust_cstates(peer, h,
						    table[i].from, table[i].to))
					return "accounting error";
				htlc_changestate(h, table[i].from,
						 table[i].to, db_commit);
				check_both_committed(peer, h);
				changed = true;
			}
		}
	}

	for (i = 0; i < n_ftable; i++) {
		struct feechange *f = peer->feechanges[ftable[i].from];
		if (!f)
			continue;
		adjust_cstates_fee(peer, f, ftable[i].from, ftable[i].to);
		feechange_changestate(peer, f,
				      ftable[i].from, ftable[i].to,
				      db_commit);
		changed = true;
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (!changed)
		return "no changes made";
	return NULL;
}

/* This is the io loop while we're negotiating closing tx. */
static bool closing_pkt_in(struct peer *peer, const Pkt *pkt)
{
	const CloseSignature *c = pkt->close_signature;
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature theirsig;

	assert(peer->state == STATE_MUTUAL_CLOSING);

	if (pkt->pkt_case != PKT__PKT_CLOSE_SIGNATURE)
		return peer_received_unexpected_pkt(peer, pkt, __func__);

	log_info(peer->log, "closing_pkt_in: they offered close fee %"PRIu64,
		 c->close_fee);

	/* FIXME-OLD #2:
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

	/* FIXME-OLD #2:
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

	/* FIXME-OLD #2:
	 *
	 * The receiver MUST check `sig` is valid for the close
	 * transaction with the given `close_fee`, and MUST fail the
	 * connection if it is not. */
	theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(c->sig, &theirsig.sig))
		return peer_comms_err(peer,
				      pkt_err(peer, "Invalid signature format"));

	close_tx = peer_create_close_tx(c, peer, c->close_fee);
	if (!check_tx_sig(close_tx, 0,
			  NULL, 0,
			  peer->anchor.witnessscript,
			  &peer->remote.commitkey, &theirsig))
		return peer_comms_err(peer,
				      pkt_err(peer, "Invalid signature"));

	tal_free(peer->closing.their_sig);
	peer->closing.their_sig = tal_dup(peer,
					  struct bitcoin_signature, &theirsig);
	peer->closing.their_fee = c->close_fee;
	peer->closing.sigs_in++;

	if (!db_update_their_closing(peer))
		return peer_database_err(peer);

	if (peer->closing.our_fee != peer->closing.their_fee) {
		/* FIXME-OLD #2:
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

		peer->closing.closing_order = peer->order_counter++;

		db_start_transaction(peer);
		db_update_our_closing(peer);
		if (db_commit_transaction(peer) != NULL)
			return peer_database_err(peer);

		queue_pkt_close_signature(peer);
	}

	/* Note corner case: we may *now* agree with them! */
	if (peer->closing.our_fee == peer->closing.their_fee) {
		const struct bitcoin_tx *close;
		log_info(peer->log, "accept_pkt_close_sig: we agree");
		/* FIXME-OLD #2:
		 *
		 * Once a node has sent or received a `close_signature` with
		 * matching `close_fee` it SHOULD close the connection and
		 * SHOULD sign and broadcast the final closing transaction.
		 */
		close = mk_bitcoin_close(peer, peer);
		broadcast_tx(peer, close, NULL);
		tal_free(close);
		return false;
	}

	return true;
}

/* We can get update_commit in both normal and shutdown states. */
static Pkt *handle_pkt_commit(struct peer *peer, const Pkt *pkt)
{
	Pkt *err;
	const char *errmsg;
	struct sha256 preimage;
	struct commit_info *ci;
	bool to_them_only;
	/* FIXME: We can actually merge these two... */
	static const struct htlcs_table commit_changes[] = {
		{ RCVD_ADD_REVOCATION, RCVD_ADD_ACK_COMMIT },
		{ RCVD_REMOVE_HTLC, RCVD_REMOVE_COMMIT },
		{ RCVD_ADD_HTLC, RCVD_ADD_COMMIT },
		{ RCVD_REMOVE_REVOCATION, RCVD_REMOVE_ACK_COMMIT }
	};
	static const struct feechanges_table commit_feechanges[] = {
		{ RCVD_FEECHANGE_REVOCATION, RCVD_FEECHANGE_ACK_COMMIT },
		{ RCVD_FEECHANGE, RCVD_FEECHANGE_COMMIT }
	};
	static const struct htlcs_table revocation_changes[] = {
		{ RCVD_ADD_ACK_COMMIT, SENT_ADD_ACK_REVOCATION },
		{ RCVD_REMOVE_COMMIT, SENT_REMOVE_REVOCATION },
		{ RCVD_ADD_COMMIT, SENT_ADD_REVOCATION },
		{ RCVD_REMOVE_ACK_COMMIT, SENT_REMOVE_ACK_REVOCATION }
	};
	static const struct feechanges_table revocation_feechanges[] = {
		{ RCVD_FEECHANGE_ACK_COMMIT, SENT_FEECHANGE_ACK_REVOCATION },
		{ RCVD_FEECHANGE_COMMIT, SENT_FEECHANGE_REVOCATION }
	};

	ci = new_commit_info(peer, peer->local.commit->commit_num + 1);

	db_start_transaction(peer);

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	errmsg = changestates(peer,
			      commit_changes, ARRAY_SIZE(commit_changes),
			      commit_feechanges, ARRAY_SIZE(commit_feechanges),
			      true);
	if (errmsg) {
		db_abort_transaction(peer);
		return pkt_err(peer, "%s", errmsg);
	}

	/* Create new commit info for this commit tx. */
	ci->revocation_hash = peer->local.next_revocation_hash;

	/* FIXME-OLD #2:
	 *
	 * A receiving node MUST apply all local acked and unacked
	 * changes except unacked fee changes to the local commitment
	 */
	/* (We already applied them to staging_cstate as we went) */
	ci->cstate = copy_cstate(ci, peer->local.staging_cstate);
	ci->tx = create_commit_tx(ci, peer, &ci->revocation_hash,
				  ci->cstate, LOCAL, &to_them_only);
	bitcoin_txid(ci->tx, &ci->txid);

	log_debug(peer->log, "Check tx %"PRIu64" sig", ci->commit_num);
	log_add_struct(peer->log, " for %s", struct channel_state, ci->cstate);
	log_add_struct(peer->log, " (txid %s)", struct sha256_double, &ci->txid);

	/* FIXME-OLD #2:
	 *
	 * If the commitment transaction has only a single output which pays
	 * to the other node, `sig` MUST be unset.  Otherwise, a sending node
	 * MUST apply all remote acked and unacked changes except unacked fee
	 * changes to the remote commitment before generating `sig`.
	 */
	if (!to_them_only)
		ci->sig = tal(ci, struct bitcoin_signature);

	err = accept_pkt_commit(peer, pkt, ci->sig);
	if (err)
		return err;

	/* FIXME-OLD #2:
	 *
	 * A receiving node MUST apply all local acked and unacked changes
	 * except unacked fee changes to the local commitment, then it MUST
	 * check `sig` is valid for that transaction.
	 */
	if (ci->sig && !check_tx_sig(ci->tx, 0,
				     NULL, 0,
				     peer->anchor.witnessscript,
				     &peer->remote.commitkey,
				     ci->sig)) {
		db_abort_transaction(peer);
		return pkt_err(peer, "Bad signature");
	}

	/* Switch to the new commitment. */
	tal_free(peer->local.commit);
	peer->local.commit = ci;
	peer->local.commit->order = peer->order_counter++;

	db_new_commit_info(peer, LOCAL, NULL);
	peer_get_revocation_hash(peer, ci->commit_num + 1,
				 &peer->local.next_revocation_hash);
	peer->their_commitsigs++;

	/* Now, send the revocation. */

	/* We have their signature on the current one, right? */
	assert(to_them_only || peer->local.commit->sig);
	assert(peer->local.commit->commit_num > 0);

	errmsg = changestates(peer,
			      revocation_changes, ARRAY_SIZE(revocation_changes),
			      revocation_feechanges,
			      ARRAY_SIZE(revocation_feechanges),
			      true);
	if (errmsg) {
		log_broken(peer->log, "queue_pkt_revocation: %s", errmsg);
		db_abort_transaction(peer);
		return pkt_err(peer, "Database error");
	}

	peer_get_revocation_preimage(peer, peer->local.commit->commit_num - 1,
				     &preimage);

	/* Fire off timer if this ack caused new changes */
	if (peer_uncommitted_changes(peer))
		remote_changes_pending(peer);

	queue_pkt_revocation(peer, &preimage, &peer->local.next_revocation_hash);

	/* If we're shutting down and no more HTLCs, begin closing */
	if (peer->closing.their_script && !committed_to_htlcs(peer))
		start_closing_in_transaction(peer);

	if (db_commit_transaction(peer) != NULL)
		return pkt_err(peer, "Database error");

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

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT offer `amount_msat` it cannot pay for in
	 * the remote commitment transaction at the current `fee_rate` (see
	 * "Fee Calculation" ).  A node SHOULD fail the connection if
	 * this occurs.
	 */
	if (!cstate_add_htlc(peer->local.staging_cstate, htlc, true)) {
		u64 id = htlc->id;
		log_broken_struct(peer->log, "They cannot afford htlc %s",
				  struct htlc, htlc);
		log_add_struct(peer->log, " cstate %s",
			       struct channel_state,
			       peer->local.staging_cstate);
		tal_free(htlc);
		return pkt_err(peer, "Cannot afford htlc %"PRIu64, id);
	}
	return NULL;
}

static Pkt *handle_pkt_htlc_fail(struct peer *peer, const Pkt *pkt)
{
	struct htlc *htlc;
	u8 *fail;
	Pkt *err;

	err = accept_pkt_htlc_fail(peer, pkt, &htlc, &fail);
	if (err)
		return err;

	/* This can happen with re-transmissions; simply note it. */
	if (htlc->fail) {
		log_debug(peer->log, "HTLC %"PRIu64" failed twice", htlc->id);
		htlc->fail = tal_free(htlc->fail);
	}

	db_start_transaction(peer);

	set_htlc_fail(peer, htlc, fail, tal_count(fail));
	tal_free(fail);

	if (db_commit_transaction(peer) != NULL)
		return pkt_err(peer, "database error");

	cstate_fail_htlc(peer->local.staging_cstate, htlc);

	/* FIXME-OLD #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	htlc_changestate(htlc, SENT_ADD_ACK_REVOCATION, RCVD_REMOVE_HTLC, false);
	return NULL;
}

static Pkt *handle_pkt_htlc_fulfill(struct peer *peer, const Pkt *pkt)
{
	struct htlc *htlc;
	Pkt *err;
	struct rval r;

	err = accept_pkt_htlc_fulfill(peer, pkt, &htlc, &r);
	if (err)
		return err;

	/* Reconnect may mean HTLC was already fulfilled.  That's OK. */
	if (!htlc->r) {
		db_start_transaction(peer);
		set_htlc_rval(peer, htlc, &r);

		/* We can relay this upstream immediately. */
		our_htlc_fulfilled(peer, htlc);
		if (db_commit_transaction(peer) != NULL)
			return pkt_err(peer, "database error");
	}

	/* FIXME-OLD #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	cstate_fulfill_htlc(peer->local.staging_cstate, htlc);
	htlc_changestate(htlc, SENT_ADD_ACK_REVOCATION, RCVD_REMOVE_HTLC, false);
	return NULL;
}

static void set_feechange(struct peer *peer, u64 fee_rate,
			  enum feechange_state state)
{
	/* If we already have a feechange for this commit, simply update it. */
	if (peer->feechanges[state]) {
		log_debug(peer->log, "Feechange: fee %"PRIu64" to %"PRIu64,
			  peer->feechanges[state]->fee_rate,
			  fee_rate);
		peer->feechanges[state]->fee_rate = fee_rate;
	} else {
		log_debug(peer->log, "Feechange: New fee %"PRIu64, fee_rate);
		peer->feechanges[state] = new_feechange(peer, fee_rate, state);
	}
}

static Pkt *handle_pkt_feechange(struct peer *peer, const Pkt *pkt)
{
	u64 feerate;
	Pkt *err;

	err = accept_pkt_update_fee(peer, pkt, &feerate);
	if (err)
		return err;

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST NOT send a `fee_rate` which it could not
	 * afford (see "Fee Calculation), were it applied to the receiving
	 * node's commitment transaction.  The receiving node SHOULD fail the
	 * connection if this occurs.
	 */
	if (!can_afford_feerate(peer->local.staging_cstate, feerate, REMOTE))
		return pkt_err(peer, "Cannot afford feerate %"PRIu64,
			       feerate);

	set_feechange(peer, feerate, RCVD_FEECHANGE);
	return NULL;
}

static Pkt *handle_pkt_revocation(struct peer *peer, const Pkt *pkt,
				  enum state next_state)
{
	Pkt *err;
	const char *errmsg;
	static const struct htlcs_table changes[] = {
		{ SENT_ADD_COMMIT, RCVD_ADD_REVOCATION },
		{ SENT_REMOVE_ACK_COMMIT, RCVD_REMOVE_ACK_REVOCATION },
		{ SENT_ADD_ACK_COMMIT, RCVD_ADD_ACK_REVOCATION },
		{ SENT_REMOVE_COMMIT, RCVD_REMOVE_REVOCATION }
	};
	static const struct feechanges_table feechanges[] = {
		{ SENT_FEECHANGE_COMMIT, RCVD_FEECHANGE_REVOCATION },
		{ SENT_FEECHANGE_ACK_COMMIT, RCVD_FEECHANGE_ACK_REVOCATION }
	};

	err = accept_pkt_revocation(peer, pkt);
	if (err)
		return err;

	/* FIXME-OLD #2:
	 *
	 * The receiver of `update_revocation`... MUST add the remote
	 * unacked changes to the set of local acked changes.
	 */
	db_start_transaction(peer);
	errmsg = changestates(peer, changes, ARRAY_SIZE(changes),
			      feechanges, ARRAY_SIZE(feechanges), true);
	if (errmsg) {
		log_broken(peer->log, "accept_pkt_revocation: %s", errmsg);
		db_abort_transaction(peer);
		return pkt_err(peer, "failure accepting update_revocation: %s",
			       errmsg);
	}
	db_save_shachain(peer);
	db_update_next_revocation_hash(peer);
	set_peer_state(peer, next_state, __func__, true);
	db_remove_their_prev_revocation_hash(peer);

	/* If we're shutting down and no more HTLCs, begin closing */
	if (peer->closing.their_script && !committed_to_htlcs(peer))
		start_closing_in_transaction(peer);

	if (db_commit_transaction(peer) != NULL)
		return pkt_err(peer, "database error");

	return NULL;
}

/* This is the io loop while we're doing shutdown. */
static bool shutdown_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err = NULL;

	assert(peer->state == STATE_SHUTDOWN
	       || peer->state == STATE_SHUTDOWN_COMMITTING);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_REVOCATION:
		if (peer->state == STATE_SHUTDOWN)
			return peer_received_unexpected_pkt(peer, pkt, __func__);
		else {
			err = handle_pkt_revocation(peer, pkt, STATE_SHUTDOWN);
			if (!err)
				peer_update_complete(peer);
		}
		break;

	case PKT__PKT_UPDATE_ADD_HTLC:
		/* FIXME-OLD #2:
		 *
		 * A node MUST NOT send a `update_add_htlc` after a
		 * `close_shutdown` */
		if (peer->closing.their_script)
			err = pkt_err(peer, "Update during shutdown");
		else
			err = handle_pkt_htlc_add(peer, pkt);
		break;

	case PKT__PKT_CLOSE_SHUTDOWN:
		/* FIXME-OLD #2:
		 *
		 * A node... MUST NOT send more than one `close_shutdown`. */
		if (peer->closing.their_script)
			return peer_received_unexpected_pkt(peer, pkt, __func__);
		else {
			err = accept_pkt_close_shutdown(peer, pkt);
			if (!err) {
				db_start_transaction(peer);
				db_set_their_closing_script(peer);
				/* If no more HTLCs, we're closing. */
				if (!committed_to_htlcs(peer))
					start_closing_in_transaction(peer);
				if (db_commit_transaction(peer) != NULL)
					err = pkt_err(peer, "database error");
			}
		}
		break;

	case PKT__PKT_UPDATE_FULFILL_HTLC:
		err = handle_pkt_htlc_fulfill(peer, pkt);
		break;
	case PKT__PKT_UPDATE_FAIL_HTLC:
		err = handle_pkt_htlc_fail(peer, pkt);
		break;
	case PKT__PKT_UPDATE_FEE:
		err = handle_pkt_feechange(peer, pkt);
		break;
	case PKT__PKT_UPDATE_COMMIT:
		err = handle_pkt_commit(peer, pkt);
		break;
	case PKT__PKT_ERROR:
		return peer_received_unexpected_pkt(peer, pkt, __func__);

	case PKT__PKT_AUTH:
	case PKT__PKT_OPEN:
	case PKT__PKT_OPEN_ANCHOR:
	case PKT__PKT_OPEN_COMMIT_SIG:
	case PKT__PKT_OPEN_COMPLETE:
	case PKT__PKT_CLOSE_SIGNATURE:
	default:
		return peer_received_unexpected_pkt(peer, pkt, __func__);
	}

	if (err)
		return peer_comms_err(peer, err);

	return true;
}

static bool do_commit(struct peer *peer, struct command *jsoncmd)
{
	struct commit_info *ci;
	const char *errmsg;
	static const struct htlcs_table changes[] = {
		{ SENT_ADD_HTLC, SENT_ADD_COMMIT },
		{ SENT_REMOVE_REVOCATION, SENT_REMOVE_ACK_COMMIT },
		{ SENT_ADD_REVOCATION, SENT_ADD_ACK_COMMIT},
		{ SENT_REMOVE_HTLC, SENT_REMOVE_COMMIT}
	};
	static const struct feechanges_table feechanges[] = {
		{ SENT_FEECHANGE, SENT_FEECHANGE_COMMIT },
		{ SENT_FEECHANGE_REVOCATION, SENT_FEECHANGE_ACK_COMMIT}
	};
	bool to_us_only;

	/* We can have changes we suggested, or changes they suggested. */
	if (!peer_uncommitted_changes(peer)) {
		log_debug(peer->log, "do_commit: no changes to commit");
		if (jsoncmd)
			command_fail(jsoncmd, "no changes to commit");
		return true;
	}

	log_debug(peer->log, "do_commit: sending commit command %"PRIu64,
		  peer->remote.commit->commit_num + 1);

	assert(state_can_commit(peer->state));
	assert(!peer->commit_jsoncmd);

	peer->commit_jsoncmd = jsoncmd;
	ci = new_commit_info(peer, peer->remote.commit->commit_num + 1);

	assert(!peer->their_prev_revocation_hash);
	peer->their_prev_revocation_hash
		= tal_dup(peer, struct sha256,
			  &peer->remote.commit->revocation_hash);

	db_start_transaction(peer);

	errmsg = changestates(peer, changes, ARRAY_SIZE(changes),
			      feechanges, ARRAY_SIZE(feechanges), true);
	if (errmsg) {
		log_broken(peer->log, "queue_pkt_commit: %s", errmsg);
		goto database_error;
	}

	/* Create new commit info for this commit tx. */
	ci->revocation_hash = peer->remote.next_revocation_hash;
	/* FIXME-OLD #2:
	 *
	 * ...a sending node MUST apply all remote acked and unacked
	 * changes except unacked fee changes to the remote commitment
	 * before generating `sig`. */
	ci->cstate = copy_cstate(ci, peer->remote.staging_cstate);
	ci->tx = create_commit_tx(ci, peer, &ci->revocation_hash,
				  ci->cstate, REMOTE, &to_us_only);
	bitcoin_txid(ci->tx, &ci->txid);

	if (!to_us_only) {
		log_debug(peer->log, "Signing tx %"PRIu64, ci->commit_num);
		log_add_struct(peer->log, " for %s",
			       struct channel_state, ci->cstate);
		log_add_struct(peer->log, " (txid %s)",
			       struct sha256_double, &ci->txid);

		ci->sig = tal(ci, struct bitcoin_signature);
		ci->sig->stype = SIGHASH_ALL;
		peer_sign_theircommit(peer, ci->tx, &ci->sig->sig);
	}

	/* Switch to the new commitment. */
	tal_free(peer->remote.commit);
	peer->remote.commit = ci;
	peer->remote.commit->order = peer->order_counter++;
	db_new_commit_info(peer, REMOTE, peer->their_prev_revocation_hash);

	/* We don't need to remember their commit if we don't give sig. */
	if (ci->sig)
		peer_add_their_commit(peer, &ci->txid, ci->commit_num);

	if (peer->state == STATE_SHUTDOWN) {
		set_peer_state(peer, STATE_SHUTDOWN_COMMITTING, __func__, true);
	} else {
		assert(peer->state == STATE_NORMAL);
		set_peer_state(peer, STATE_NORMAL_COMMITTING, __func__, true);
	}
	if (db_commit_transaction(peer) != NULL)
		goto database_error;

	queue_pkt_commit(peer, ci->sig);
	return true;

database_error:
	db_abort_transaction(peer);
	peer_fail(peer, __func__);
	return false;
}

static bool peer_start_shutdown(struct peer *peer)
{
	enum state newstate;
	u8 *redeemscript;

	/* We might have uncommited changes; if so, commit them now. */
	if (!do_commit(peer, NULL))
		return false;

	db_start_transaction(peer);

	db_begin_shutdown(peer);

	/* If they started close, we might not have sent ours. */
	assert(!peer->closing.our_script);

	redeemscript = bitcoin_redeem_single(peer, &peer->local.finalkey);

	peer->closing.our_script = scriptpubkey_p2sh(peer, redeemscript);
	tal_free(redeemscript);

	/* FIXME-OLD #2:
	 *
	 * A node SHOULD send a `close_shutdown` (if it has
	 * not already) after receiving `close_shutdown`.
	 */
	peer->closing.shutdown_order = peer->order_counter++;
	db_set_our_closing_script(peer);

	queue_pkt_close_shutdown(peer);

	if (peer->state == STATE_NORMAL_COMMITTING)
		newstate = STATE_SHUTDOWN_COMMITTING;
	else {
		assert(peer->state == STATE_NORMAL);
		newstate = STATE_SHUTDOWN;
	}
	set_peer_state(peer, newstate, __func__, true);

	/* Catch case where we've exchanged and had no HTLCs anyway. */
	if (peer->closing.their_script && !committed_to_htlcs(peer))
		start_closing_in_transaction(peer);

	return db_commit_transaction(peer) == NULL;
}

/* Shim to handle the new packet format until we complete the
 * switch. Handing the protobuf in anyway to fall back on protobuf
 * based error handling. */
static bool nested_pkt_in(struct peer *peer, const u32 type,
				 const u8 *innerpkt, size_t innerpktlen,
				 const Pkt *pkt)
{
	switch (type) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		handle_channel_announcement(peer, innerpkt, innerpktlen);
		break;
	case WIRE_CHANNEL_UPDATE:
		handle_channel_update(peer, innerpkt, innerpktlen);
		break;
	case WIRE_NODE_ANNOUNCEMENT:
		handle_node_announcement(peer, innerpkt, innerpktlen);
		break;
	default:
		/* BOLT01: Unknown even typed packets MUST kill the
		   connection, unknown odd-typed packets MAY be ignored. */
		if (type % 2 == 0){
			return peer_received_unexpected_pkt(peer, pkt, __func__);
		} else {
			log_debug(peer->log, "Ignoring odd typed (%d) unknown packet.", type);
			return true;
		}
	}
	return true;
}

/* This is the io loop while we're in normal mode. */
static bool normal_pkt_in(struct peer *peer, const Pkt *pkt)
{
	Pkt *err = NULL;

	assert(peer->state == STATE_NORMAL
	       || peer->state == STATE_NORMAL_COMMITTING);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_ADD_HTLC:
		err = handle_pkt_htlc_add(peer, pkt);
		break;

	case PKT__PKT_UPDATE_FULFILL_HTLC:
		err = handle_pkt_htlc_fulfill(peer, pkt);
		break;

	case PKT__PKT_UPDATE_FAIL_HTLC:
		err = handle_pkt_htlc_fail(peer, pkt);
		break;

	case PKT__PKT_UPDATE_FEE:
		err = handle_pkt_feechange(peer, pkt);
		break;

	case PKT__PKT_UPDATE_COMMIT:
		err = handle_pkt_commit(peer, pkt);
		break;

	case PKT__PKT_CLOSE_SHUTDOWN:
		err = accept_pkt_close_shutdown(peer, pkt);
		if (err)
			break;
		if (!peer_start_shutdown(peer)) {
			err = pkt_err(peer, "database error");
			break;
		}
		return true;

	case PKT__PKT_UPDATE_REVOCATION:
		if (peer->state == STATE_NORMAL_COMMITTING) {
			err = handle_pkt_revocation(peer, pkt, STATE_NORMAL);
			if (!err)
				peer_update_complete(peer);
			break;
		}
		/* Fall thru. */
	default:
		return peer_received_unexpected_pkt(peer, pkt, __func__);
	}

	if (err) {
		return peer_comms_err(peer, err);
	}

	return true;
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
	satoshis = htlc->msatoshi / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's their HTLC, and that we collected it via rval. */
	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
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

	tx->input[0].witness = bitcoin_witness_htlc(tx,
						    htlc->r, &sig, wscript);

	log_debug(peer->log, "tx cost for htlc fulfill tx: %zu",
		  measure_tx_cost(tx));

	return tx;
}

static bool command_htlc_set_fail(struct peer *peer, struct htlc *htlc,
				  enum fail_error error_code, const char *why)
{
	const u8 *fail = failinfo_create(htlc,
					 &peer->dstate->id, error_code, why);

	set_htlc_fail(peer, htlc, fail, tal_count(fail));
	tal_free(fail);
	return command_htlc_fail(peer, htlc);
}

static bool command_htlc_fail(struct peer *peer, struct htlc *htlc)
{
	/* If onchain, nothing we can do. */
	if (!state_can_remove_htlc(peer->state))
		return false;

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	cstate_fail_htlc(peer->remote.staging_cstate, htlc);

	htlc_changestate(htlc, RCVD_ADD_ACK_REVOCATION, SENT_REMOVE_HTLC, false);

	remote_changes_pending(peer);

	queue_pkt_htlc_fail(peer, htlc);
	return true;
}

/* FIXME-OLD #onchain:
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
			broadcast_tx(peer, peer->onchain.resolved[i], NULL);
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

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	cstate_fulfill_htlc(peer->remote.staging_cstate, htlc);

	htlc_changestate(htlc, RCVD_ADD_ACK_REVOCATION, SENT_REMOVE_HTLC, false);

	remote_changes_pending(peer);

	queue_pkt_htlc_fulfill(peer, htlc);
	return true;
}

const char *command_htlc_add(struct peer *peer, u64 msatoshi,
			     unsigned int expiry,
			     const struct sha256 *rhash,
			     struct htlc *src,
			     const u8 *route,
			     u32 *error_code,
			     struct htlc **htlc)
{
	struct abs_locktime locktime;

	if (!blocks_to_abs_locktime(expiry, &locktime)) {
		log_unusual(peer->log, "add_htlc: fail: bad expiry %u", expiry);
		*error_code = BAD_REQUEST_400;
		return "bad expiry";
	}

	if (expiry < get_block_height(peer->dstate) + peer->dstate->config.min_htlc_expiry) {
		log_unusual(peer->log, "add_htlc: fail: expiry %u is too soon",
			    expiry);
		*error_code = BAD_REQUEST_400;
		return "expiry too soon";
	}

	if (expiry > get_block_height(peer->dstate) + peer->dstate->config.max_htlc_expiry) {
		log_unusual(peer->log, "add_htlc: fail: expiry %u is too far",
			    expiry);
		*error_code = BAD_REQUEST_400;
		return "expiry too far";
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 300 HTLCs in the remote commitment transaction.
	 */
	if (peer->remote.staging_cstate->side[LOCAL].num_htlcs == 300) {
		log_unusual(peer->log, "add_htlc: fail: already at limit");
		*error_code = SERVICE_UNAVAILABLE_503;
		return "channel full";
	}

	if (!state_can_add_htlc(peer->state)) {
		log_unusual(peer->log, "add_htlc: fail: peer state %s",
			    state_name(peer->state));
		*error_code = NOT_FOUND_404;
		return "peer not available";
	}

	*htlc = peer_new_htlc(peer, peer->htlc_id_counter,
			      msatoshi, rhash, expiry, route, tal_count(route),
			      src, SENT_ADD_HTLC);

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST add the HTLC addition to the unacked
	 * changeset for its remote commitment
	 */
	if (!cstate_add_htlc(peer->remote.staging_cstate, *htlc, true)) {
		/* FIXME-OLD #2:
		 *
		 * A node MUST NOT offer `amount_msat` it cannot pay for in
		 * the remote commitment transaction at the current `fee_rate`
		 */
 		log_unusual(peer->log, "add_htlc: fail: Cannot afford %"PRIu64
 			    " milli-satoshis in their commit tx",
 			    msatoshi);
		log_add_struct(peer->log, " channel state %s",
			       struct channel_state,
			       peer->remote.staging_cstate);
 		*htlc = tal_free(*htlc);
		*error_code = SERVICE_UNAVAILABLE_503;
		return "cannot afford htlc";
 	}

	remote_changes_pending(peer);

	queue_pkt_htlc_add(peer, *htlc);

	/* Make sure we never offer the same one twice. */
	peer->htlc_id_counter++;

	return NULL;
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
	log_debug(peer->log, "pkt_out: writing %s", pkt_name(out->pkt_case));
	return peer_write_packet(conn, peer, out, pkt_out);
}

static void clear_output_queue(struct peer *peer)
{
	size_t i, n = tal_count(peer->outpkt);
	for (i = 0; i < n; i++)
		tal_free(peer->outpkt[i]);
	tal_resize(&peer->outpkt, 0);
}

static struct io_plan *pkt_in(struct io_conn *conn, struct peer *peer)
{
	bool keep_going = true;

	/* We ignore packets if they tell us to, or we're closing already */
	if (peer->fake_close || !state_can_io(peer->state))
		keep_going = true;

	/* Sidestep the state machine for nested packets */
	else if (peer->inpkt->pkt_case == PKT__PKT_NESTED)
		keep_going = nested_pkt_in(peer, peer->inpkt->nested->type,
					   peer->inpkt->nested->inner_pkt.data,
					   peer->inpkt->nested->inner_pkt.len,
					   peer->inpkt);
	else if (state_is_normal(peer->state))
		keep_going = normal_pkt_in(peer, peer->inpkt);
	else if (state_is_shutdown(peer->state))
		keep_going = shutdown_pkt_in(peer, peer->inpkt);
	else if (peer->state == STATE_MUTUAL_CLOSING)
		keep_going = closing_pkt_in(peer, peer->inpkt);
	else if (peer->state == STATE_OPEN_WAIT_FOR_OPENPKT)
		keep_going = open_pkt_in(peer, peer->inpkt);
	else if (peer->state == STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT)
		keep_going = open_ouranchor_pkt_in(peer, peer->inpkt);
	else if (peer->state == STATE_OPEN_WAIT_FOR_ANCHORPKT)
		keep_going = open_theiranchor_pkt_in(peer, peer->inpkt);
	else if (state_is_openwait(peer->state))
		keep_going = open_wait_pkt_in(peer, peer->inpkt);
	else {
		log_unusual(peer->log,
			    "Unexpected state %s", state_name(peer->state));
		keep_going = false;
	}

	peer->inpkt = tal_free(peer->inpkt);
	if (keep_going)
		return peer_read_packet(conn, peer, pkt_in);
	else
		return peer_close(conn, peer);
}

/*
 * This only works because we send one update at a time, and they can't
 * ask for it again if they've already sent the `update_revocation` acking it.
 */
static void retransmit_updates(struct peer *peer)
{
	struct htlc_map_iter it;
	struct htlc *h;

	/* FIXME-OLD #2:
	 *
	 * A node MAY simply retransmit messages which are identical to the
	 * previous transmission. */
	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		switch (h->state) {
		case SENT_ADD_COMMIT:
			log_debug(peer->log, "Retransmitting add HTLC %"PRIu64,
				  h->id);
			queue_pkt_htlc_add(peer, h);
			break;
		case SENT_REMOVE_COMMIT:
			log_debug(peer->log, "Retransmitting %s HTLC %"PRIu64,
				  h->r ? "fulfill" : "fail", h->id);
			if (h->r)
				queue_pkt_htlc_fulfill(peer, h);
			else
				queue_pkt_htlc_fail(peer, h);
			break;
		default:
			break;
		}
	}

	assert(!peer->feechanges[SENT_FEECHANGE]);
}

/* FIXME-OLD #2:
 *
 * On disconnection, a node MUST reverse any uncommitted changes sent by the
 * other side (ie. `update_add_htlc`, `update_fee`, `update_fail_htlc` and
 * `update_fulfill_htlc` for which no `update_commit` has been received).  A
 * node SHOULD retain the `r` value from the `update_fulfill_htlc`, however.
*/
static void forget_uncommitted_changes(struct peer *peer)
{
	struct htlc *h;
	struct htlc_map_iter it;
	bool retry;

	if (!peer->remote.commit || !peer->remote.commit->cstate)
		return;

	log_debug(peer->log, "Forgetting uncommitted");
	log_debug_struct(peer->log, "LOCAL: changing from %s",
			 struct channel_state, peer->local.staging_cstate);
	log_add_struct(peer->log, " to %s",
			 struct channel_state, peer->local.commit->cstate);
	log_debug_struct(peer->log, "REMOTE: changing from %s",
			 struct channel_state, peer->remote.staging_cstate);
	log_add_struct(peer->log, " to %s",
			 struct channel_state, peer->remote.commit->cstate);

	tal_free(peer->local.staging_cstate);
	tal_free(peer->remote.staging_cstate);
	peer->local.staging_cstate
		= copy_cstate(peer, peer->local.commit->cstate);
	peer->remote.staging_cstate
		= copy_cstate(peer, peer->remote.commit->cstate);

	/* We forget everything we're routing, and re-send.  This
	 * works for the reload-from-database case as well as the
	 * normal reconnect. */
again:
	retry = false;
	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		switch (h->state) {
		case SENT_ADD_HTLC:
			/* Adjust counter to lowest HTLC removed */
			if (peer->htlc_id_counter > h->id) {
				log_debug(peer->log,
					  "Lowering htlc_id_counter to %"PRIu64,
					  h->id);
				peer->htlc_id_counter = h->id;
			}
			 /* Fall thru */
		case RCVD_ADD_HTLC:
			log_debug(peer->log, "Forgetting %s %"PRIu64,
				  htlc_state_name(h->state), h->id);
			/* May miss some due to delete reorg. */
			tal_free(h);
			retry = true;
			break;
		case RCVD_REMOVE_HTLC:
			log_debug(peer->log, "Undoing %s %"PRIu64,
				  htlc_state_name(h->state), h->id);
			htlc_undostate(h, RCVD_REMOVE_HTLC,
				       SENT_ADD_ACK_REVOCATION);
			break;
		case SENT_REMOVE_HTLC:
			log_debug(peer->log, "Undoing %s %"PRIu64,
				  htlc_state_name(h->state), h->id);
			htlc_undostate(h, SENT_REMOVE_HTLC,
				       RCVD_ADD_ACK_REVOCATION);
			break;
		default:
			break;
		}
	}
	if (retry)
		goto again;

	/* Forget uncommitted feechanges */
	peer->feechanges[SENT_FEECHANGE]
		= tal_free(peer->feechanges[SENT_FEECHANGE]);
	peer->feechanges[RCVD_FEECHANGE]
		= tal_free(peer->feechanges[RCVD_FEECHANGE]);

	/* Make sure our HTLC counter is correct. */
	if (peer->htlc_id_counter != 0)
		assert(htlc_get(&peer->htlcs, peer->htlc_id_counter-1, LOCAL));
	assert(!htlc_get(&peer->htlcs, peer->htlc_id_counter, LOCAL));
}

static void retransmit_pkts(struct peer *peer, s64 ack)
{
	log_debug(peer->log, "Our order counter is %"PRIi64", their ack %"PRIi64,
		  peer->order_counter, ack);

	if (ack > peer->order_counter) {
		log_unusual(peer->log, "reconnect ack %"PRIi64" > %"PRIi64,
			    ack, peer->order_counter);
		peer_comms_err(peer, pkt_err(peer, "invalid ack"));
		return;
	}

	log_debug(peer->log, "They acked %"PRIi64", remote=%"PRIi64" local=%"PRIi64,
		  ack, peer->remote.commit ? peer->remote.commit->order : -2,
		  peer->local.commit ? peer->local.commit->order : -2);

	/* FIXME-OLD #2:
	 *
	 * A node MAY assume that only one of each type of message need be
	 * retransmitted.  A node SHOULD retransmit the last of each message
	 * type which was not counted by the `ack` field.
	 */
	while (ack < peer->order_counter) {
		if (ack == 0) {
			queue_pkt_open(peer, peer->local.offer_anchor);
		} else if (ack == 1) {
			queue_pkt_open_commit_sig(peer);
		} else if (peer->remote.commit
			   && ack == peer->remote.commit->order) {
			/* FIXME-OLD #2:
			 *
			 * Before retransmitting `update_commit`, the node
			 * MUST send appropriate `update_add_htlc`,
			 * `update_fee`, `update_fail_htlc` or
			 * `update_fulfill_htlc` messages (the other node will
			 * have forgotten them, as required above).
			 */
			retransmit_updates(peer);
			queue_pkt_commit(peer, peer->remote.commit->sig);
		} else if (peer->local.commit
			   && ack == peer->local.commit->order) {
			/* Re-transmit revocation. */
			struct sha256 preimage, next;
			u64 commit_num = peer->local.commit->commit_num - 1;

			/* Make sure we don't revoke current commit! */
			assert(commit_num < peer->local.commit->commit_num);
			peer_get_revocation_preimage(peer, commit_num,&preimage);
			peer_get_revocation_hash(peer, commit_num + 2, &next);
			log_debug(peer->log, "Re-sending revocation hash %"PRIu64,
				  commit_num + 2);
			log_add_struct(peer->log, "value %s", struct sha256,
				       &next);
			log_add_struct(peer->log, "local.next=%s", struct sha256,
				       &peer->local.next_revocation_hash);
			log_debug(peer->log, "Re-sending revocation %"PRIu64,
				  commit_num);
			queue_pkt_revocation(peer, &preimage, &next);
		} else if (ack == peer->closing.shutdown_order) {
			log_debug(peer->log, "Re-sending shutdown");
			queue_pkt_close_shutdown(peer);
		} else if (ack == peer->closing.closing_order) {
			log_debug(peer->log, "Re-sending closing order");
			queue_pkt_close_signature(peer);
		} else {
			log_broken(peer->log, "Can't rexmit %"PRIu64
				   " when local commit %"PRIi64" and remote %"PRIi64,
				   ack,
				   peer->local.commit ? peer->local.commit->order : -2,
				   peer->remote.commit ? peer->remote.commit->order : -2);
			peer_comms_err(peer, pkt_err(peer, "invalid ack"));
			return;
		}
		ack++;
	}

	/* We might need to update HTLCs which were from other peers. */
	retry_all_routing(peer);
}

static u64 desired_commit_feerate(struct lightningd_state *dstate)
{
	return get_feerate(dstate) * dstate->config.commitment_fee_percent / 100;
}

static bool want_feechange(const struct peer *peer)
{
	if (!state_is_normal(peer->state) && !state_is_shutdown(peer->state))
		return false;
	log_debug(peer->log, "Current fee_rate: %"PRIu64" want %"PRIu64,
		  peer->local.staging_cstate->fee_rate,
		  desired_commit_feerate(peer->dstate));
	/* FIXME: Send fee changes when we want it */
	return false;
}

static void peer_has_connected(struct peer *peer)
{
	assert(!peer->connected);
	peer->connected = true;

	/* Do we want to send something? */
	if (peer_uncommitted_changes(peer) || want_feechange(peer)) {
		log_debug(peer->log, "connected: changes pending");
		remote_changes_pending(peer);
	}
}

static struct io_plan *init_pkt_in(struct io_conn *conn, struct peer *peer)
{
	if (peer->inpkt->pkt_case != PKT__PKT_INIT) {
		peer_received_unexpected_pkt(peer, peer->inpkt, __func__);
		goto fail;
	}

	/* They might have missed the error, tell them before hanging up */
	if (state_is_error(peer->state)) {
		queue_pkt_err(peer, pkt_err(peer, "In error state %s",
					    state_name(peer->state)));
		goto fail;
	}

	if (peer->inpkt->init->has_features) {
		size_t i;

		/* FIXME-OLD #2:
		 *
		 * The receiving node SHOULD ignore any odd feature bits it
		 * does not support, and MUST fail the connection if any
		 * unsupported even `features` bit is set. */
		for (i = 0; i < peer->inpkt->init->features.len*CHAR_BIT; i++) {
			size_t byte = i / CHAR_BIT, bit = i % CHAR_BIT;
			if (peer->inpkt->init->features.data[byte] & (1<<bit)) {
				/* Can't handle even features. */
				if (i % 2 != 0) {
					log_debug(peer->log,
						  "They offered feature %zu", i);
					continue;
				}
				queue_pkt_err(peer,
					      pkt_err(peer,
						      "Unsupported feature %zu",
						      i));
				goto fail;
			}
		}
	}

	/* Send any packets they missed. */
	retransmit_pkts(peer, peer->inpkt->init->ack);

	/* We let the conversation go this far in case they missed the
	 * close packets.  But now we can close if we're done. */
	if (!state_can_io(peer->state)) {
		log_debug(peer->log, "State %s, closing immediately",
			  state_name(peer->state));
		goto fail;
	}

	/* Back into normal mode. */
	peer->inpkt = tal_free(peer->inpkt);

	peer_has_connected(peer);

	if (state_is_normal(peer->state)){
		announce_channel(peer->dstate, peer);
		sync_routing_table(peer->dstate, peer);
	}

	return io_duplex(conn,
			 peer_read_packet(conn, peer, pkt_in),
			 pkt_out(conn, peer));

fail:
	/* We always free inpkt; they may yet reconnect. */
	peer->inpkt = tal_free(peer->inpkt);
	return pkt_out(conn, peer);
}

static struct io_plan *read_init_pkt(struct io_conn *conn,
					  struct peer *peer)
{
	return peer_read_packet(conn, peer, init_pkt_in);
}

static u64 peer_commitsigs_received(struct peer *peer)
{
	return peer->their_commitsigs;
}

static u64 peer_revocations_received(struct peer *peer)
{
	/* How many preimages we've received. */
	return -peer->their_preimages.min_index;
}

static struct io_plan *peer_send_init(struct io_conn *conn, struct peer *peer)
{
	u64 open, sigs, revokes, shutdown, closing;

	open = (peer->state == STATE_OPEN_WAIT_FOR_OPENPKT ? 0 : 1);
	sigs = peer_commitsigs_received(peer);
	revokes = peer_revocations_received(peer);
	shutdown = peer->closing.their_script ? 1 : 0;
	closing = peer->closing.sigs_in;
	log_debug(peer->log,
		  "Init with ack %"PRIu64" opens + %"PRIu64" sigs + %"
		  PRIu64" revokes + %"PRIu64" shutdown + %"PRIu64" closing",
		  open, sigs, revokes, shutdown, closing);

	/* FIXME-OLD #2:
	 *
	 * A node MUST send an `init` message immediately immediately after
	 * it has validated the `authenticate` message.  A node MUST set
	 * the `ack` field in the `init` message to the the sum of
	 * previously-processed messages of types `open`, `open_commit_sig`,
	 * `update_commit`, `update_revocation`, `close_shutdown` and
	 * `close_signature`. */
	return peer_write_packet(conn, peer,
				 pkt_init(peer, open + sigs + revokes
					  + shutdown + closing),
				 read_init_pkt);
}

/* Crypto is on, we are live. */
static struct io_plan *peer_crypto_on(struct io_conn *conn, struct peer *peer)
{
	peer_secrets_init(peer);

	peer_get_revocation_hash(peer, 0, &peer->local.next_revocation_hash);

	assert(peer->state == STATE_INIT);

	/* Counter is 1 for sending pkt_open: we'll do it in retransmit_pkts */
	peer->order_counter++;

	db_start_transaction(peer);
	set_peer_state(peer, STATE_OPEN_WAIT_FOR_OPENPKT, __func__, true);

	/* FIXME: Start timeout, and close peer if they don't progress! */
	db_create_peer(peer);
	if (db_commit_transaction(peer) != NULL) {
		peer_database_err(peer);
		return peer_close(conn, peer);
	}

	/* Set up out commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->local.commit = new_commit_info(peer, 0);
	peer->local.commit->revocation_hash = peer->local.next_revocation_hash;
	peer_get_revocation_hash(peer, 1, &peer->local.next_revocation_hash);

	return peer_send_init(conn,peer);
}

static void destroy_peer(struct peer *peer)
{
	if (peer->conn)
		io_close(peer->conn);
	list_del_from(&peer->dstate->peers, &peer->list);
}

static void try_reconnect(struct peer *peer);

static void peer_disconnect(struct io_conn *conn, struct peer *peer)
{
	log_info(peer->log, "Disconnected");

	/* No longer connected. */
	peer->conn = NULL;
	peer->connected = false;

	/* Not even set up yet?  Simply free.*/
	if (peer->state == STATE_INIT) {
		/* This means we didn't get past crypto handshake or hit db */
		tal_free(peer);
		return;
	}

	/* Completely dead?  Free it now. */
	if (peer->state == STATE_CLOSED) {
		io_break(peer);
		return;
	}

	/* This is an unexpected close. */
	if (state_can_io(peer->state)) {
		forget_uncommitted_changes(peer);
		try_reconnect(peer);
	}
}

static void try_commit(struct peer *peer)
{
	peer->commit_timer = NULL;

	if (!peer->connected) {
		log_debug(peer->log, "try_commit: state=%s, not connected",
			  state_name(peer->state));
		return;
	}

	if (state_can_commit(peer->state))
		do_commit(peer, NULL);
	else {
		/* FIXME: try again when we receive revocation /
		 * reconnect, rather than using timer! */
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
	ci->order = (s64)-1LL;
	return ci;
}

static bool peer_reconnected(struct peer *peer,
			     struct io_conn *conn,
			     int addr_type, int addr_protocol,
			     struct io_data *iod,
			     const struct pubkey *id,
			     bool we_connected)
{
	char *name;
	struct netaddr addr;

	assert(structeq(peer->id, id));

	peer->io_data = tal_steal(peer, iod);

	/* FIXME: Attach IO logging for this peer. */
	if (!netaddr_from_fd(io_conn_fd(conn), addr_type, addr_protocol, &addr))
		return false;

	/* If we free peer, conn should be closed, but can't be freed
	 * immediately so don't make peer a parent. */
	peer->conn = conn;
	io_set_finish(conn, peer_disconnect, peer);

	name = netaddr_name(peer, &addr);
	log_info(peer->log, "Reconnected %s %s",
		 we_connected ? "out to" : "in from", name);
	tal_free(name);

	return true;
}

struct peer *new_peer(struct lightningd_state *dstate,
		      struct log *log,
		      enum state state,
		      bool offer_anchor)
{
	struct peer *peer = tal(dstate, struct peer);

	peer->state = state;
	peer->connected = false;
	peer->id = NULL;
	peer->dstate = dstate;
	peer->io_data = NULL;
	peer->secrets = NULL;
	list_head_init(&peer->watches);
	peer->inpkt = NULL;
	peer->outpkt = tal_arr(peer, Pkt *, 0);
	peer->open_jsoncmd = NULL;
	peer->commit_jsoncmd = NULL;
	list_head_init(&peer->outgoing_txs);
	list_head_init(&peer->their_commits);
	peer->anchor.ok_depth = -1;
	peer->order_counter = 0;
	peer->their_commitsigs = 0;
	peer->cur_commit.watch = NULL;
	peer->closing.their_sig = NULL;
	peer->closing.our_script = NULL;
	peer->closing.their_script = NULL;
	peer->closing.shutdown_order = (s64)-1LL;
	peer->closing.closing_order = (s64)-1LL;
	peer->closing.sigs_in = 0;
	peer->onchain.tx = NULL;
	peer->onchain.resolved = NULL;
	peer->onchain.htlcs = NULL;
	peer->onchain.wscripts = NULL;
	peer->commit_timer = NULL;
	peer->nc = NULL;
	peer->their_prev_revocation_hash = NULL;
	peer->conn = NULL;
	peer->fake_close = false;
	peer->output_enabled = true;
	peer->local.offer_anchor = offer_anchor;
	if (!blocks_to_rel_locktime(dstate->config.locktime_blocks,
				    &peer->local.locktime))
		fatal("Could not convert locktime_blocks");
	peer->local.mindepth = dstate->config.anchor_confirms;
	peer->local.commit = peer->remote.commit = NULL;
	peer->local.staging_cstate = peer->remote.staging_cstate = NULL;
	peer->log = tal_steal(peer, log);
	log_debug(peer->log, "New peer %p", peer);

	htlc_map_init(&peer->htlcs);
	memset(peer->feechanges, 0, sizeof(peer->feechanges));
	shachain_init(&peer->their_preimages);

	list_add(&dstate->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	return peer;
}

static struct peer_address *find_address(struct lightningd_state *dstate,
					 const struct pubkey *id)
{
	struct peer_address *i;

	list_for_each(&dstate->addresses, i, list) {
		if (structeq(&id->pubkey, &i->id.pubkey))
			return i;
	}
	return NULL;
}

static bool add_peer_address(struct lightningd_state *dstate,
			     const struct pubkey *id,
			     const struct netaddr *addr)
{
	struct peer_address *a = find_address(dstate, id);
	if (a) {
		a->addr = *addr;
	} else {
		a = tal(dstate, struct peer_address);
		a->addr = *addr;
		a->id = *id;
		list_add_tail(&dstate->addresses, &a->list);
	}
	return db_add_peer_address(dstate, a);
}

static bool peer_first_connected(struct peer *peer,
				 struct io_conn *conn,
				 int addr_type, int addr_protocol,
				 struct io_data *iod,
				 const struct pubkey *id,
				 bool we_connected)
{
	char *name, *idstr;
	struct netaddr addr;

	peer->io_data = tal_steal(peer, iod);
	peer->id = tal_dup(peer, struct pubkey, id);
	peer->local.commit_fee_rate = desired_commit_feerate(peer->dstate);

	peer->htlc_id_counter = 0;

	/* If we free peer, conn should be closed, but can't be freed
	 * immediately so don't make peer a parent. */
	peer->conn = conn;
	io_set_finish(conn, peer_disconnect, peer);

	peer->anchor.min_depth = get_block_height(peer->dstate);

	/* FIXME: Attach IO logging for this peer. */
	if (!netaddr_from_fd(io_conn_fd(conn), addr_type, addr_protocol, &addr))
		return false;

	/* Save/update address if we connected to them. */
	if (we_connected && !add_peer_address(peer->dstate, peer->id, &addr))
		return false;

	name = netaddr_name(peer, &addr);
	idstr = pubkey_to_hexstr(name, peer->id);
	log_info(peer->log, "Connected %s %s id %s, changing prefix",
		 we_connected ? "out to" : "in from", name, idstr);
	set_log_prefix(peer->log, tal_fmt(name, "%s:", idstr));
	tal_free(name);

	log_debug(peer->log, "Using fee rate %"PRIu64,
		  peer->local.commit_fee_rate);
	return true;
}

static void htlc_destroy(struct htlc *htlc)
{
	if (!htlc_map_del(&htlc->peer->htlcs, htlc))
		fatal("Could not find htlc to destroy");
}

struct htlc *peer_new_htlc(struct peer *peer,
			   u64 id,
			   u64 msatoshi,
			   const struct sha256 *rhash,
			   u32 expiry,
			   const u8 *route,
			   size_t routelen,
			   struct htlc *src,
			   enum htlc_state state)
{
	struct htlc *h = tal(peer, struct htlc);
	h->peer = peer;
	h->state = state;
	h->id = id;
	h->msatoshi = msatoshi;
	h->rhash = *rhash;
	h->r = NULL;
	h->fail = NULL;
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

static struct io_plan *crypto_on_reconnect(struct io_conn *conn,
					   struct lightningd_state *dstate,
					   struct io_data *iod,
					   const struct pubkey *id,
					   struct peer *peer,
					   bool we_connected)
{
	/* Setup peer->conn and peer->io_data */
	if (!peer_reconnected(peer, conn, SOCK_STREAM, IPPROTO_TCP,
			      iod, id, we_connected))
		return io_close(conn);

	/* We need to eliminate queue now. */
	clear_output_queue(peer);

	return peer_send_init(conn, peer);
}

static struct io_plan *crypto_on_reconnect_in(struct io_conn *conn,
					      struct lightningd_state *dstate,
					      struct io_data *iod,
					      struct log *log,
					      const struct pubkey *id,
					      struct peer *peer)
{
	assert(log == peer->log);
	return crypto_on_reconnect(conn, dstate, iod, id, peer, false);
}

static struct io_plan *crypto_on_reconnect_out(struct io_conn *conn,
					       struct lightningd_state *dstate,
					       struct io_data *iod,
					       struct log *log,
					       const struct pubkey *id,
					       struct peer *peer)
{
	assert(log == peer->log);
	return crypto_on_reconnect(conn, dstate, iod, id, peer, true);
}

static struct io_plan *crypto_on_out(struct io_conn *conn,
				     struct lightningd_state *dstate,
				     struct io_data *iod,
				     struct log *log,
				     const struct pubkey *id,
				     struct json_connecting *connect)
{
	struct peer *peer;

	if (find_peer(dstate, id)) {
		command_fail(connect->cmd, "Already connected to peer %s",
			     pubkey_to_hexstr(connect->cmd, id));
		return io_close(conn);
	}

	/* Initiator currently funds channel */
	peer = new_peer(dstate, log, STATE_INIT, true);
	if (!peer_first_connected(peer, conn, SOCK_STREAM, IPPROTO_TCP,
				  iod, id, true)) {
		command_fail(connect->cmd, "Failed to make peer for %s:%s",
			     connect->name, connect->port);
		return io_close(conn);
	}
	peer->anchor.input = tal_steal(peer, connect->input);
	peer->open_jsoncmd = connect->cmd;
	return peer_crypto_on(conn, peer);
}

static struct io_plan *peer_connected_out(struct io_conn *conn,
					  struct lightningd_state *dstate,
					  struct json_connecting *connect)
{
	struct log *l;
	struct netaddr addr;

	l = new_log(conn, dstate->log_book, "OUT-%s:%s:",
		    connect->name, connect->port);

	if (!netaddr_from_fd(io_conn_fd(conn), SOCK_STREAM, IPPROTO_TCP, &addr)) {
		log_unusual(l, "Failed to get netaddr: %s", strerror(errno));
		return io_close(conn);
	}

	log_debug_struct(l, "Connected out to %s", struct netaddr, &addr);
	return peer_crypto_setup(conn, dstate, NULL, l, crypto_on_out, connect);
}

static struct io_plan *crypto_on_in(struct io_conn *conn,
				    struct lightningd_state *dstate,
				    struct io_data *iod,
				    struct log *log,
				    const struct pubkey *id,
				    void *unused)
{
	struct peer *peer;

	/* FIXME-OLD #2:
	 *
	 * A node MUST handle continuing a previous channel on a new encrypted
	 * transport. */
	peer = find_peer(dstate, id);
	if (peer) {
		/* Close any existing connection, without side effects. */
		if (peer->conn) {
			log_debug(log, "This is reconnect for peer %p", peer);
			log_debug(peer->log, "Reconnect: closing old conn %p for new conn %p",
				  peer->conn, conn);
			io_set_finish(peer->conn, NULL, NULL);
			io_close(peer->conn);
			peer->conn = NULL;
			peer->connected = false;
		}
		return crypto_on_reconnect_in(conn, dstate, iod, peer->log, id,
					      peer);
	}

	/* Initiator currently funds channel */
	peer = new_peer(dstate, log, STATE_INIT, false);
	if (!peer_first_connected(peer, conn, SOCK_STREAM, IPPROTO_TCP,
				  iod, id, false))
		return io_close(conn);

	return peer_crypto_on(conn, peer);
}

static struct io_plan *peer_connected_in(struct io_conn *conn,
					 struct lightningd_state *dstate)
{
	struct netaddr addr;
	struct log *l;
	const char *name;

	if (!netaddr_from_fd(io_conn_fd(conn), SOCK_STREAM, IPPROTO_TCP, &addr))
		return false;
	name = netaddr_name(conn, &addr);
	l = new_log(conn, dstate->log_book, "IN-%s:", name);

	log_debug(l, "Connected in");

	return peer_crypto_setup(conn, dstate, NULL, l, crypto_on_in, NULL);
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

void setup_listeners(struct lightningd_state *dstate)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;

	if (!dstate->portnum)
		return;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(dstate->portnum);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(dstate->portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(dstate, AF_INET6, &addr6, sizeof(addr6));
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
			assert(dstate->portnum == ntohs(addr.sin_port));
			log_debug(dstate->base_log,
				  "Creating IPv6 listener on port %u",
				  dstate->portnum);
			io_new_listener(dstate, fd1, peer_connected_in, dstate);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(dstate, AF_INET, &addr, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
		} else {
			assert(dstate->portnum == ntohs(addr.sin_port));
			log_debug(dstate->base_log,
				  "Creating IPv4 listener on port %u",
				  dstate->portnum);
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
	u64 fee;
	const tal_t *tmpctx = tal_tmpctx(cmd);

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
	tx = bitcoin_tx_from_hex(tmpctx, buffer + txtok->start, txhexlen);
	if (!tx) {
		command_fail(cmd, "'%.*s' is not a valid transaction",
			     txtok->end - txtok->start,
			     buffer + txtok->start);
		return;
	}

	bitcoin_txid(tx, &connect->input->txid);

	/* Find an output we know how to spend. */
	for (output = 0; output < tx->output_count; output++) {
		if (wallet_can_spend(cmd->dstate, &tx->output[output],
				     &connect->input->walletkey))
			break;
	}
	if (output == tx->output_count) {
		command_fail(cmd, "Tx doesn't send to wallet address");
		return;
	}

	connect->input->index = output;
	connect->input->in_amount = tx->output[output].amount;

	/* FIXME: This is normal case, not exact. */
	fee = fee_by_feerate(94 + 1+73 + 1+33 + 1, get_feerate(cmd->dstate));
	if (fee >= connect->input->in_amount) {
		command_fail(cmd, "Amount %"PRIu64" below fee %"PRIu64,
			     connect->input->in_amount, fee);
		return;
	}

	connect->input->out_amount = connect->input->in_amount - fee;
	if (anchor_too_large(connect->input->out_amount)) {
		command_fail(cmd, "Amount %"PRIu64" is too large",
			     connect->input->out_amount);
		return;
	}
	if (!dns_resolve_and_connect(cmd->dstate, connect->name, connect->port,
				     peer_connected_out, peer_failed, connect)) {
		command_fail(cmd, "DNS failed");
		return;
	}

	tal_free(tmpctx);
}

static const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to a {host} at {port} using hex-encoded {tx} to fund",
	"Returns the {id} on success (once channel established)"
};
AUTODATA(json_command, &connect_command);

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

		db_start_transaction(peer);
		/* This can fail only if we're in an error state. */
		command_htlc_set_fail(peer, h,
				      REQUEST_TIMEOUT_408, "timed out");
		if (db_commit_transaction(peer) != NULL) {
			peer_fail(peer, __func__);
			return;
		}
	}

	/* FIXME-OLD #2:
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

	if (any_deadline_past(peer))
		peer_fail(peer, __func__);
}

static void peer_depth_ok(struct peer *peer)
{
	queue_pkt_open_complete(peer);

	db_start_transaction(peer);

	switch (peer->state) {
	case STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE:
		set_peer_state(peer, STATE_OPEN_WAIT_THEIRCOMPLETE,
			       __func__, true);
		break;
	case STATE_OPEN_WAIT_ANCHORDEPTH:
		peer_open_complete(peer, NULL);
		set_peer_state(peer, STATE_NORMAL, __func__, true);
		announce_channel(peer->dstate, peer);
		sync_routing_table(peer->dstate, peer);
		break;
	default:
		log_broken(peer->log, "%s: state %s",
			   __func__, state_name(peer->state));
		peer_fail(peer, __func__);
		break;
	}

	if (db_commit_transaction(peer))
		peer_database_err(peer);
}

static enum watch_result anchor_depthchange(struct peer *peer,
					    unsigned int depth,
					    const struct sha256_double *txid,
					    void *unused)
{
	log_debug(peer->log, "Anchor at depth %u", depth);

	/* Still waiting for it to reach depth? */
	if (state_is_waiting_for_anchor(peer->state)) {
		log_debug(peer->log, "Waiting for depth %i",
			  peer->anchor.ok_depth);
		/* We can see a run of blocks all at once, so may be > depth */
		if ((int)depth >= peer->anchor.ok_depth) {
			peer_depth_ok(peer);
			peer->anchor.ok_depth = -1;
		}
	} else if (depth == 0)
		/* FIXME: Report losses! */
		fatal("Funding transaction was unspent!");

	/* Since this gets called on every new block, check HTLCs here. */
	check_htlc_expiry(peer);

	/* If fee rate has changed, fire off update to change it. */
	if (want_feechange(peer) && state_can_commit(peer->state)) {
		log_debug(peer->log, "fee rate changed to %"PRIu64,
			  desired_commit_feerate(peer->dstate));
		/* FIXME: If fee changes back before update, we screw
		 * up and send an empty commit.  We need to generate a
		 * real packet here! */
		remote_changes_pending(peer);
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST update bitcoin fees if it estimates that the
	 * current commitment transaction will not be processed in a
	 * timely manner (see "Risks With HTLC Timeouts").
	 */
	/* Note: we don't do this when we're told to ignore fees. */
	/* FIXME: BOLT should say what to do if it can't!  We drop conn. */
	if (!state_is_onchain(peer->state) && !state_is_error(peer->state)
	    && peer->dstate->config.commitment_fee_min_percent != 0
	    && peer->local.commit->cstate->fee_rate < get_feerate(peer->dstate)) {
		log_broken(peer->log, "fee rate %"PRIu64" lower than %"PRIu64,
			   peer->local.commit->cstate->fee_rate,
			   get_feerate(peer->dstate));
		peer_fail(peer, __func__);
	}

	return KEEP_WATCHING;
}

void peers_new_block(struct lightningd_state *dstate, unsigned int height)
{
	/* This is where we check for anchor timeouts. */
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list) {
		if (!state_is_waiting_for_anchor(peer->state))
			continue;

		/* If we haven't seen anchor yet, we can timeout. */
		if (height >= peer->anchor.min_depth
		    + dstate->config.anchor_onchain_wait
		    + dstate->config.anchor_confirms) {
			queue_pkt_err(peer, pkt_err(peer, "Funding timeout"));
			set_peer_state(peer, STATE_ERR_ANCHOR_TIMEOUT, __func__,
				       false);
			peer_breakdown(peer);
		}
	}
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
				enum side side,
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
	satoshis = htlc->msatoshi / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&peer->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's our HTLC, and that we collected it via timeout. */
	tx->output[0].script = scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
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

	tx->input[0].witness = bitcoin_witness_htlc(tx,
						    NULL, &sig, wscript);

	log_unusual(peer->log, "tx cost for htlc timeout tx: %zu",
		    measure_tx_cost(tx));

	return tx;
}

static void reset_onchain_closing(struct peer *peer)
{
	if (peer->onchain.tx) {
		log_unusual_struct(peer->log,
				   "New anchor spend, forgetting old tx %s",
				   struct sha256_double, &peer->onchain.txid);
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

/* We usually don't fail HTLCs we offered, but if the peer breaks down
 * before we've confirmed it, this is exactly what happens. */
static void fail_own_htlc(struct peer *peer, struct htlc *htlc)
{
	/* We can't do anything about db failures; peer already closed. */
	db_start_transaction(peer);
	set_htlc_fail(peer, htlc, "peer closed", strlen("peer closed"));
	our_htlc_failed(peer, htlc);
	db_commit_transaction(peer);
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
	fail_own_htlc(peer, htlc);
	return DELETE_WATCH;
}

static enum watch_result our_htlc_depth(struct peer *peer,
					unsigned int depth,
					const struct sha256_double *txid,
					enum side whose_commit,
					unsigned int out_num)
{
	struct htlc *h = peer->onchain.htlcs[out_num];
	u32 height;

	/* Must be in a block. */
	if (depth == 0)
		return KEEP_WATCHING;

	height = get_block_height(peer->dstate);

	/* FIXME-OLD #onchain:
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

	/* FIXME-OLD #onchain:
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
		broadcast_tx(peer, peer->onchain.resolved[out_num], NULL);
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

	/* FIXME-OLD #onchain:
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

	/* FIXME-OLD #onchain:
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
	broadcast_tx(peer, peer->onchain.resolved[peer->onchain.to_us_idx],
		     NULL);
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
			fail_own_htlc(peer, h);
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

	/* FIXME-OLD #onchain:
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

	set_htlc_rval(peer, h, &preimage);
	our_htlc_fulfilled(peer, h);

	/* FIXME-OLD #onchain:
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
	/* FIXME-OLD #onchain:
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
	/* FIXME-OLD #onchain:
	 *
	 * If the node ... already knows... a redemption preimage for an
	 * unresolved *commitment tx* output it was offered, it MUST *resolve*
	 * the output by spending it using the preimage.
	 */
	if (peer->onchain.htlcs[out_num]->r) {
		peer->onchain.resolved[out_num]	= htlc_fulfill_tx(peer, out_num);
		broadcast_tx(peer, peer->onchain.resolved[out_num], NULL);
	} else {
		/* FIXME-OLD #onchain:
		 *
		 * Otherwise, if the output HTLC has expired, it is considered
		 * *irrevocably resolved*.
		 */
		watch_tx(peer->onchain.tx, peer, peer->onchain.tx,
			 their_htlc_depth, int2ptr(out_num));
	}
}

/* FIXME-OLD #onchain:
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
		/* FIXME-OLD #onchain:
		 *
		 * 1. _A's main output_: A node SHOULD spend this output to a
		 *    convenient address. ... A node MUST wait until the
		 *    `OP_CHECKSEQUENCEVERIFY` delay has passed (as specified
		 *    by the other node's `open_channel` `delay` field) before
		 *    spending the output.
		 */
		if (i == peer->onchain.to_us_idx)
			watch_tx(tx, peer, tx, our_main_output_depth, NULL);

		/* FIXME-OLD #onchain:
		 *
		 * 2. _B's main output_: No action required, this output is
		 *    considered *resolved* by the *commitment tx*.
		 */
		else if (i == peer->onchain.to_them_idx)
			peer->onchain.resolved[i] = tx;

		/* FIXME-OLD #onchain:
		 *
		 * 3. _A's offered HTLCs_: See On-chain HTLC Handling: Our
		 *    Offers below.
		 */
		else if (htlc_owner(peer->onchain.htlcs[i]) == LOCAL)
			resolve_our_htlc(peer, i, our_htlc_depth_ourcommit);

		/* FIXME-OLD #onchain:
		 *
		 * 4. _B's offered HTLCs_: See On-chain HTLC Handling: Their
		 *    Offers below.
		 */
		else
			resolve_their_htlc(peer, i);
	}
}

/* FIXME-OLD #onchain:
 *
 * Similarly, when node A sees a *commitment tx* from B:
 */
static void resolve_their_unilateral(struct peer *peer)
{
	unsigned int i;
	const struct bitcoin_tx *tx = peer->onchain.tx;

	for (i = 0; i < tx->output_count; i++) {
		/* FIXME-OLD #onchain:
		 *
		 * 1. _A's main output_: No action is required; this is a
		 *    simple P2WPKH output.  This output is considered
		 *    *resolved* by the *commitment tx*.
		 */
		if (i == peer->onchain.to_us_idx)
			peer->onchain.resolved[i] = tx;
		/* FIXME-OLD #onchain:
		 *
		 * 2. _B's main output_: No action required, this output is
		 *    considered *resolved* by the *commitment tx*.
		 */
		else if (i == peer->onchain.to_them_idx)
			peer->onchain.resolved[i] = tx;
		/* FIXME-OLD #onchain:
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

	/* FIXME-OLD #onchain:
	 *
	 * A node doesn't need to do anything else as it has already agreed to
	 * the output, which is sent to its specified scriptpubkey (see FIXME-OLD
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

	/* FIXME-OLD #onchain:
	 *
	 * A node MUST *resolve* all outputs as specified below, and MUST be
	 * prepared to resolve them multiple times in case of blockchain
	 * reorganizations.
	 */
	for (i = 0; i < n; i++)
		if (!peer->onchain.resolved[i])
			return KEEP_WATCHING;

	/* FIXME-OLD #onchain:
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

	/* FIXME-OLD #onchain:
	 *
	 * A node MUST monitor the blockchain for transactions which spend any
	 * output which is not *irrevocably resolved* until all outputs are
	 * *irrevocably resolved*.
	 */
	set_peer_state(peer, STATE_CLOSED, "check_for_resolution", false);
	db_forget_peer(peer);

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
		/* FIXME-OLD #onchain:
		 * 1. _A's main output_: No action is required; this is a
		 *    simple P2WPKH output.  This output is considered
		 *    *resolved* by the *commitment tx*.
		 */
		if (i == peer->onchain.to_us_idx) {
			log_debug(peer->log, "%i is to-us, ignoring", i);
			peer->onchain.resolved[i] = tx;
			continue;
		}

		/* FIXME-OLD #onchain:
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
		wsize += tal_count(peer->onchain.wscripts[i]);
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
						       &peer->local.finalkey));
	steal_tx->output[0].script_length = tal_count(steal_tx->output[0].script);

	/* Now, we can sign them all (they're all of same form). */
	n = 0;
	for (i = 0; i < tx->output_count; i++) {
		struct bitcoin_signature sig;

		/* Don't bother stealing the output already to us. */
		if (i == peer->onchain.to_us_idx)
			continue;

		sig.stype = SIGHASH_ALL;
		peer_sign_steal_input(peer, steal_tx, n,
				      peer->onchain.wscripts[i],
				      &sig.sig);

		steal_tx->input[n].witness
			= bitcoin_witness_secret(steal_tx,
						 revocation_preimage,
						 sizeof(*revocation_preimage),
						 &sig,
						 peer->onchain.wscripts[i]);
		n++;
	}
	assert(n == steal_tx->input_count);

	broadcast_tx(peer, steal_tx, NULL);
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
			fail_own_htlc(peer, h);
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
				   peer->local.commit->commit_num);
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

	/* FIXME-OLD #onchain:
	 *
	 * A node MAY send a descriptive error packet in this case.
	 */
	if (err && state_can_io(peer->state))
		queue_pkt_err(peer, err);

	/* Don't need to save to DB: it will be replayed if we crash. */
	set_peer_state(peer, newstate, "anchor_spent", false);

	/* If we've just closed connection, make output close it. */
	io_wake(peer);

	/* FIXME-OLD #onchain:
	 *
	 * A node SHOULD fail the connection if it is not already
	 * closed when it sees the funding transaction spent.
	 */
	assert(!state_can_io(peer->state));

	assert(peer->onchain.resolved != NULL);
	watch_tx(tx, peer, tx, check_for_resolution, NULL);

	return KEEP_WATCHING;

unknown_spend:
	/* FIXME-OLD #onchain:
	 *
	 * A node SHOULD report an error to the operator if it
	 * sees a transaction spend the funding transaction
	 * output which does not fall into one of these
	 * categories (mutual close, unilateral close, or
	 * cheating attempt).  Such a transaction implies its
	 * private key has leaked, and funds may be lost.
	 */
	/* FIXME: Save to db. */
	set_peer_state(peer, STATE_ERR_INFORMATION_LEAK, "anchor_spent", false);
	return DELETE_WATCH;
}

void peer_watch_anchor(struct peer *peer, int depth)
{
	log_debug_struct(peer->log, "watching for anchor %s",
			 struct sha256_double, &peer->anchor.txid);
	log_add(peer->log, " to hit depth %i", depth);

	peer->anchor.ok_depth = depth;
	watch_txid(peer, peer, &peer->anchor.txid, anchor_depthchange, NULL);
	watch_txo(peer, peer, &peer->anchor.txid, 0, anchor_spent, NULL);
}

struct bitcoin_tx *peer_create_close_tx(const tal_t *ctx,
					struct peer *peer, u64 fee)
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
		  cstate.side[LOCAL].pay_msat / 1000,
		  cstate.side[REMOTE].pay_msat / 1000);
	log_add_struct(peer->log, "%s", struct pubkey, &peer->local.finalkey);
	log_add_struct(peer->log, "/%s", struct pubkey, &peer->remote.finalkey);

 	return create_close_tx(ctx,
			       peer->closing.our_script,
			       peer->closing.their_script,
			       &peer->anchor.txid,
			       peer->anchor.index,
			       peer->anchor.satoshis,
			       cstate.side[LOCAL].pay_msat / 1000,
			       cstate.side[REMOTE].pay_msat / 1000);
}

/* Sets up the initial cstate and commit tx for both nodes: false if
 * insufficient funds. */
bool setup_first_commit(struct peer *peer)
{
	bool to_them_only, to_us_only;

	assert(!peer->local.commit->tx);
	assert(!peer->remote.commit->tx);

	/* Revocation hashes already filled in, from pkt_open */
	peer->local.commit->cstate = initial_cstate(peer->local.commit,
						    peer->anchor.satoshis,
						    peer->local.commit_fee_rate,
						    peer->local.offer_anchor ?
						    LOCAL : REMOTE);
	if (!peer->local.commit->cstate)
		return false;

	peer->remote.commit->cstate = initial_cstate(peer->remote.commit,
						     peer->anchor.satoshis,
						     peer->remote.commit_fee_rate,
						     peer->local.offer_anchor ?
						     LOCAL : REMOTE);
	if (!peer->remote.commit->cstate)
		return false;

	peer->local.commit->tx = create_commit_tx(peer->local.commit,
						  peer,
						  &peer->local.commit->revocation_hash,
						  peer->local.commit->cstate,
						  LOCAL, &to_them_only);
	bitcoin_txid(peer->local.commit->tx, &peer->local.commit->txid);

	peer->remote.commit->tx = create_commit_tx(peer->remote.commit,
						   peer,
						   &peer->remote.commit->revocation_hash,
						   peer->remote.commit->cstate,
						   REMOTE, &to_us_only);
	assert(to_them_only != to_us_only);

	/* If we offer anchor, their commit is to-us only. */
	assert(to_us_only == peer->local.offer_anchor);
	bitcoin_txid(peer->remote.commit->tx, &peer->remote.commit->txid);

	peer->local.staging_cstate = copy_cstate(peer, peer->local.commit->cstate);
	peer->remote.staging_cstate = copy_cstate(peer, peer->remote.commit->cstate);

	return true;
}

static struct io_plan *peer_reconnect(struct io_conn *conn, struct peer *peer)
{
	/* In case they reconnected to us already. */
	if (peer->conn)
		return io_close(conn);

	log_debug(peer->log, "Reconnected, doing crypto...");
	peer->conn = conn;
	assert(!peer->connected);

	assert(peer->id);
	return peer_crypto_setup(conn, peer->dstate,
				 peer->id, peer->log,
				 crypto_on_reconnect_out, peer);
}

/* We can't only retry when we want to send: they may want to send us
 * something but not be able to connect (NAT).  So keep retrying.. */
static void reconnect_failed(struct io_conn *conn, struct peer *peer)
{
	/* Already otherwise connected (ie. they connected in)? */
	if (peer->conn) {
		log_debug(peer->log, "reconnect_failed: already connected");
		return;
	}

	log_debug(peer->log, "Setting timer to re-connect");
	new_reltimer(peer->dstate, peer, time_from_sec(15), try_reconnect, peer);
}

static struct io_plan *init_conn(struct io_conn *conn, struct peer *peer)
{
	struct addrinfo a;
	struct peer_address *addr = find_address(peer->dstate, peer->id);

	netaddr_to_addrinfo(&a, &addr->addr);
	return io_connect(conn, &a, peer_reconnect, peer);
}

static void try_reconnect(struct peer *peer)
{
	struct io_conn *conn;
	struct peer_address *addr;
	char *name;
	int fd;

	/* Already reconnected? */
	if (peer->conn) {
		log_debug(peer->log, "try_reconnect: already connected");
		return;
	}

	addr = find_address(peer->dstate, peer->id);
	if (!addr) {
		log_debug(peer->log, "try_reconnect: no known address");
		return;
	}

	fd = socket(addr->addr.saddr.s.sa_family, addr->addr.type,
		    addr->addr.protocol);
	if (fd < 0) {
		log_broken(peer->log, "do_reconnect: failed to create socket: %s",
			   strerror(errno));
		peer_fail(peer, __func__);
		return;
	}

	assert(!peer->conn);
	conn = io_new_conn(peer->dstate, fd, init_conn, peer);
	name = netaddr_name(peer, &addr->addr);
	log_debug(peer->log, "Trying to reconnect to %s", name);
	tal_free(name);
	io_set_finish(conn, reconnect_failed, peer);
}

void reconnect_peers(struct lightningd_state *dstate)
{
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list)
		try_reconnect(peer);
}

/* We may have gone down before broadcasting the anchor.  Try again. */
void rebroadcast_anchors(struct lightningd_state *dstate)
{
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list) {
		if (!state_is_waiting_for_anchor(peer->state))
			continue;
		if (!peer->anchor.ours)
			continue;
		if (!bitcoin_create_anchor(peer))
			peer_fail(peer, __func__);
		else
			broadcast_tx(peer, peer->anchor.tx, NULL);
	}
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
			   struct peer *peer,
			   enum side owner)
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
		json_add_u64(response, "msatoshi", h->msatoshi);
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
			json_add_pubkey(response, "peerid", p->id);

		json_add_bool(response, "connected", p->connected);

		/* FIXME: Report anchor. */

		if (!p->local.commit || !p->local.commit->cstate) {
			json_object_end(response);
			continue;
		}
		last = p->local.commit->cstate;

		json_add_num(response, "our_amount", last->side[LOCAL].pay_msat);
		json_add_num(response, "our_fee", last->side[LOCAL].fee_msat);
		json_add_num(response, "their_amount", last->side[REMOTE].pay_msat);
		json_add_num(response, "their_fee", last->side[REMOTE].fee_msat);
		json_add_htlcs(response, "our_htlcs", p, LOCAL);
		json_add_htlcs(response, "their_htlcs", p, REMOTE);
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getpeers_command = {
	"getpeers",
	json_getpeers,
	"List the current peers",
	"Returns a 'peers' array"
};
AUTODATA(json_command, &getpeers_command);

static void json_gethtlcs(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *resolvedtok;
	bool resolved = false;
	struct json_result *response = new_json_result(cmd);
	struct htlc *h;
	struct htlc_map_iter it;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "?resolved", &resolvedtok,
			     NULL)) {
		command_fail(cmd, "Need peerid");
		return;
	}

	peer = find_peer_json(cmd->dstate, buffer, peeridtok);
	if (!peer) {
		command_fail(cmd, "Could not find peer with that peerid");
		return;
	}

	if (resolvedtok && !json_tok_bool(buffer, resolvedtok, &resolved)) {
		command_fail(cmd, "resolved must be true or false");
		return;
	}

	json_object_start(response, NULL);
	json_array_start(response, "htlcs");
	for (h = htlc_map_first(&peer->htlcs, &it);
	     h; h = htlc_map_next(&peer->htlcs, &it)) {
		if (htlc_is_dead(h) && !resolved)
			continue;

		json_object_start(response, NULL);
		json_add_u64(response, "id", h->id);
		json_add_string(response, "state", htlc_state_name(h->state));
		json_add_u64(response, "msatoshi", h->msatoshi);
		json_add_abstime(response, "expiry", &h->expiry);
		json_add_hex(response, "rhash", &h->rhash, sizeof(h->rhash));
		if (h->r)
			json_add_hex(response, "r", h->r, sizeof(*h->r));
		if (htlc_owner(h) == LOCAL) {
			json_add_num(response, "deadline", h->deadline);
			if (h->src) {
				json_object_start(response, "src");
				json_add_pubkey(response,
						"peerid", h->src->peer->id);
				json_add_u64(response, "id", h->src->id);
				json_object_end(response);
			}
		} else {
			if (h->routing)
				json_add_hex(response, "routing",
					     h->routing, tal_count(h->routing));
		}
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command gethtlcs_command = {
	"gethtlcs",
	json_gethtlcs,
	"List HTLCs for {peer}; all if {resolved} is true.",
	"Returns a 'htlcs' array"
};
AUTODATA(json_command, &gethtlcs_command);

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

static void json_newhtlc(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *msatoshitok, *expirytok, *rhashtok;
	unsigned int expiry;
	u64 msatoshi;
	struct sha256 rhash;
	struct json_result *response = new_json_result(cmd);
	struct htlc *htlc;
	const char *err;
	enum fail_error error_code;
	struct hoppayload *hoppayloads;
	u8 sessionkey[32];
	struct onionpacket *packet;
	u8 *onion;
	struct pubkey *path = tal_arrz(cmd, struct pubkey, 1);

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "msatoshi", &msatoshitok,
			     "expiry", &expirytok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need peerid, msatoshi, expiry and rhash");
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

	if (!peer->connected) {
		command_fail(cmd, "peer not connected");
		return;
	}

	if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshitok->end - msatoshitok->start),
			     buffer + msatoshitok->start);
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

	tal_arr(cmd, struct pubkey, 1);
	hoppayloads = tal_arrz(cmd, struct hoppayload, 1);
	memcpy(&path[0], peer->id, sizeof(struct pubkey));
	randombytes_buf(&sessionkey, sizeof(sessionkey));
	packet = create_onionpacket(cmd, path, hoppayloads, sessionkey,
				    rhash.u.u8, sizeof(rhash));
	onion = serialize_onionpacket(cmd, packet);

	log_debug(peer->log, "JSON command to add new HTLC");
	err = command_htlc_add(peer, msatoshi, expiry, &rhash, NULL,
			       onion,
			       &error_code, &htlc);
	if (err) {
		command_fail(cmd, "could not add htlc: %u:%s", error_code, err);
		return;
	}
	log_debug(peer->log, "JSON new HTLC is %"PRIu64, htlc->id);

	json_object_start(response, NULL);
	json_add_u64(response, "id", htlc->id);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command dev_newhtlc_command = {
	"dev-newhtlc",
	json_newhtlc,
	"Offer {peerid} an HTLC worth {msatoshi} in {expiry} (block number) with {rhash}",
	"Returns { id: u64 } result on success"
};
AUTODATA(json_command, &dev_newhtlc_command);

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

	if (!peer->connected) {
		command_fail(cmd, "peer not connected");
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

	/* This can happen if we're disconnected, and thus haven't sent
	 * fulfill yet; we stored r in database immediately. */
	if (!htlc->r) {
		const char *db_err;

		db_start_transaction(peer);
		set_htlc_rval(peer, htlc, &r);

		/* We can relay this upstream immediately. */
		our_htlc_fulfilled(peer, htlc);
		db_err = db_commit_transaction(peer);
		if (db_err) {
			command_fail(cmd, "%s", db_err);
			return;
		}
	}

	if (command_htlc_fulfill(peer, htlc))
		command_success(cmd, null_response(cmd));
	else
		command_fail(cmd,
			     "htlc_fulfill not possible in state %s",
			     state_name(peer->state));
}

static const struct json_command dev_fulfillhtlc_command = {
	"dev-fulfillhtlc",
	json_fulfillhtlc,
	"Redeem htlc proposed by {peerid} of {id} using {r}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_fulfillhtlc_command);

static void json_failhtlc(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok, *idtok, *reasontok;
	u64 id;
	struct htlc *htlc;
	const char *db_err;

	if (!json_get_params(buffer, params,
			     "peerid", &peeridtok,
			     "id", &idtok,
			     "reason", &reasontok,
			     NULL)) {
		command_fail(cmd, "Need peerid, id and reason");
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

	if (!peer->connected) {
		command_fail(cmd, "peer not connected");
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

	db_start_transaction(peer);

	set_htlc_fail(peer, htlc, buffer + reasontok->start,
		      reasontok->end - reasontok->start);

	db_err = db_commit_transaction(peer);
	if (db_err) {
		command_fail(cmd, "%s", db_err);
		return;
	}

	if (command_htlc_fail(peer, htlc))
		command_success(cmd, null_response(cmd));
	else
		command_fail(cmd,
			     "htlc_fail not possible in state %s",
			     state_name(peer->state));
}

static const struct json_command dev_failhtlc_command = {
	"dev-failhtlc",
	json_failhtlc,
	"Fail htlc proposed by {peerid} which has {id}, using {reason}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_failhtlc_command);

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

	if (!peer->connected) {
		command_fail(cmd, "peer not connected");
		return;
	}

	if (!state_can_commit(peer->state)) {
		command_fail(cmd, "peer in state %s", state_name(peer->state));
		return;
	}

	do_commit(peer, cmd);
}

static const struct json_command dev_commit_command = {
	"dev-commit",
	json_commit,
	"Commit all staged HTLC changes with {peerid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_commit_command);

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

	if (!peer_start_shutdown(peer)) {
		command_fail(cmd, "Database error");
		return;
	}
	/* FIXME: Block until closed! */
	command_success(cmd, null_response(cmd));
}

static const struct json_command close_command = {
	"close",
	json_close,
	"Close the channel with peer {peerid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &close_command);

static void json_feerate(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *feeratetok;
	u64 feerate;

	if (!json_get_params(buffer, params,
			     "feerate", &feeratetok,
			     NULL)) {
		command_fail(cmd, "Need feerate");
		return;
	}

	if (!json_tok_u64(buffer, feeratetok, &feerate)) {
		command_fail(cmd, "Invalid feerate");
		return;
	}
	log_debug(cmd->jcon->log, "Fee rate changed to %"PRIu64, feerate);
	cmd->dstate->config.default_fee_rate = feerate;

	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_feerate_command = {
	"dev-feerate",
	json_feerate,
	"Change the (default) fee rate to {feerate}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_feerate_command);

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
	peer->connected = false;
	peer_fail(peer, __func__);

	command_success(cmd, null_response(cmd));
}

static void json_reconnect(struct command *cmd,
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

	/* Should reconnect on its own. */
	io_close(peer->conn);
	command_success(cmd, null_response(cmd));
}

static void json_signcommit(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	struct peer *peer;
	jsmntok_t *peeridtok;
	u8 *linear;
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

	sign_commit_tx(peer);
	linear = linearize_tx(cmd, peer->local.commit->tx);

	/* Clear witness for potential future uses. */
	peer->local.commit->tx->input[0].witness
		= tal_free(peer->local.commit->tx->input[0].witness);

	json_object_start(response, NULL);
	json_add_string(response, "tx", tal_hex(cmd, linear));
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
static const struct json_command dev_output_command = {
	"dev-output",
	json_output,
	"Enable/disable any messages to peer {peerid} depending on {enable}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_output_command);

static const struct json_command dev_disconnect_command = {
	"dev-disconnect",
	json_disconnect,
	"Force a disconnect with peer {peerid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_disconnect_command);

static const struct json_command dev_reconnect_command = {
	"dev-reconnect",
	json_reconnect,
	"Force a reconnect with peer {peerid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_reconnect_command);

static const struct json_command dev_signcommit_command = {
	"dev-signcommit",
	json_signcommit,
	"Sign and return the current commit with peer {peerid}",
	"Returns a hex string on success"
};
AUTODATA(json_command, &dev_signcommit_command);
