#include <bitcoin/script.h>
#include <closingd/gen_closing_wire.h>
#include <common/close_tx.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/htlc.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4

static struct bitcoin_tx *close_tx(const tal_t *ctx,
				   struct crypto_state *cs,
				   const struct channel_id *channel_id,
				   u8 *scriptpubkey[NUM_SIDES],
				   const struct bitcoin_txid *funding_txid,
				   unsigned int funding_txout,
				   u64 funding_satoshi,
				   const u64 satoshi_out[NUM_SIDES],
				   enum side funder,
				   uint64_t fee,
				   uint64_t dust_limit)
{
	struct bitcoin_tx *tx;

	if (satoshi_out[funder] < fee)
		peer_failed(PEER_FD, cs, channel_id,
			      "Funder cannot afford fee %"PRIu64
			      " (%"PRIu64" and %"PRIu64")",
			      fee, satoshi_out[LOCAL],
			      satoshi_out[REMOTE]);

	status_trace("Making close tx at = %"PRIu64"/%"PRIu64" fee %"PRIu64,
		     satoshi_out[LOCAL], satoshi_out[REMOTE], fee);

	/* FIXME: We need to allow this! */
	tx = create_close_tx(ctx,
			     scriptpubkey[LOCAL], scriptpubkey[REMOTE],
			     funding_txid,
			     funding_txout,
			     funding_satoshi,
			     satoshi_out[LOCAL] - (funder == LOCAL ? fee : 0),
			     satoshi_out[REMOTE] - (funder == REMOTE ? fee : 0),
			     dust_limit);
	if (!tx)
		peer_failed(PEER_FD, cs, channel_id,
			    "Both outputs below dust limit:"
			    " funding = %"PRIu64
			    " fee = %"PRIu64
			    " dust_limit = %"PRIu64
			    " LOCAL = %"PRIu64
			    " REMOTE = %"PRIu64,
			    funding_satoshi,
			    fee,
			    dust_limit,
			    satoshi_out[LOCAL],
			    satoshi_out[REMOTE]);
	return tx;
}

static u64 one_towards(u64 target, u64 value)
{
	if (value > target)
		return value-1;
	else if (value < target)
		return value+1;
	return value;
}

static void do_reconnect(struct crypto_state *cs,
			 const struct channel_id *channel_id,
			 const u64 next_index[NUM_SIDES],
			 u64 revocations_received)
{
	u8 *msg;
	struct channel_id their_channel_id;
	const tal_t *tmpctx = tal_tmpctx(NULL);
	u64 next_local_commitment_number, next_remote_revocation_number;

	/* BOLT #2:
	 *
	 * On reconnection, a node MUST transmit `channel_reestablish` for
	 * each channel, and MUST wait for to receive the other node's
	 * `channel_reestablish` message before sending any other messages for
	 * that channel.  The sending node MUST set
	 * `next_local_commitment_number` to the commitment number of the next
	 * `commitment_signed` it expects to receive, and MUST set
	 * `next_remote_revocation_number` to the commitment number of the
	 * next `revoke_and_ack` message it expects to receive.
	 */
	msg = towire_channel_reestablish(tmpctx, channel_id,
					 next_index[LOCAL],
					 revocations_received);
	if (!sync_crypto_write(cs, PEER_FD, take(msg)))
		status_failed(STATUS_FAIL_PEER_IO,
			      "Failed writing reestablish: %s", strerror(errno));

again:
	msg = sync_crypto_read(tmpctx, cs, PEER_FD);
	if (!msg)
		status_failed(STATUS_FAIL_PEER_IO,
			      "Failed reading reestablish: %s", strerror(errno));

	if (is_gossip_msg(msg)) {
		if (!wire_sync_write(GOSSIP_FD, take(msg)))
			status_failed(STATUS_FAIL_GOSSIP_IO, "Writing gossip");
		goto again;
	}

	if (!fromwire_channel_reestablish(msg, NULL, &their_channel_id,
					  &next_local_commitment_number,
					  &next_remote_revocation_number)) {
		peer_failed(PEER_FD, cs, channel_id,
			    "bad reestablish msg: %s %s",
			    wire_type_name(fromwire_peektype(msg)),
			    tal_hex(tmpctx, msg));
	}
	status_trace("Got reestablish commit=%"PRIu64" revoke=%"PRIu64,
		     next_local_commitment_number,
		     next_remote_revocation_number);

	/* FIXME: Spec says to re-xmit funding_locked here if we haven't
	 * done any updates. */

	/* BOLT #2:
	 *
	 * On reconnection if the node has sent a previous `closing_signed` it
	 * MUST send another `closing_signed`
	 */

	/* Since we always transmit closing_signed immediately, if
	 * we're reconnecting we consider ourselves to have transmitted once,
	 * and we'll immediately do the retransmit now anyway. */
	tal_free(tmpctx);
}

int main(int argc, char *argv[])
{
	struct crypto_state cs;
	const tal_t *ctx = tal_tmpctx(NULL);
	u8 *msg;
	struct privkey seed;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	u64 funding_satoshi, satoshi_out[NUM_SIDES];
	u64 our_dust_limit;
	u64 minfee, maxfee, sent_fee;
	s64 last_received_fee = -1;
	enum side funder;
	u8 *scriptpubkey[NUM_SIDES], *funding_wscript;
	struct channel_id channel_id;
	struct secrets secrets;
	secp256k1_ecdsa_signature sig;
	bool reconnected;
	u64 next_index[NUM_SIDES], revocations_received;
	u64 gossip_index;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(ctx, REQ_FD);
	if (!fromwire_closing_init(ctx, msg, NULL,
				   &cs, &gossip_index, &seed,
				   &funding_txid, &funding_txout,
				   &funding_satoshi,
				   &funding_pubkey[REMOTE],
				   &funder,
				   &satoshi_out[LOCAL],
				   &satoshi_out[REMOTE],
				   &our_dust_limit,
				   &minfee, &maxfee, &sent_fee,
				   &scriptpubkey[LOCAL],
				   &scriptpubkey[REMOTE],
				   &reconnected,
				   &next_index[LOCAL],
				   &next_index[REMOTE],
				   &revocations_received))
		master_badmsg(WIRE_CLOSING_INIT, msg);

	status_trace("satoshi_out = %"PRIu64"/%"PRIu64,
		     satoshi_out[LOCAL], satoshi_out[REMOTE]);
	status_trace("dustlimit = %"PRIu64, our_dust_limit);
	status_trace("fee = %"PRIu64, sent_fee);
	derive_channel_id(&channel_id, &funding_txid, funding_txout);
	derive_basepoints(&seed, &funding_pubkey[LOCAL], NULL,
			  &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(ctx,
					      &funding_pubkey[LOCAL],
					      &funding_pubkey[REMOTE]);

	if (reconnected)
		do_reconnect(&cs, &channel_id, next_index, revocations_received);

	/* BOLT #2:
	 *
	 * Nodes SHOULD send a `closing_signed` message after `shutdown` has
	 * been received and no HTLCs remain in either commitment transaction.
	 */

	/* BOLT #2:
	 *
	 * On reconnection, ... if the node has sent a previous
	 * `closing_signed` it MUST send another `closing_signed`, otherwise
	 * if the node has sent a previous `shutdown` it MUST retransmit it.
	 */
	for (;;) {
		const tal_t *tmpctx = tal_tmpctx(ctx);
		struct bitcoin_tx *tx;
		u64 received_fee, limit_fee, new_fee;

		/* BOLT #2:
		 *
		 * The sender MUST set `signature` to the Bitcoin signature of
		 * the close transaction as specified in [BOLT
		 * #3](03-transactions.md#closing-transaction).
		 */
		tx = close_tx(tmpctx, &cs, &channel_id,
			      scriptpubkey,
			      &funding_txid,
			      funding_txout,
			      funding_satoshi,
			      satoshi_out, funder, sent_fee, our_dust_limit);

		/* BOLT #3:
		 *
		 * ## Closing Transaction
		 *...
		 * Each node offering a signature... MAY also eliminate its
		 * own output.
		 */
		/* (We don't do this). */
		sign_tx_input(tx, 0, NULL, funding_wscript,
			      &secrets.funding_privkey,
			      &funding_pubkey[LOCAL],
			      &sig);

		status_trace("sending fee offer %"PRIu64, sent_fee);

		/* Now send closing offer */
		msg = towire_closing_signed(tmpctx, &channel_id, sent_fee, &sig);
		if (!sync_crypto_write(&cs, PEER_FD, take(msg)))
			status_failed(STATUS_FAIL_PEER_IO,
				      "Writing closing_signed");

		/* Did we just agree with them?  If so, we're done. */
		if (sent_fee == last_received_fee)
			break;

	again:
		msg = sync_crypto_read(tmpctx, &cs, PEER_FD);
		if (!msg)
			status_failed(STATUS_FAIL_PEER_IO, "Reading input");

		/* We don't send gossip at this stage, but we can recv it */
		if (is_gossip_msg(msg)) {
			if (!wire_sync_write(GOSSIP_FD, take(msg)))
				status_failed(STATUS_FAIL_GOSSIP_IO,
					      "Writing gossip");
			goto again;
		}

		/* BOLT #2:
		 *
		 * On reconnection, a node MUST ignore a redundant
		 * `funding_locked` if it receives one.
		 */
		/* This should only happen if we've made no commitments, but
		 * we don't have to check that: it's their problem. */
		if (fromwire_peektype(msg) == WIRE_FUNDING_LOCKED) {
			tal_free(msg);
			goto again;
		}

		/* BOLT #2:
		 *
		 * ...if the node has sent a previous `shutdown` it MUST
		 * retransmit it.
		 */
		if (fromwire_peektype(msg) == WIRE_SHUTDOWN) {
			tal_free(msg);
			goto again;
		}

		if (!fromwire_closing_signed(msg, NULL, &channel_id,
					     &received_fee, &sig))
			peer_failed(PEER_FD, &cs, &channel_id,
				    "Expected closing_signed: %s",
				    tal_hex(trc, msg));

		/* BOLT #2:
		 *
		 * The receiver MUST check `signature` is valid for either
		 * variant of close transaction specified in [BOLT
		 * #3](03-transactions.md#closing-transaction), and MUST fail
		 * the connection if it is not.
		 */
		tx = close_tx(tmpctx, &cs, &channel_id,
			      scriptpubkey,
			      &funding_txid,
			      funding_txout,
			      funding_satoshi,
			      satoshi_out, funder, received_fee, our_dust_limit);

		if (!check_tx_sig(tx, 0, NULL, funding_wscript,
				  &funding_pubkey[REMOTE], &sig)) {
			/* Trim it by reducing their output to minimum */
			struct bitcoin_tx *trimmed;
			u64 trimming_satoshi_out[NUM_SIDES];

			if (funder == REMOTE)
				trimming_satoshi_out[REMOTE] = received_fee;
			else
				trimming_satoshi_out[REMOTE] = 0;
			trimming_satoshi_out[LOCAL] = satoshi_out[LOCAL];

			/* BOLT #3:
			 *
			 * Each node offering a signature MUST subtract the
			 * fee given by `fee_satoshis` from the output to the
			 * funder; it MUST then remove any output below its
			 * own `dust_limit_satoshis`, and MAY also eliminate
			 * its own output.
			*/
			trimmed = close_tx(tmpctx, &cs, &channel_id,
					   scriptpubkey,
					   &funding_txid,
					   funding_txout,
					   funding_satoshi,
					   trimming_satoshi_out,
					   funder, received_fee, our_dust_limit);
			if (!trimmed
			    || !check_tx_sig(trimmed, 0, NULL, funding_wscript,
					     &funding_pubkey[REMOTE], &sig)) {
				peer_failed(PEER_FD, &cs, &channel_id,
					      "Bad closing_signed signature for"
					      " %s (and trimmed version %s)",
					      type_to_string(tmpctx,
							     struct bitcoin_tx,
							     tx),
					      trimmed ?
					      type_to_string(tmpctx,
							     struct bitcoin_tx,
							     trimmed)
					      : "NONE");
			}
			tx = trimmed;
		}

		status_trace("Received fee offer %"PRIu64, received_fee);

		/* BOLT #2:
		 *
		 * Otherwise, the recipient MUST fail the connection if
		 * `fee_satoshis` is greater than the base fee of the final
		 * commitment transaction as calculated in [BOLT #3] */
		if (received_fee > maxfee)
			peer_failed(PEER_FD, &cs, &channel_id,
				    "Bad closing_signed fee %"PRIu64" > %"PRIu64,
				    received_fee, maxfee);

		/* Is fee reasonable?  Tell master. */
		if (received_fee < minfee) {
			status_trace("Fee too low, below %"PRIu64, minfee);
			limit_fee = minfee;
		} else {
			status_trace("Fee accepted.");
			msg = towire_closing_received_signature(tmpctx,
								&sig, tx);
			if (!wire_sync_write(REQ_FD, take(msg)))
				status_failed(STATUS_FAIL_MASTER_IO,
					      "Writing received to master: %s",
					      strerror(errno));
			msg = wire_sync_read(tmpctx, REQ_FD);
			if (!fromwire_closing_received_signature_reply(msg,NULL))
				master_badmsg(WIRE_CLOSING_RECEIVED_SIGNATURE_REPLY,
					      msg);
			limit_fee = received_fee;
		}

		/* BOLT #2:
		 *
		 * If `fee_satoshis` is equal to its previously sent
		 * `fee_satoshis`, the receiver SHOULD sign and broadcast the
		 * final closing transaction and MAY close the connection.
		 */
		if (received_fee == sent_fee)
			break;

		/* BOLT #2:
		 *
		 * the recipient SHOULD fail the connection if `fee_satoshis`
		 * is not strictly between its last-sent `fee_satoshis` and
		 * its previously-received `fee_satoshis`, unless it has
		 * reconnected since then. */
		if (last_received_fee != -1) {
			bool previous_dir = sent_fee < last_received_fee;
			bool dir = received_fee < last_received_fee;
			bool next_dir = sent_fee < received_fee;

			/* They went away from our offer? */
			if (dir != previous_dir)
				peer_failed(PEER_FD, &cs, &channel_id,
					    "Their fee went %"
					    PRIu64" to %"PRIu64
					    " when ours was %"PRIu64,
					    last_received_fee,
					    received_fee,
					    sent_fee);

			/* They jumped over our offer? */
			if (next_dir != previous_dir)
				peer_failed(PEER_FD, &cs, &channel_id,
					    "Their fee jumped %"
					    PRIu64" to %"PRIu64
					    " when ours was %"PRIu64,
					    last_received_fee,
					    received_fee,
					    sent_fee);
		}

		/* BOLT #2:
		 *
		 * ...otherwise it MUST propose a value strictly between the
		 * received `fee_satoshis` and its previously-sent
		 * `fee_satoshis`.
		 */

		/* We do it by bisection, with twists:
		 * 1. Don't go outside limits, or reach them immediately:
		 *    treat out-of-limit offers as on-limit offers.
		 * 2. Round towards the target, otherwise we can't close
		 *    a final 1-satoshi gap.
		 *
		 * Note: Overflow impossible here, since fee <= funder amount */
		new_fee = one_towards(limit_fee, limit_fee + sent_fee) / 2;

		/* If we didn't move, give up (we're ~ at min/max). */
		if (new_fee == sent_fee)
			peer_failed(PEER_FD, &cs, &channel_id,
				      "Final fee %"PRIu64" vs %"PRIu64
				      " at limits %"PRIu64"-%"PRIu64,
				      sent_fee, received_fee,
				      minfee, maxfee);

		last_received_fee = received_fee;
		sent_fee = new_fee;
		tal_free(tmpctx);
	}

	/* We're done! */
	wire_sync_write(REQ_FD,
			take(towire_closing_complete(ctx, gossip_index)));
	tal_free(ctx);

	return 0;
}
