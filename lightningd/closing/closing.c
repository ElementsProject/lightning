#include <bitcoin/script.h>
#include <close_tx.h>
#include <daemon/htlc.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/closing/gen_closing_wire.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/debug.h>
#include <lightningd/derive_basepoints.h>
#include <lightningd/status.h>
#include <lightningd/subd.h>
#include <signal.h>
#include <stdio.h>
#include <type_to_string.h>
#include <utils.h>
#include <version.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4

static struct bitcoin_tx *close_tx(const tal_t *ctx,
				   u8 *scriptpubkey[NUM_SIDES],
				   const struct sha256_double *funding_txid,
				   unsigned int funding_txout,
				   u64 funding_satoshi,
				   const u64 satoshi_out[NUM_SIDES],
				   enum side funder,
				   uint64_t fee,
				   uint64_t dust_limit)
{
	struct bitcoin_tx *tx;

	if (satoshi_out[funder] < fee)
		status_failed(WIRE_CLOSING_NEGOTIATION_ERROR,
			      "Funder cannot afford fee %"PRIu64
			      " (%"PRIu64" and %"PRIu64")",
			      fee, satoshi_out[LOCAL],
			      satoshi_out[REMOTE]);

	tx = create_close_tx(ctx, scriptpubkey[LOCAL], scriptpubkey[REMOTE],
			     funding_txid,
			     funding_txout,
			     funding_satoshi,
			     satoshi_out[LOCAL] - (funder == LOCAL ? fee : 0),
			     satoshi_out[REMOTE] - (funder == REMOTE ? fee : 0),
			     dust_limit);
	if (!tx)
		status_failed(WIRE_CLOSING_NEGOTIATION_ERROR,
			      "Both outputs below dust limit");
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

int main(int argc, char *argv[])
{
	struct crypto_state cs;
	const tal_t *ctx = tal_tmpctx(NULL);
	u8 *msg;
	struct privkey seed;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct sha256_double funding_txid;
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

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	subdaemon_debug(argc, argv);

	/* We handle write returning errors! */
	signal(SIGCHLD, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	status_setup_sync(REQ_FD);

	msg = wire_sync_read(ctx, REQ_FD);
	if (!fromwire_closing_init(ctx, msg, NULL,
				   &cs, &seed,
				   &funding_txid, &funding_txout,
				   &funding_satoshi,
				   &funding_pubkey[REMOTE],
				   &funder,
				   &satoshi_out[LOCAL],
				   &satoshi_out[REMOTE],
				   &our_dust_limit,
				   &minfee, &maxfee, &sent_fee,
				   &scriptpubkey[LOCAL],
				   &scriptpubkey[REMOTE])) {
		status_failed(WIRE_CLOSING_PEER_BAD_MESSAGE,
			      "Bad init message %s", tal_hex(ctx, msg));
	}
	derive_channel_id(&channel_id, &funding_txid, funding_txout);
	derive_basepoints(&seed, &funding_pubkey[LOCAL], NULL,
			  &secrets, NULL);

	funding_wscript = bitcoin_redeem_2of2(ctx,
					      &funding_pubkey[LOCAL],
					      &funding_pubkey[REMOTE]);

	/* BOLT #2:
	 *
	 * Nodes SHOULD send a `closing_signed` message after `shutdown` has
	 * been received and no HTLCs remain in either commitment transaction.
	 */
	/* BOLT #2:
	 *
	 * On reconnection, ... if the node has sent a previous
	 * `closing_signed` it MUST then retransmit the last `closing_signed`.
	 */
	for (;;) {
		const tal_t *tmpctx = tal_tmpctx(ctx);
		struct bitcoin_tx *tx;
		u64 received_fee, limit_fee, new_fee;

		/* BOLT #2:
		 *
		 * The sender MUST set `signature` to the Bitcoin signature of
		 * the close transaction with the node responsible for paying
		 * the bitcoin fee paying `fee_satoshis`, then removing any
		 * output which is below its own `dust_limit_satoshis`. The
		 * sender MAY then also eliminate its own output from the
		 * mutual close transaction.
		 */
		tx = close_tx(tmpctx, scriptpubkey,
			      &funding_txid,
			      funding_txout,
			      funding_satoshi,
			      satoshi_out, funder, sent_fee, our_dust_limit);
		if (!tx)
			status_failed(WIRE_CLOSING_NEGOTIATION_ERROR,
				      "Both outputs below dust limit");

		/* BOLT #2:
		 *
		 * The sender MAY then also eliminate its own output from the
		 * mutual close transaction.
		 */
		/* (We don't do this). */
		sign_tx_input(tx, 0, NULL, funding_wscript,
			      &secrets.funding_privkey,
			      &funding_pubkey[LOCAL],
			      &sig);

		/* Tell master we're making an offer, wait for db commit. */
		msg = towire_closing_offered_signature(tmpctx, sent_fee, &sig);
		if (!wire_sync_write(REQ_FD, msg))
			status_failed(WIRE_CLOSING_INTERNAL_ERROR,
				      "Writing offer to master failed: %s",
				      strerror(errno));
		msg = wire_sync_read(tmpctx, REQ_FD);
		if (!fromwire_closing_offered_signature_reply(msg, NULL))
			status_failed(WIRE_CLOSING_INTERNAL_ERROR,
				      "Reading offer reply from master failed");

		status_trace("sending fee offer %"PRIu64, sent_fee);

		/* Now send closing offer */
		msg = towire_closing_signed(tmpctx, &channel_id, sent_fee, &sig);
		if (!sync_crypto_write(&cs, PEER_FD, take(msg)))
			status_failed(WIRE_CLOSING_PEER_WRITE_FAILED,
				      "Writing closing_signed");

		/* Did we just agree with them?  If so, we're done. */
		if (sent_fee == last_received_fee)
			break;

	again:
		msg = sync_crypto_read(tmpctx, &cs, PEER_FD);
		if (!msg)
			status_failed(WIRE_CLOSING_PEER_READ_FAILED,
				      "Reading input");

		/* We don't send gossip at this stage, but we can recv it */
		if (is_gossip_msg(msg)) {
			if (!wire_sync_write(GOSSIP_FD, take(msg)))
				status_failed(WIRE_CLOSING_GOSSIP_FAILED,
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

		if (!fromwire_closing_signed(msg, NULL, &channel_id,
					     &received_fee, &sig))
			status_failed(WIRE_CLOSING_PEER_BAD_MESSAGE,
				      "Expected closing_signed: %s",
				      tal_hex(trc, msg));

		/* BOLT #2:
		 *
		 * The receiver MUST check `signature` is valid for either the
		 * close transaction with the given `fee_satoshis` as detailed
		 * above and its own `dust_limit_satoshis` OR that same
		 * transaction with the sender's output eliminated, and MUST
		 * fail the connection if it is not.
		 */
		tx = close_tx(tmpctx, scriptpubkey,
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

			trimmed = close_tx(tmpctx, scriptpubkey,
					   &funding_txid,
					   funding_txout,
					   funding_satoshi,
					   trimming_satoshi_out,
					   funder, received_fee, our_dust_limit);
			if (!trimmed
			    || !check_tx_sig(trimmed, 0, NULL, funding_wscript,
					     &funding_pubkey[REMOTE], &sig)) {
				status_failed(WIRE_CLOSING_PEER_BAD_MESSAGE,
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
		}

		status_trace("Received fee offer %"PRIu64, received_fee);

		/* Is fee reasonable?  Tell master. */
		if (received_fee < minfee) {
			status_trace("Fee too low, below %"PRIu64, minfee);
			limit_fee = minfee;
		} else if (received_fee > maxfee) {
			status_trace("Fee too high, above %"PRIu64, maxfee);
			limit_fee = maxfee;
		} else {
			status_trace("Fee accepted.");
			msg = towire_closing_received_signature(tmpctx,
								received_fee,
								&sig);
			if (!wire_sync_write(REQ_FD, take(msg)))
				status_failed(WIRE_CLOSING_INTERNAL_ERROR,
					      "Writing received to master: %s",
					      strerror(errno));
			msg = wire_sync_read(tmpctx, REQ_FD);
			if (!fromwire_closing_received_signature_reply(msg,NULL))
				status_failed(WIRE_CLOSING_INTERNAL_ERROR,
					      "Bad received reply from master");
			limit_fee = received_fee;
		}

		/* BOLT #2:
		 *
		 * Once a node has sent or received a `closing_signed` with
		 * matching `fee_satoshis` it SHOULD close the connection and
		 * SHOULD sign and broadcast the final closing transaction.
		 */
		if (received_fee == sent_fee)
			break;

		/* Check that they moved in right direction.  Not really
		 * a requirement that we check, but good to catch their bugs. */
		if (last_received_fee != -1) {
			bool previous_dir = sent_fee < last_received_fee;
			bool dir = received_fee < last_received_fee;
			bool next_dir = sent_fee < received_fee;

			/* They went away from our offer? */
			if (dir != previous_dir)
				status_failed(WIRE_CLOSING_NEGOTIATION_ERROR,
					      "Their fee went %"
					      PRIu64" to %"PRIu64
					      " when ours was %"PRIu64,
					      last_received_fee,
					      received_fee,
					      sent_fee);

			/* They jumped over our offer? */
			if (next_dir != previous_dir)
				status_failed(WIRE_CLOSING_NEGOTIATION_ERROR,
					      "Their fee jumped %"
					      PRIu64" to %"PRIu64
					      " when ours was %"PRIu64,
					      last_received_fee,
					      received_fee,
					      sent_fee);
		}

		/* BOLT #2:
		 *
		 * ...otherwise it SHOULD propose a value strictly between the
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
			status_failed(WIRE_CLOSING_NEGOTIATION_ERROR,
				      "Final fee %"PRIu64" vs %"PRIu64
				      " at limits %"PRIu64"-%"PRIu64,
				      sent_fee, received_fee,
				      minfee, maxfee);

		last_received_fee = received_fee;
		sent_fee = new_fee;
		tal_free(tmpctx);
	}

	/* We're done! */
	wire_sync_write(REQ_FD, take(towire_closing_complete(ctx)));
	tal_free(ctx);

	return 0;
}
