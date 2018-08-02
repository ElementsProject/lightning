#include <bitcoin/script.h>
#include <closingd/gen_closing_wire.h>
#include <common/close_tx.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/htlc.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/read_peer_msg.h>
#include <common/socket_close.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <errno.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4
#define HSM_FD 5

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
		peer_failed(cs, channel_id,
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
		peer_failed(cs, channel_id,
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

/* Handle random messages we might get, returning the first non-handled one. */
static u8 *closing_read_peer_msg(const tal_t *ctx,
				 struct crypto_state *cs,
				 const struct channel_id *channel_id)
{
	for (;;) {
		u8 *msg;
		bool from_gossipd;

		clean_tmpctx();
		msg = peer_or_gossip_sync_read(ctx, PEER_FD, GOSSIP_FD,
					       cs, &from_gossipd);
		if (from_gossipd) {
			handle_gossip_msg(PEER_FD, cs, take(msg));
			continue;
		}
		if (!handle_peer_gossip_or_error(PEER_FD, GOSSIP_FD, cs,
						 channel_id, msg))
			return msg;
	}
}

static void do_reconnect(struct crypto_state *cs,
			 const struct channel_id *channel_id,
			 const u64 next_index[NUM_SIDES],
			 u64 revocations_received,
			 const u8 *channel_reestablish)
{
	u8 *msg;
	struct channel_id their_channel_id;
	u64 next_local_commitment_number, next_remote_revocation_number;

	/* BOLT #2:
	 *
	 *   - upon reconnection:
	 *     - if a channel is in an error state:
	 *       - SHOULD retransmit the error packet and ignore any other packets for
	 *        that channel.
	 *     - otherwise:
	 *       - MUST transmit `channel_reestablish` for each channel.
	 *       - MUST wait to receive the other node's `channel_reestablish`
	 *         message before sending any other messages for that channel.
	 *
	 * The sending node:
	 *   - MUST set `next_local_commitment_number` to the commitment number
	 *     of the next `commitment_signed` it expects to receive.
	 *   - MUST set `next_remote_revocation_number` to the commitment number
	 *     of the next `revoke_and_ack` message it expects to receive.
	 */
	msg = towire_channel_reestablish(NULL, channel_id,
					 next_index[LOCAL],
					 revocations_received);
	sync_crypto_write(cs, PEER_FD, take(msg));

	/* They might have already send reestablish, which triggered us */
	if (!channel_reestablish)
		channel_reestablish = closing_read_peer_msg(tmpctx, cs, channel_id);

	if (!fromwire_channel_reestablish(channel_reestablish, &their_channel_id,
					  &next_local_commitment_number,
					  &next_remote_revocation_number)) {
		peer_failed(cs, channel_id,
			    "bad reestablish msg: %s %s",
			    wire_type_name(fromwire_peektype(channel_reestablish)),
			    tal_hex(tmpctx, channel_reestablish));
	}
	status_trace("Got reestablish commit=%"PRIu64" revoke=%"PRIu64,
		     next_local_commitment_number,
		     next_remote_revocation_number);

	/* FIXME: Spec says to re-xmit funding_locked here if we haven't
	 * done any updates. */
}

static void send_offer(struct crypto_state *cs,
		       const struct channel_id *channel_id,
		       const struct pubkey funding_pubkey[NUM_SIDES],
		       u8 *scriptpubkey[NUM_SIDES],
		       const struct bitcoin_txid *funding_txid,
		       unsigned int funding_txout,
		       u64 funding_satoshi,
		       const u64 satoshi_out[NUM_SIDES],
		       enum side funder,
		       uint64_t our_dust_limit,
		       uint64_t fee_to_offer)
{
	struct bitcoin_tx *tx;
	secp256k1_ecdsa_signature our_sig;
	u8 *msg;

	/* BOLT #2:
	 *
	 *   - MUST set `signature` to the Bitcoin signature of the close
	 *     transaction, as specified in [BOLT
	 *     #3](03-transactions.md#closing-transaction).
	 */
	tx = close_tx(tmpctx, cs, channel_id,
		      scriptpubkey,
		      funding_txid,
		      funding_txout,
		      funding_satoshi,
		      satoshi_out,
		      funder, fee_to_offer, our_dust_limit);

	/* BOLT #3:
	 *
	 * ## Closing Transaction
	 *...
	 * Each node offering a signature... MAY eliminate its
	 * own output.
	 */
	/* (We don't do this). */
	wire_sync_write(HSM_FD,
			take(towire_hsm_sign_mutual_close_tx(NULL,
							     tx,
							     &funding_pubkey[REMOTE],
							     funding_satoshi)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &our_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsm_sign_mutual_close_tx reply %s",
			      tal_hex(tmpctx, msg));

	status_trace("sending fee offer %"PRIu64, fee_to_offer);

	msg = towire_closing_signed(NULL, channel_id, fee_to_offer, &our_sig);
	sync_crypto_write(cs, PEER_FD, take(msg));
}

static void tell_master_their_offer(const secp256k1_ecdsa_signature *their_sig,
				    const struct bitcoin_tx *tx)
{
	u8 *msg = towire_closing_received_signature(NULL, their_sig, tx);
	if (!wire_sync_write(REQ_FD, take(msg)))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Writing received to master: %s",
			      strerror(errno));

	/* Wait for master to ack, to make sure it's in db. */
	msg = wire_sync_read(NULL, REQ_FD);
	if (!fromwire_closing_received_signature_reply(msg))
		master_badmsg(WIRE_CLOSING_RECEIVED_SIGNATURE_REPLY, msg);
	tal_free(msg);
}

/* Returns fee they offered. */
static uint64_t receive_offer(struct crypto_state *cs,
			      const struct channel_id *channel_id,
			      const struct pubkey funding_pubkey[NUM_SIDES],
			      const u8 *funding_wscript,
			      u8 *scriptpubkey[NUM_SIDES],
			      const struct bitcoin_txid *funding_txid,
			      unsigned int funding_txout,
			      u64 funding_satoshi,
			      const u64 satoshi_out[NUM_SIDES],
			      enum side funder,
			      uint64_t our_dust_limit,
			      u64 min_fee_to_accept)
{
	u8 *msg;
	struct channel_id their_channel_id;
	u64 received_fee;
	secp256k1_ecdsa_signature their_sig;
	struct bitcoin_tx *tx;

	/* Wait for them to say something interesting */
	do {
		msg = closing_read_peer_msg(tmpctx, cs, channel_id);

		/* BOLT #2:
		 *
		 *  - upon reconnection:
		 *     - MUST ignore any redundant `funding_locked` it receives.
		 */
		/* This should only happen if we've made no commitments, but
		 * we don't have to check that: it's their problem. */
		if (fromwire_peektype(msg) == WIRE_FUNDING_LOCKED)
			msg = tal_free(msg);
		/* BOLT #2:
		 *     - if it has sent a previous `shutdown`:
		 *       - MUST retransmit `shutdown`.
		 */
		else if (fromwire_peektype(msg) == WIRE_SHUTDOWN)
			msg = tal_free(msg);
	} while (!msg);

	if (!fromwire_closing_signed(msg, &their_channel_id,
				     &received_fee, &their_sig))
		peer_failed(cs, channel_id,
			    "Expected closing_signed: %s",
			    tal_hex(tmpctx, msg));

	/* BOLT #2:
	 *
	 * The receiving node:
	 *   - if the `signature` is not valid for either variant of close
	 *     transaction specified in [BOLT #3](03-transactions.md#closing-transaction):
	 *     - MUST fail the connection.
	 */
	tx = close_tx(tmpctx, cs, channel_id,
		      scriptpubkey,
		      funding_txid,
		      funding_txout,
		      funding_satoshi,
		      satoshi_out, funder, received_fee, our_dust_limit);

	if (!check_tx_sig(tx, 0, NULL, funding_wscript,
			  &funding_pubkey[REMOTE], &their_sig)) {
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
		 * Each node offering a signature:
		 *   - MUST round each output down to whole satoshis.
		 *   - MUST subtract the fee given by `fee_satoshis` from the
		 *     output to the funder.
		 *   - MUST remove any output below its own
		 *    `dust_limit_satoshis`.
		 *   - MAY eliminate its own output.
		 */
		trimmed = close_tx(tmpctx, cs, channel_id,
				   scriptpubkey,
				   funding_txid,
				   funding_txout,
				   funding_satoshi,
				   trimming_satoshi_out,
				   funder, received_fee, our_dust_limit);
		if (!trimmed
		    || !check_tx_sig(trimmed, 0, NULL, funding_wscript,
				     &funding_pubkey[REMOTE], &their_sig)) {
			peer_failed(cs, channel_id,
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

	/* Master sorts out what is best offer, we just tell it any above min */
	if (received_fee >= min_fee_to_accept) {
		status_trace("...offer is reasonable");
		tell_master_their_offer(&their_sig, tx);
	}

	return received_fee;
}

struct feerange {
	enum side higher_side;
	u64 min, max;
};

static void init_feerange(struct feerange *feerange,
			  u64 commitment_fee,
			  const u64 offer[NUM_SIDES])
{
	feerange->min = 0;

	/* BOLT #2:
	 *
	 *  - MUST set `fee_satoshis` less than or equal to the base
         *    fee of the final commitment transaction, as calculated
         *    in [BOLT #3](03-transactions.md#fee-calculation).
	 */
	feerange->max = commitment_fee;

	if (offer[LOCAL] > offer[REMOTE])
		feerange->higher_side = LOCAL;
	else
		feerange->higher_side = REMOTE;

	status_trace("Feerange init %"PRIu64"-%"PRIu64", %s higher",
		     feerange->min, feerange->max,
		     feerange->higher_side == LOCAL ? "local" : "remote");
}

static void adjust_feerange(struct feerange *feerange,
			    u64 offer, enum side side)
{
	/* BOLT #2:
	 *
	 *     - MUST propose a value "strictly between" the received
	 *      `fee_satoshis` and its previously-sent `fee_satoshis`.
	 */
	if (side == feerange->higher_side)
		feerange->max = offer - 1;
	else
		feerange->min = offer + 1;

	status_trace("Feerange %s update %"PRIu64": now %"PRIu64"-%"PRIu64,
		     side == LOCAL ? "local" : "remote",
		     offer, feerange->min, feerange->max);
}

/* Figure out what we should offer now. */
static u64 adjust_offer(struct crypto_state *cs,
			const struct channel_id *channel_id,
			const struct feerange *feerange,
			u64 remote_offer,
			u64 min_fee_to_accept)
{
	/* Within 1 satoshi?  Agree. */
	if (feerange->min + 1 >= feerange->max)
		return remote_offer;

	/* Max is below our minimum acceptable? */
	if (feerange->max < min_fee_to_accept)
		peer_failed(cs, channel_id,
			    "Feerange %"PRIu64"-%"PRIu64
			    " below minimum acceptable %"PRIu64,
			    feerange->min, feerange->max,
			    min_fee_to_accept);

	/* Bisect between our minimum and max. */
	if (feerange->min > min_fee_to_accept)
		min_fee_to_accept = feerange->min;

	return (feerange->max + min_fee_to_accept)/2;
}

int main(int argc, char *argv[])
{
	setup_locale();

	struct crypto_state cs;
	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	u64 funding_satoshi, satoshi_out[NUM_SIDES];
	u64 our_dust_limit;
	u64 min_fee_to_accept, commitment_fee, offer[NUM_SIDES];
	struct feerange feerange;
	enum side funder;
	u8 *scriptpubkey[NUM_SIDES], *funding_wscript;
	struct channel_id channel_id;
	bool reconnected;
	u64 next_index[NUM_SIDES], revocations_received;
	enum side whose_turn;
	u8 *channel_reestablish;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_closing_init(ctx, msg,
				   &cs,
				   &funding_txid, &funding_txout,
				   &funding_satoshi,
				   &funding_pubkey[LOCAL],
				   &funding_pubkey[REMOTE],
				   &funder,
				   &satoshi_out[LOCAL],
				   &satoshi_out[REMOTE],
				   &our_dust_limit,
				   &min_fee_to_accept, &commitment_fee,
				   &offer[LOCAL],
				   &scriptpubkey[LOCAL],
				   &scriptpubkey[REMOTE],
				   &reconnected,
				   &next_index[LOCAL],
				   &next_index[REMOTE],
				   &revocations_received,
				   &channel_reestablish))
		master_badmsg(WIRE_CLOSING_INIT, msg);

	status_trace("satoshi_out = %"PRIu64"/%"PRIu64,
		     satoshi_out[LOCAL], satoshi_out[REMOTE]);
	status_trace("dustlimit = %"PRIu64, our_dust_limit);
	status_trace("fee = %"PRIu64, offer[LOCAL]);
	derive_channel_id(&channel_id, &funding_txid, funding_txout);

	funding_wscript = bitcoin_redeem_2of2(ctx,
					      &funding_pubkey[LOCAL],
					      &funding_pubkey[REMOTE]);

	if (reconnected)
		do_reconnect(&cs, &channel_id,
			     next_index, revocations_received,
			     channel_reestablish);

	peer_billboard(true, "Negotiating closing fee between %"PRIu64
		       " and %"PRIu64" satoshi (ideal %"PRIu64")",
		       min_fee_to_accept, commitment_fee, offer[LOCAL]);

	/* BOLT #2:
	 *
	 * The funding node:
	 *  - after `shutdown` has been received, AND no HTLCs remain in either
	 *    commitment transaction:
	 *    - SHOULD send a `closing_signed` message.
	 */
	whose_turn = funder;
	for (size_t i = 0; i < 2; i++, whose_turn = !whose_turn) {
		if (whose_turn == LOCAL) {
			send_offer(&cs,
				   &channel_id, funding_pubkey,
				   scriptpubkey, &funding_txid, funding_txout,
				   funding_satoshi, satoshi_out, funder,
				   our_dust_limit,
				   offer[LOCAL]);
		} else {
			if (i == 0)
				peer_billboard(false, "Waiting for their initial"
					       " closing fee offer");
			else
				peer_billboard(false, "Waiting for their initial"
					       " closing fee offer:"
					       " ours was %"PRIu64" satoshi",
					       offer[LOCAL]);
			offer[REMOTE]
				= receive_offer(&cs,
						&channel_id, funding_pubkey,
						funding_wscript,
						scriptpubkey, &funding_txid,
						funding_txout, funding_satoshi,
						satoshi_out, funder,
						our_dust_limit,
						min_fee_to_accept);
		}
	}

	/* Now we have first two points, we can init fee range. */
	init_feerange(&feerange, commitment_fee, offer);

	/* Apply (and check) funder offer now. */
	adjust_feerange(&feerange, offer[funder], funder);

	/* Now any extra rounds required. */
	while (offer[LOCAL] != offer[REMOTE]) {
		/* Still don't agree: adjust feerange based on previous offer */
		adjust_feerange(&feerange,
				offer[!whose_turn], !whose_turn);

		if (whose_turn == LOCAL) {
			offer[LOCAL] = adjust_offer(&cs,
						    &channel_id,
						    &feerange, offer[REMOTE],
						    min_fee_to_accept);
			send_offer(&cs, &channel_id,
				   funding_pubkey,
				   scriptpubkey, &funding_txid, funding_txout,
				   funding_satoshi, satoshi_out, funder,
				   our_dust_limit,
				   offer[LOCAL]);
		} else {
			peer_billboard(false, "Waiting for another"
				       " closing fee offer:"
				       " ours was %"PRIu64" satoshi,"
				       " theirs was %"PRIu64" satoshi,",
				       offer[LOCAL], offer[REMOTE]);
			offer[REMOTE]
				= receive_offer(&cs, &channel_id,
						funding_pubkey,
						funding_wscript,
						scriptpubkey, &funding_txid,
						funding_txout, funding_satoshi,
						satoshi_out, funder,
						our_dust_limit,
						min_fee_to_accept);
		}

		whose_turn = !whose_turn;
	}

	peer_billboard(true, "We agreed on a closing fee of %"PRIu64" satoshi",
		       offer[LOCAL]);

	/* We're done! */
	/* Properly close the channel first. */
	if (!socket_close(PEER_FD))
		status_unusual("Closing and draining peerfd gave error: %s",
			       strerror(errno));
	/* Sending the below will kill us! */
	wire_sync_write(REQ_FD,	take(towire_closing_complete(NULL)));
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
