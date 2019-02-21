#include <bitcoin/script.h>
#include <closingd/gen_closing_wire.h>
#include <common/close_tx.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/htlc.h>
#include <common/memleak.h>
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
#include <hsmd/gen_hsm_wire.h>
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
				   struct amount_sat funding,
				   const struct amount_sat out[NUM_SIDES],
				   enum side funder,
				   struct amount_sat fee,
				   struct amount_sat dust_limit)
{
	struct bitcoin_tx *tx;
	struct amount_sat out_minus_fee[NUM_SIDES];

	out_minus_fee[LOCAL] = out[LOCAL];
	out_minus_fee[REMOTE] = out[REMOTE];
	if (!amount_sat_sub(&out_minus_fee[funder], out[funder], fee))
		peer_failed(cs, channel_id,
			    "Funder cannot afford fee %s (%s and %s)",
			    type_to_string(tmpctx, struct amount_sat, &fee),
			    type_to_string(tmpctx, struct amount_sat,
					   &out[LOCAL]),
			    type_to_string(tmpctx, struct amount_sat,
					   &out[REMOTE]));

	status_trace("Making close tx at = %s/%s fee %s",
		     type_to_string(tmpctx, struct amount_sat, &out[LOCAL]),
		     type_to_string(tmpctx, struct amount_sat, &out[REMOTE]),
		     type_to_string(tmpctx, struct amount_sat, &fee));

	/* FIXME: We need to allow this! */
	tx = create_close_tx(ctx,
			     scriptpubkey[LOCAL], scriptpubkey[REMOTE],
			     funding_txid,
			     funding_txout,
			     funding,
			     out_minus_fee[LOCAL],
			     out_minus_fee[REMOTE],
			     dust_limit);
	if (!tx)
		peer_failed(cs, channel_id,
			    "Both outputs below dust limit:"
			    " funding = %s"
			    " fee = %s"
			    " dust_limit = %s"
			    " LOCAL = %s"
			    " REMOTE = %s",
			    type_to_string(tmpctx, struct amount_sat, &funding),
			    type_to_string(tmpctx, struct amount_sat, &fee),
			    type_to_string(tmpctx, struct amount_sat, &dust_limit),
			    type_to_string(tmpctx, struct amount_sat, &out[LOCAL]),
			    type_to_string(tmpctx, struct amount_sat, &out[REMOTE]));
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
			 const u8 *channel_reestablish,
			 const u8 *final_scriptpubkey)
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

	/* BOLT #2:
	 *
	 * A node:
	 *...
	 *   - upon reconnection:
	 *     - if it has sent a previous `shutdown`:
	 *       - MUST retransmit `shutdown`.
	 */
	msg = towire_shutdown(NULL, channel_id, final_scriptpubkey);
	sync_crypto_write(cs, PEER_FD, take(msg));

	/* FIXME: Spec says to re-xmit funding_locked here if we haven't
	 * done any updates. */
}

static void send_offer(struct crypto_state *cs,
		       const struct channel_id *channel_id,
		       const struct pubkey funding_pubkey[NUM_SIDES],
		       u8 *scriptpubkey[NUM_SIDES],
		       const struct bitcoin_txid *funding_txid,
		       unsigned int funding_txout,
		       struct amount_sat funding,
		       const struct amount_sat out[NUM_SIDES],
		       enum side funder,
		       struct amount_sat our_dust_limit,
		       struct amount_sat fee_to_offer)
{
	struct bitcoin_tx *tx;
	struct bitcoin_signature our_sig;
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
		      funding,
		      out,
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
							     funding)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &our_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsm_sign_mutual_close_tx reply %s",
			      tal_hex(tmpctx, msg));

	status_trace("sending fee offer %s",
		     type_to_string(tmpctx, struct amount_sat, &fee_to_offer));

	assert(our_sig.sighash_type == SIGHASH_ALL);
	msg = towire_closing_signed(NULL, channel_id, fee_to_offer, &our_sig.s);
	sync_crypto_write(cs, PEER_FD, take(msg));
}

static void tell_master_their_offer(const struct bitcoin_signature *their_sig,
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
static struct amount_sat
receive_offer(struct crypto_state *cs,
	      const struct channel_id *channel_id,
	      const struct pubkey funding_pubkey[NUM_SIDES],
	      const u8 *funding_wscript,
	      u8 *scriptpubkey[NUM_SIDES],
	      const struct bitcoin_txid *funding_txid,
	      unsigned int funding_txout,
	      struct amount_sat funding,
	      const struct amount_sat out[NUM_SIDES],
	      enum side funder,
	      struct amount_sat our_dust_limit,
	      struct amount_sat min_fee_to_accept)
{
	u8 *msg;
	struct channel_id their_channel_id;
	struct amount_sat received_fee;
	struct bitcoin_signature their_sig;
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

	their_sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_closing_signed(msg, &their_channel_id,
				     &received_fee, &their_sig.s))
		peer_failed(cs, channel_id,
			    "Expected closing_signed: %s",
			    tal_hex(tmpctx, msg));

	/* BOLT #2:
	 *
	 * The receiving node:
	 *   - if the `signature` is not valid for either variant of closing transaction
	 *   specified in [BOLT #3](03-transactions.md#closing-transaction):
	 *     - MUST fail the connection.
	 */
	tx = close_tx(tmpctx, cs, channel_id,
		      scriptpubkey,
		      funding_txid,
		      funding_txout,
		      funding,
		      out, funder, received_fee, our_dust_limit);

	if (!check_tx_sig(tx, 0, NULL, funding_wscript,
			  &funding_pubkey[REMOTE], &their_sig)) {
		/* Trim it by reducing their output to minimum */
		struct bitcoin_tx *trimmed;
		struct amount_sat trimming_out[NUM_SIDES];

		if (funder == REMOTE)
			trimming_out[REMOTE] = received_fee;
		else
			trimming_out[REMOTE] = AMOUNT_SAT(0);
		trimming_out[LOCAL] = out[LOCAL];

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
				   funding,
				   trimming_out,
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

	status_trace("Received fee offer %s",
		     type_to_string(tmpctx, struct amount_sat, &received_fee));

	/* Master sorts out what is best offer, we just tell it any above min */
	if (amount_sat_greater_eq(received_fee, min_fee_to_accept)) {
		status_trace("...offer is reasonable");
		tell_master_their_offer(&their_sig, tx);
	}

	return received_fee;
}

struct feerange {
	enum side higher_side;
	struct amount_sat min, max;
};

static void init_feerange(struct feerange *feerange,
			  struct amount_sat commitment_fee,
			  const struct amount_sat offer[NUM_SIDES])
{
	feerange->min = AMOUNT_SAT(0);

	/* BOLT #2:
	 *
	 *  - MUST set `fee_satoshis` less than or equal to the base
         *    fee of the final commitment transaction, as calculated
         *    in [BOLT #3](03-transactions.md#fee-calculation).
	 */
	feerange->max = commitment_fee;

	if (amount_sat_greater(offer[LOCAL], offer[REMOTE]))
		feerange->higher_side = LOCAL;
	else
		feerange->higher_side = REMOTE;

	status_trace("Feerange init %s-%s, %s higher",
		     type_to_string(tmpctx, struct amount_sat, &feerange->min),
		     type_to_string(tmpctx, struct amount_sat, &feerange->max),
		     feerange->higher_side == LOCAL ? "local" : "remote");
}

static void adjust_feerange(struct feerange *feerange,
			    struct amount_sat offer, enum side side)
{
	bool ok;

	/* BOLT #2:
	 *
	 *     - MUST propose a value "strictly between" the received
	 *      `fee_satoshis` and its previously-sent `fee_satoshis`.
	 */
	if (side == feerange->higher_side)
		ok = amount_sat_sub(&feerange->max, offer, AMOUNT_SAT(1));
	else
		ok = amount_sat_add(&feerange->min, offer, AMOUNT_SAT(1));

	status_trace("Feerange %s update %s: now %s-%s",
		     side == LOCAL ? "local" : "remote",
		     type_to_string(tmpctx, struct amount_sat, &offer),
		     type_to_string(tmpctx, struct amount_sat, &feerange->min),
		     type_to_string(tmpctx, struct amount_sat, &feerange->max));

	if (!ok)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow in updating fee range");
}

/* Figure out what we should offer now. */
static struct amount_sat adjust_offer(struct crypto_state *cs,
				      const struct channel_id *channel_id,
				      const struct feerange *feerange,
				      struct amount_sat remote_offer,
				      struct amount_sat min_fee_to_accept)
{
	struct amount_sat min_plus_one, avg;

	/* Within 1 satoshi?  Agree. */
	if (!amount_sat_add(&min_plus_one, feerange->min, AMOUNT_SAT(1)))
		peer_failed(cs, channel_id,
			    "Fee offer %s min too large",
			    type_to_string(tmpctx, struct amount_sat,
					   &feerange->min));

	if (amount_sat_greater_eq(min_plus_one, feerange->max))
		return remote_offer;

	/* Max is below our minimum acceptable? */
	if (amount_sat_less(feerange->max, min_fee_to_accept))
		peer_failed(cs, channel_id,
			    "Feerange %s-%s"
			    " below minimum acceptable %s",
			    type_to_string(tmpctx, struct amount_sat,
					   &feerange->min),
			    type_to_string(tmpctx, struct amount_sat,
					   &feerange->max),
			    type_to_string(tmpctx, struct amount_sat,
					   &min_fee_to_accept));

	/* Bisect between our minimum and max. */
	if (amount_sat_greater(feerange->min, min_fee_to_accept))
		min_fee_to_accept = feerange->min;

	if (!amount_sat_add(&avg, feerange->max, min_fee_to_accept))
		peer_failed(cs, channel_id,
			    "Fee offer %s max too large",
			    type_to_string(tmpctx, struct amount_sat,
					   &feerange->max));

	avg.satoshis /= 2; /* Raw: average calculation */
	return avg;
}

#if DEVELOPER
/* FIXME: We should talk to lightningd anyway, rather than doing this */
static void closing_dev_memleak(const tal_t *ctx,
				u8 *scriptpubkey[NUM_SIDES],
				const u8 *funding_wscript)
{
	struct htable *memtable;

	memtable = memleak_enter_allocations(tmpctx,
					     scriptpubkey[LOCAL],
					     scriptpubkey[REMOTE]);

	/* Now delete known pointers (these aren't really roots, just
	 * pointers we know are referenced).*/
	memleak_remove_referenced(memtable, ctx);
	memleak_remove_referenced(memtable, funding_wscript);

	dump_memleak(memtable);
}
#endif /* DEVELOPER */

int main(int argc, char *argv[])
{
	setup_locale();

	struct crypto_state cs;
	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	struct amount_sat funding, out[NUM_SIDES];
	struct amount_sat our_dust_limit;
	struct amount_sat min_fee_to_accept, commitment_fee, offer[NUM_SIDES];
	struct feerange feerange;
	enum side funder;
	u8 *scriptpubkey[NUM_SIDES], *funding_wscript, *final_scriptpubkey;
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
				   &funding,
				   &funding_pubkey[LOCAL],
				   &funding_pubkey[REMOTE],
				   &funder,
				   &out[LOCAL],
				   &out[REMOTE],
				   &our_dust_limit,
				   &min_fee_to_accept, &commitment_fee,
				   &offer[LOCAL],
				   &scriptpubkey[LOCAL],
				   &scriptpubkey[REMOTE],
				   &reconnected,
				   &next_index[LOCAL],
				   &next_index[REMOTE],
				   &revocations_received,
				   &channel_reestablish,
				   &final_scriptpubkey))
		master_badmsg(WIRE_CLOSING_INIT, msg);

	status_trace("out = %s/%s",
		     type_to_string(tmpctx, struct amount_sat, &out[LOCAL]),
		     type_to_string(tmpctx, struct amount_sat, &out[REMOTE]));
	status_trace("dustlimit = %s",
		     type_to_string(tmpctx, struct amount_sat, &our_dust_limit));
	status_trace("fee = %s",
		     type_to_string(tmpctx, struct amount_sat, &offer[LOCAL]));
	derive_channel_id(&channel_id, &funding_txid, funding_txout);

	funding_wscript = bitcoin_redeem_2of2(ctx,
					      &funding_pubkey[LOCAL],
					      &funding_pubkey[REMOTE]);

	if (reconnected)
		do_reconnect(&cs, &channel_id,
			     next_index, revocations_received,
			     channel_reestablish, final_scriptpubkey);

	/* We don't need this any more */
	tal_free(final_scriptpubkey);

	peer_billboard(true, "Negotiating closing fee between %s"
		       " and %s satoshi (ideal %s)",
		       type_to_string(tmpctx, struct amount_sat,
				      &min_fee_to_accept),
		       type_to_string(tmpctx, struct amount_sat,
				      &commitment_fee),
		       type_to_string(tmpctx, struct amount_sat, &offer[LOCAL]));

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
				   funding, out, funder,
				   our_dust_limit,
				   offer[LOCAL]);
		} else {
			if (i == 0)
				peer_billboard(false, "Waiting for their initial"
					       " closing fee offer");
			else
				peer_billboard(false, "Waiting for their initial"
					       " closing fee offer:"
					       " ours was %s",
					       type_to_string(tmpctx,
							      struct amount_sat,
							      &offer[LOCAL]));
			offer[REMOTE]
				= receive_offer(&cs,
						&channel_id, funding_pubkey,
						funding_wscript,
						scriptpubkey, &funding_txid,
						funding_txout, funding,
						out, funder,
						our_dust_limit,
						min_fee_to_accept);
		}
	}

	/* Now we have first two points, we can init fee range. */
	init_feerange(&feerange, commitment_fee, offer);

	/* Apply (and check) funder offer now. */
	adjust_feerange(&feerange, offer[funder], funder);

	/* Now any extra rounds required. */
	while (!amount_sat_eq(offer[LOCAL], offer[REMOTE])) {
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
				   funding, out, funder,
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
						funding_txout, funding,
						out, funder,
						our_dust_limit,
						min_fee_to_accept);
		}

		whose_turn = !whose_turn;
	}

	peer_billboard(true, "We agreed on a closing fee of %"PRIu64" satoshi",
		       offer[LOCAL]);

#if DEVELOPER
	/* We don't listen for master commands, so always check memleak here */
	closing_dev_memleak(ctx, scriptpubkey, funding_wscript);
#endif

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
