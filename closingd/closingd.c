#include <bitcoin/script.h>
#include <ccan/fdpass/fdpass.h>
#include <closingd/closingd_wiregen.h>
#include <common/close_tx.h>
#include <common/closing_fee.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/htlc.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <common/socket_close.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <errno.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/common_wiregen.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip, 5 = gossip_store, 6 = hsmd */
#define REQ_FD STDIN_FILENO
#define HSM_FD 6

static struct bitcoin_tx *close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   struct per_peer_state *pps,
				   const struct channel_id *channel_id,
				   u8 *scriptpubkey[NUM_SIDES],
				   const struct bitcoin_txid *funding_txid,
				   unsigned int funding_txout,
				   struct amount_sat funding,
				   const u8 *funding_wscript,
				   const struct amount_sat out[NUM_SIDES],
				   enum side opener,
				   struct amount_sat fee,
				   struct amount_sat dust_limit,
				   const struct bitcoin_outpoint *wrong_funding)
{
	struct bitcoin_tx *tx;
	struct amount_sat out_minus_fee[NUM_SIDES];

	out_minus_fee[LOCAL] = out[LOCAL];
	out_minus_fee[REMOTE] = out[REMOTE];
	if (!amount_sat_sub(&out_minus_fee[opener], out[opener], fee))
		peer_failed_warn(pps, channel_id,
				 "Funder cannot afford fee %s (%s and %s)",
				 type_to_string(tmpctx, struct amount_sat, &fee),
				 type_to_string(tmpctx, struct amount_sat,
						&out[LOCAL]),
				 type_to_string(tmpctx, struct amount_sat,
						&out[REMOTE]));

	status_debug("Making close tx at = %s/%s fee %s",
		     type_to_string(tmpctx, struct amount_sat, &out[LOCAL]),
		     type_to_string(tmpctx, struct amount_sat, &out[REMOTE]),
		     type_to_string(tmpctx, struct amount_sat, &fee));

	/* FIXME: We need to allow this! */
	tx = create_close_tx(ctx,
			     chainparams,
			     scriptpubkey[LOCAL], scriptpubkey[REMOTE],
			     funding_wscript,
			     funding_txid,
			     funding_txout,
			     funding,
			     out_minus_fee[LOCAL],
			     out_minus_fee[REMOTE],
			     dust_limit);
	if (!tx)
		peer_failed_err(pps, channel_id,
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

	if (wrong_funding)
		bitcoin_tx_input_set_txid(tx, 0,
					  &wrong_funding->txid,
					  wrong_funding->n);

	return tx;
}

/* Handle random messages we might get, returning the first non-handled one. */
static u8 *closing_read_peer_msg(const tal_t *ctx,
				 struct per_peer_state *pps,
				 const struct channel_id *channel_id)
{
	for (;;) {
		u8 *msg;
		bool from_gossipd;

		clean_tmpctx();
		msg = peer_or_gossip_sync_read(ctx, pps, &from_gossipd);
		if (from_gossipd) {
			handle_gossip_msg(pps, take(msg));
			continue;
		}
#if DEVELOPER
		/* Handle custommsgs */
		enum peer_wire type = fromwire_peektype(msg);
		if (type % 2 == 1 && !peer_wire_is_defined(type)) {
			/* The message is not part of the messages we know
			 * how to handle. Assume is custommsg, forward it
			 * to master. */
			wire_sync_write(REQ_FD, take(towire_custommsg_in(NULL, msg)));
			continue;
		}
#endif
		if (!handle_peer_gossip_or_error(pps, channel_id, false, msg))
			return msg;
	}
}

static struct pubkey get_per_commitment_point(u64 commitment_number)
{
	u8 *msg;
	struct pubkey commitment_point;
	struct secret *s;

	/* Our current per-commitment point is the commitment point in the last
	 * received signed commitment; HSM gives us that and the previous
	 * secret (which we don't need). */
	msg = towire_hsmd_get_per_commitment_point(NULL,
	                                          commitment_number);
	if (!wire_sync_write(HSM_FD, take(msg)))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Writing get_per_commitment_point to HSM: %s",
			      strerror(errno));

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg)
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading resp get_per_commitment_point reply: %s",
			      strerror(errno));
	if (!fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
	                                                 &commitment_point,
	                                                 &s))
		status_failed(STATUS_FAIL_HSM_IO,
		              "Bad per_commitment_point reply %s",
		              tal_hex(tmpctx, msg));

	return commitment_point;
}

static void do_reconnect(struct per_peer_state *pps,
			 const struct channel_id *channel_id,
			 const u64 next_index[NUM_SIDES],
			 u64 revocations_received,
			 const u8 *channel_reestablish,
			 const u8 *final_scriptpubkey,
			 const struct secret *last_remote_per_commit_secret,
			 const struct bitcoin_outpoint *wrong_funding)
{
	u8 *msg;
	struct channel_id their_channel_id;
	u64 next_local_commitment_number, next_remote_revocation_number;
	struct pubkey my_current_per_commitment_point, next_commitment_point;
	struct secret their_secret;
	struct tlv_shutdown_tlvs *tlvs;
#if EXPERIMENTAL_FEATURES
	struct tlv_channel_reestablish_tlvs *reestablish_tlvs = tlv_channel_reestablish_tlvs_new(tmpctx);
#endif

	my_current_per_commitment_point = get_per_commitment_point(next_index[LOCAL]-1);

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
	 *   - MUST set `next_commitment_number` to the commitment number
	 *     of the next `commitment_signed` it expects to receive.
	 *   - MUST set `next_revocation_number` to the commitment number
	 *     of the next `revoke_and_ack` message it expects to receive.
	 */

	msg = towire_channel_reestablish(NULL, channel_id,
					 next_index[LOCAL],
					 revocations_received,
					 last_remote_per_commit_secret,
					 &my_current_per_commitment_point
#if EXPERIMENTAL_FEATURES
					 , reestablish_tlvs
#endif
		);
	sync_crypto_write(pps, take(msg));

	/* They might have already sent reestablish, which triggered us */
	if (!channel_reestablish) {
		do {
			tal_free(channel_reestablish);
			channel_reestablish = closing_read_peer_msg(tmpctx, pps,
								    channel_id);
			/* They *should* send reestablish first, but lnd
			 * sends other messages, which we can ignore since
			 * we're closing anyway... */
		} while (fromwire_peektype(channel_reestablish)
			 != WIRE_CHANNEL_REESTABLISH);
	}

#if EXPERIMENTAL_FEATURES
	reestablish_tlvs = tlv_channel_reestablish_tlvs_new(tmpctx);
#endif

	if (!fromwire_channel_reestablish(channel_reestablish, &their_channel_id,
					  &next_local_commitment_number,
					  &next_remote_revocation_number,
					  &their_secret,
					  &next_commitment_point
#if EXPERIMENTAL_FEATURES
					 , reestablish_tlvs
#endif
		    )) {
		peer_failed_warn(pps, channel_id,
				 "bad reestablish msg: %s %s",
				 peer_wire_name(fromwire_peektype(channel_reestablish)),
				 tal_hex(tmpctx, channel_reestablish));
	}
	status_debug("Got reestablish commit=%"PRIu64" revoke=%"PRIu64,
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
	if (wrong_funding) {
		tlvs = tlv_shutdown_tlvs_new(tmpctx);
		tlvs->wrong_funding
			= tal(tlvs, struct tlv_shutdown_tlvs_wrong_funding);
		tlvs->wrong_funding->txid = wrong_funding->txid;
		tlvs->wrong_funding->outnum = wrong_funding->n;
	} else
		tlvs = NULL;

	msg = towire_shutdown(NULL, channel_id, final_scriptpubkey, tlvs);
	sync_crypto_write(pps, take(msg));

	/* BOLT #2:
	 *
	 * A node:
	 *...
	 *   - if `next_commitment_number` is 1 in both the `channel_reestablish` it sent and received:
	 *     - MUST retransmit `funding_locked`.
	 */
	if (next_index[REMOTE] == 1 && next_index[LOCAL] == 1) {
		status_debug("Retransmitting funding_locked for channel %s",
		             type_to_string(tmpctx, struct channel_id, channel_id));
		next_commitment_point = get_per_commitment_point(next_index[LOCAL]);
		msg = towire_funding_locked(NULL, channel_id, &next_commitment_point);
		sync_crypto_write(pps, take(msg));
	}
}

static void send_offer(struct per_peer_state *pps,
		       const struct chainparams *chainparams,
		       const struct channel_id *channel_id,
		       const struct pubkey funding_pubkey[NUM_SIDES],
		       const u8 *funding_wscript,
		       u8 *scriptpubkey[NUM_SIDES],
		       const struct bitcoin_txid *funding_txid,
		       unsigned int funding_txout,
		       struct amount_sat funding,
		       const struct amount_sat out[NUM_SIDES],
		       enum side opener,
		       struct amount_sat our_dust_limit,
		       struct amount_sat fee_to_offer,
		       const struct bitcoin_outpoint *wrong_funding)
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
	tx = close_tx(tmpctx, chainparams, pps, channel_id,
		      scriptpubkey,
		      funding_txid,
		      funding_txout,
		      funding,
		      funding_wscript,
		      out,
		      opener, fee_to_offer, our_dust_limit,
		      wrong_funding);

	/* BOLT #3:
	 *
	 * ## Closing Transaction
	 *...
	 * Each node offering a signature... MAY eliminate its
	 * own output.
	 */
	/* (We don't do this). */
	wire_sync_write(HSM_FD,
			take(towire_hsmd_sign_mutual_close_tx(NULL,
							     tx,
							     &funding_pubkey[REMOTE])));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_sign_tx_reply(msg, &our_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsm_sign_mutual_close_tx reply %s",
			      tal_hex(tmpctx, msg));

	status_debug("sending fee offer %s",
		     type_to_string(tmpctx, struct amount_sat, &fee_to_offer));

	assert(our_sig.sighash_type == SIGHASH_ALL);
	msg = towire_closing_signed(NULL, channel_id, fee_to_offer, &our_sig.s);
	sync_crypto_write(pps, take(msg));
}

static void tell_master_their_offer(const struct bitcoin_signature *their_sig,
				    const struct bitcoin_tx *tx,
				    struct bitcoin_txid *tx_id)
{
	u8 *msg = towire_closingd_received_signature(NULL, their_sig, tx);
	if (!wire_sync_write(REQ_FD, take(msg)))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Writing received to master: %s",
			      strerror(errno));

	/* Wait for master to ack, to make sure it's in db. */
	msg = wire_sync_read(NULL, REQ_FD);
	if (!fromwire_closingd_received_signature_reply(msg, tx_id))
		master_badmsg(WIRE_CLOSINGD_RECEIVED_SIGNATURE_REPLY, msg);
	tal_free(msg);
}

/* Returns fee they offered. */
static struct amount_sat
receive_offer(struct per_peer_state *pps,
	      const struct chainparams *chainparams,
	      const struct channel_id *channel_id,
	      const struct pubkey funding_pubkey[NUM_SIDES],
	      const u8 *funding_wscript,
	      u8 *scriptpubkey[NUM_SIDES],
	      const struct bitcoin_txid *funding_txid,
	      unsigned int funding_txout,
	      struct amount_sat funding,
	      const struct amount_sat out[NUM_SIDES],
	      enum side opener,
	      struct amount_sat our_dust_limit,
	      struct amount_sat min_fee_to_accept,
	      const struct bitcoin_outpoint *wrong_funding,
	      struct bitcoin_txid *closing_txid)
{
	u8 *msg;
	struct channel_id their_channel_id;
	struct amount_sat received_fee;
	struct bitcoin_signature their_sig;
	struct bitcoin_tx *tx;

	/* Wait for them to say something interesting */
	do {
		msg = closing_read_peer_msg(tmpctx, pps, channel_id);

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
		peer_failed_warn(pps, channel_id,
				 "Expected closing_signed: %s",
				 tal_hex(tmpctx, msg));

	/* BOLT #2:
	 *
	 * The receiving node:
	 *   - if the `signature` is not valid for either variant of closing transaction
	 *   specified in [BOLT #3](03-transactions.md#closing-transaction)
	 *   OR non-compliant with LOW-S-standard rule...:
	 *     - MUST fail the connection.
	 */
	tx = close_tx(tmpctx, chainparams, pps, channel_id,
		      scriptpubkey,
		      funding_txid,
		      funding_txout,
		      funding,
		      funding_wscript,
		      out, opener, received_fee, our_dust_limit,
		      wrong_funding);

	if (!check_tx_sig(tx, 0, NULL, funding_wscript,
			  &funding_pubkey[REMOTE], &their_sig)) {
		/* Trim it by reducing their output to minimum */
		struct bitcoin_tx *trimmed;
		struct amount_sat trimming_out[NUM_SIDES];

		if (opener == REMOTE)
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
		trimmed = close_tx(tmpctx, chainparams, pps, channel_id,
				   scriptpubkey,
				   funding_txid,
				   funding_txout,
				   funding,
				   funding_wscript,
				   trimming_out,
				   opener, received_fee, our_dust_limit,
				   wrong_funding);
		if (!trimmed
		    || !check_tx_sig(trimmed, 0, NULL, funding_wscript,
				     &funding_pubkey[REMOTE], &their_sig)) {
			peer_failed_warn(pps, channel_id,
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

	status_debug("Received fee offer %s",
		     type_to_string(tmpctx, struct amount_sat, &received_fee));

	/* Master sorts out what is best offer, we just tell it any above min */
	if (amount_sat_greater_eq(received_fee, min_fee_to_accept)) {
		status_debug("...offer is reasonable");
		tell_master_their_offer(&their_sig, tx, closing_txid);
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

	status_debug("Feerange init %s-%s, %s higher",
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

	status_debug("Feerange %s update %s: now %s-%s",
		     side == LOCAL ? "local" : "remote",
		     type_to_string(tmpctx, struct amount_sat, &offer),
		     type_to_string(tmpctx, struct amount_sat, &feerange->min),
		     type_to_string(tmpctx, struct amount_sat, &feerange->max));

	if (!ok)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow in updating fee range");
}

/* Figure out what we should offer now. */
static struct amount_sat
adjust_offer(struct per_peer_state *pps, const struct channel_id *channel_id,
	     const struct feerange *feerange, struct amount_sat remote_offer,
	     struct amount_sat min_fee_to_accept, u64 fee_negotiation_step,
	     u8 fee_negotiation_step_unit)
{
	struct amount_sat min_plus_one, range_len, step_sat, result;
	struct amount_msat step_msat;

	/* Within 1 satoshi?  Agree. */
	if (!amount_sat_add(&min_plus_one, feerange->min, AMOUNT_SAT(1)))
		peer_failed_warn(pps, channel_id,
				 "Fee offer %s min too large",
				 type_to_string(tmpctx, struct amount_sat,
						&feerange->min));

	if (amount_sat_greater_eq(min_plus_one, feerange->max))
		return remote_offer;

	/* feerange has already been adjusted so that our new offer is ok to be
	 * any number in [feerange->min, feerange->max] and after the following
	 * min_fee_to_accept is in that range. Thus, pick a fee in
	 * [min_fee_to_accept, feerange->max]. */
	if (amount_sat_greater(feerange->min, min_fee_to_accept))
		min_fee_to_accept = feerange->min;

	/* Max is below our minimum acceptable? */
	if (!amount_sat_sub(&range_len, feerange->max, min_fee_to_accept))
		peer_failed_warn(pps, channel_id,
				 "Feerange %s-%s"
				 " below minimum acceptable %s",
				 type_to_string(tmpctx, struct amount_sat,
						&feerange->min),
				 type_to_string(tmpctx, struct amount_sat,
						&feerange->max),
				 type_to_string(tmpctx, struct amount_sat,
						&min_fee_to_accept));

	if (fee_negotiation_step_unit ==
	    CLOSING_FEE_NEGOTIATION_STEP_UNIT_SATOSHI) {
		/* -1 because the range boundary has already been adjusted with
		 * one from our previous proposal. So, if the user requested a
		 * step of 1 satoshi at a time we should just return our end of
		 * the range from this function. */
		step_msat = amount_msat((fee_negotiation_step - 1)
					* MSAT_PER_SAT);
	} else {
		/* fee_negotiation_step is e.g. 20 to designate 20% from
		 * range_len (which is in satoshi), so:
		 * range_len * fee_negotiation_step / 100 [sat]
		 * is equivalent to:
		 * range_len * fee_negotiation_step * 10 [msat] */
		step_msat = amount_msat(range_len.satoshis /* Raw: % calc */ *
					fee_negotiation_step * 10);
	}

	step_sat = amount_msat_to_sat_round_down(step_msat);

	if (feerange->higher_side == LOCAL) {
		if (!amount_sat_sub(&result, feerange->max, step_sat))
			/* step_sat > feerange->max, unlikely */
			return min_fee_to_accept;

		if (amount_sat_less_eq(result, min_fee_to_accept))
			return min_fee_to_accept;
	} else {
		if (!amount_sat_add(&result, min_fee_to_accept, step_sat))
			/* overflow, unlikely */
			return feerange->max;

		if (amount_sat_greater_eq(result, feerange->max))
			return feerange->max;
	}

	return result;
}

#if DEVELOPER
/* FIXME: We should talk to lightningd anyway, rather than doing this */
static void closing_dev_memleak(const tal_t *ctx,
				u8 *scriptpubkey[NUM_SIDES],
				const u8 *funding_wscript)
{
	struct htable *memtable;

	memtable = memleak_find_allocations(tmpctx, NULL, NULL);

	memleak_remove_pointer(memtable, ctx);
	memleak_remove_pointer(memtable, scriptpubkey[LOCAL]);
	memleak_remove_pointer(memtable, scriptpubkey[REMOTE]);
	memleak_remove_pointer(memtable, funding_wscript);

	dump_memleak(memtable);
}
#endif /* DEVELOPER */

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	struct per_peer_state *pps;
	u8 *msg;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct bitcoin_txid funding_txid, closing_txid;
	u16 funding_txout;
	struct amount_sat funding, out[NUM_SIDES];
	struct amount_sat our_dust_limit;
	struct amount_sat min_fee_to_accept, commitment_fee, offer[NUM_SIDES];
	struct feerange feerange;
	enum side opener;
	u8 *scriptpubkey[NUM_SIDES], *funding_wscript;
	u64 fee_negotiation_step;
	u8 fee_negotiation_step_unit;
	char fee_negotiation_step_str[32]; /* fee_negotiation_step + "sat" */
	struct channel_id channel_id;
	bool reconnected;
	u64 next_index[NUM_SIDES], revocations_received;
	enum side whose_turn;
	u8 *channel_reestablish;
	struct secret last_remote_per_commit_secret;
	struct bitcoin_outpoint *wrong_funding;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_closingd_init(ctx, msg,
				    &chainparams,
				    &pps,
				    &channel_id,
				    &funding_txid, &funding_txout,
				    &funding,
				    &funding_pubkey[LOCAL],
				    &funding_pubkey[REMOTE],
				    &opener,
				    &out[LOCAL],
				    &out[REMOTE],
				    &our_dust_limit,
				    &min_fee_to_accept, &commitment_fee,
				    &offer[LOCAL],
				    &scriptpubkey[LOCAL],
				    &scriptpubkey[REMOTE],
				    &fee_negotiation_step,
				    &fee_negotiation_step_unit,
				    &reconnected,
				    &next_index[LOCAL],
				    &next_index[REMOTE],
				    &revocations_received,
				    &channel_reestablish,
				    &last_remote_per_commit_secret,
				    &dev_fast_gossip,
				    &wrong_funding))
		master_badmsg(WIRE_CLOSINGD_INIT, msg);

	/* stdin == requests, 3 == peer, 4 = gossip, 5 = gossip_store, 6 = hsmd */
	per_peer_state_set_fds(notleak(pps), 3, 4, 5);

	snprintf(fee_negotiation_step_str, sizeof(fee_negotiation_step_str),
		 "%" PRIu64 "%s", fee_negotiation_step,
		 fee_negotiation_step_unit ==
			 CLOSING_FEE_NEGOTIATION_STEP_UNIT_PERCENTAGE
		     ? "%"
		     : "sat");

	status_debug("out = %s/%s",
		     type_to_string(tmpctx, struct amount_sat, &out[LOCAL]),
		     type_to_string(tmpctx, struct amount_sat, &out[REMOTE]));
	status_debug("dustlimit = %s",
		     type_to_string(tmpctx, struct amount_sat, &our_dust_limit));
	status_debug("fee = %s",
		     type_to_string(tmpctx, struct amount_sat, &offer[LOCAL]));
	status_debug("fee negotiation step = %s", fee_negotiation_step_str);
	if (wrong_funding)
		status_unusual("Setting wrong_funding_txid to %s:%u",
			       type_to_string(tmpctx, struct bitcoin_txid,
					      &wrong_funding->txid),
			       wrong_funding->n);

	funding_wscript = bitcoin_redeem_2of2(ctx,
					      &funding_pubkey[LOCAL],
					      &funding_pubkey[REMOTE]);

	if (reconnected)
		do_reconnect(pps, &channel_id,
			     next_index, revocations_received,
			     channel_reestablish, scriptpubkey[LOCAL],
			     &last_remote_per_commit_secret,
			     wrong_funding);

	peer_billboard(
	    true,
	    "Negotiating closing fee between %s and %s satoshi (ideal %s) "
	    "using step %s",
	    type_to_string(tmpctx, struct amount_sat, &min_fee_to_accept),
	    type_to_string(tmpctx, struct amount_sat, &commitment_fee),
	    type_to_string(tmpctx, struct amount_sat, &offer[LOCAL]),
	    fee_negotiation_step_str);

	/* BOLT #2:
	 *
	 * The funding node:
	 *  - after `shutdown` has been received, AND no HTLCs remain in either
	 *    commitment transaction:
	 *    - SHOULD send a `closing_signed` message.
	 */
	whose_turn = opener;
	for (size_t i = 0; i < 2; i++, whose_turn = !whose_turn) {
		if (whose_turn == LOCAL) {
			send_offer(pps, chainparams,
				   &channel_id, funding_pubkey, funding_wscript,
				   scriptpubkey, &funding_txid, funding_txout,
				   funding, out, opener,
				   our_dust_limit,
				   offer[LOCAL],
				   wrong_funding);
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
				= receive_offer(pps, chainparams,
						&channel_id, funding_pubkey,
						funding_wscript,
						scriptpubkey, &funding_txid,
						funding_txout, funding,
						out, opener,
						our_dust_limit,
						min_fee_to_accept,
						wrong_funding,
						&closing_txid);
		}
	}

	/* Now we have first two points, we can init fee range. */
	init_feerange(&feerange, commitment_fee, offer);

	/* Apply (and check) opener offer now. */
	adjust_feerange(&feerange, offer[opener], opener);

	/* Now any extra rounds required. */
	while (!amount_sat_eq(offer[LOCAL], offer[REMOTE])) {
		/* Still don't agree: adjust feerange based on previous offer */
		adjust_feerange(&feerange,
				offer[!whose_turn], !whose_turn);

		if (whose_turn == LOCAL) {
			offer[LOCAL] = adjust_offer(pps,
						    &channel_id,
						    &feerange, offer[REMOTE],
						    min_fee_to_accept,
						    fee_negotiation_step,
						    fee_negotiation_step_unit);
			send_offer(pps, chainparams, &channel_id,
				   funding_pubkey, funding_wscript,
				   scriptpubkey, &funding_txid, funding_txout,
				   funding, out, opener,
				   our_dust_limit,
				   offer[LOCAL],
				   wrong_funding);
		} else {
			peer_billboard(false, "Waiting for another"
				       " closing fee offer:"
				       " ours was %"PRIu64" satoshi,"
				       " theirs was %"PRIu64" satoshi,",
				       offer[LOCAL], offer[REMOTE]);
			offer[REMOTE]
				= receive_offer(pps, chainparams, &channel_id,
						funding_pubkey,
						funding_wscript,
						scriptpubkey, &funding_txid,
						funding_txout, funding,
						out, opener,
						our_dust_limit,
						min_fee_to_accept,
						wrong_funding,
						&closing_txid);
		}

		whose_turn = !whose_turn;
	}

	peer_billboard(true, "We agreed on a closing fee of %"PRIu64" satoshi for tx:%s",
		       offer[LOCAL],
		       type_to_string(tmpctx, struct bitcoin_txid, &closing_txid));

#if DEVELOPER
	/* We don't listen for master commands, so always check memleak here */
	tal_free(wrong_funding);
	closing_dev_memleak(ctx, scriptpubkey, funding_wscript);
#endif

	/* We're done! */
	/* Properly close the channel first. */
	if (!socket_close(pps->peer_fd))
		status_unusual("Closing and draining peerfd gave error: %s",
			       strerror(errno));
	/* Sending the below will kill us! */
	wire_sync_write(REQ_FD, take(towire_closingd_complete(NULL)));
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
