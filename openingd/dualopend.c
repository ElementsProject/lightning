/*~ Welcome to the ~nifty~ dual-opening daemon: the other gateway to channels!
 *
 * This daemon handles a single peer.  It's happy to trade gossip with the
 * peer until either lightningd asks it to fund a channel, or the peer itself
 * asks to fund a channel.  Then it goes through with the channel opening
 * negotiations.  It's important to note that until this negotiation is complete,
 * there's nothing permanent about the channel: lightningd will only have to
 * commit to the database once dualopend succeeds.
 *
 * Much like the original opening daemon, openingd, dualopend implements the
 * new and improved, two-party opening protocol, which allows bother peers to
 * contribute inputs to the transaction
 */
#include <bitcoin/feerate.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <bitcoin/varint.h>
#include <ccan/ccan/array_size/array_size.h>
#include <ccan/ccan/mem/mem.h>
#include <ccan/ccan/take/take.h>
#include <ccan/ccan/time/time.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/short_types/short_types.h>
#include <common/amount.h>
#include <common/channel_config.h>
#include <common/channel_id.h>
#include <common/crypto_sync.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/gossip_store.h>
#include <common/htlc.h>
#include <common/initial_channel.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/penalty_base.h>
#include <common/per_peer_state.h>
#include <common/psbt_open.h>
#include <common/read_peer_msg.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include "dual_fund_roles.h"
#include <errno.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <openingd/gen_dual_open_wire.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/gen_common_wire.h>
#include <wire/gen_peer_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == lightningd, 3 == peer, 4 == gossipd, 5 = gossip_store, 6 = hsmd */
#define REQ_FD STDIN_FILENO
#define HSM_FD 6

struct psbt_changeset {
	struct input_set **added_ins;
	struct input_set **rm_ins;
	struct output_set **added_outs;
	struct output_set **rm_outs;
};

/* Global state structure.  This is only for the one specific peer and channel */
struct state {
	struct per_peer_state *pps;

	/* Features they offered */
	u8 *their_features;

	/* Constraints on a channel they open. */
	u32 minimum_depth;
	u32 min_feerate, max_feerate;
	struct amount_msat min_effective_htlc_capacity;

	/* Limits on what remote config we accept. */
	u32 max_to_self_delay;

	/* These are the points lightningd told us to use when accepting or
	 * opening a channel. */
	struct basepoints our_points;
	struct pubkey our_funding_pubkey;

	/* Information we need between funding_start and funding_complete */
	struct basepoints their_points;
	struct pubkey their_funding_pubkey;

	/* hsmd gives us our first per-commitment point, and peer tells us
	 * theirs */
	struct pubkey first_per_commitment_point[NUM_SIDES];

	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	struct amount_sat opener_funding;
	struct amount_sat accepter_funding;
	u32 tx_locktime;

	struct sha256 opening_podle_h2;
	enum dual_fund_roles our_role;

	u32 feerate_per_kw_funding;
	u32 feerate_per_kw;

	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	/* If non-NULL, this is the scriptpubkey we/they *must* close with */
	u8 *upfront_shutdown_script[NUM_SIDES];

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel. */
	struct channel_config localconf, remoteconf;

	/* The channel structure, as defined in common/initial_channel.h.  While
	 * the structure has room for HTLCs, those routines are channeld-specific
	 * as initial channels never have HTLCs. */
	struct channel *channel;

	struct feature_set *our_features;

	/* Set of pending changes to send to peer */
	struct psbt_changeset *changeset;
};

#if EXPERIMENTAL_FEATURES
static u8 *changeset_get_next(const tal_t *ctx, struct channel_id *cid,
			      struct psbt_changeset **set)
{
	size_t count;
	u16 serial_id;
	u8 *msg;

	if ((count = tal_count((*set)->added_ins)) && count > 0) {
		struct input_set *in = (*set)->added_ins[0];
		u16 max_witness_len;
		u8 *script;

		if (!psbt_get_serial_id(in->in->unknowns, &serial_id))
			abort();

		const u8 *prevtx = linearize_wtx(ctx, in->in->non_witness_utxo);
		if (!psbt_input_get_max_witness_len(in->in, &max_witness_len))
			abort();

		if (in->in->redeem_script_len)
			script = tal_dup_arr(ctx, u8, in->in->redeem_script,
					     in->in->redeem_script_len, 0);
		else
			script = NULL;

		msg = towire_tx_add_input(ctx, cid, serial_id,
					  prevtx, in->tx_in->index,
					  max_witness_len,
					  script,
					  NULL);

		/* Is this a kosher way to move the list forward? */
		/* FIXME: use a macro for these? */
		tal_free((*set)->added_ins[0]);
		if (count == 1)
			(*set)->added_ins = NULL;
		else
			(*set)->added_ins++;
		return msg;
	}
	if ((count = tal_count((*set)->rm_ins)) && count > 0) {
		if (!psbt_get_serial_id((*set)->rm_ins[0]->in->unknowns, &serial_id))
			abort();

		msg = towire_tx_remove_input(ctx, cid, serial_id);

		/* Is this a kosher way to move the list forward? */
		tal_free((*set)->rm_ins[0]);
		if (count == 1)
			(*set)->rm_ins = NULL;
		else
			(*set)->rm_ins++;
		return msg;
	}
	if ((count = tal_count((*set)->added_outs)) && count > 0) {
		struct amount_sat sats;
		struct amount_asset asset_amt;

		struct output_set *out = (*set)->added_outs[0];
		if (!psbt_get_serial_id(out->out->unknowns, &serial_id))
			abort();

		asset_amt = wally_tx_output_get_amount(out->tx_out);
		sats = amount_asset_to_sat(&asset_amt);
		const u8 *script = wally_tx_output_get_script(ctx, out->tx_out);

		msg = towire_tx_add_output(ctx, cid, serial_id,
					   sats.satoshis, /* Raw: wire interface */
					   script);

		/* Is this a kosher way to move the list forward? */
		tal_free((*set)->added_outs[0]);
		if (count == 1)
			(*set)->added_outs = NULL;
		else
			(*set)->added_outs++;
		return msg;
	}
	if ((count = tal_count((*set)->rm_outs)) && count > 0) {
		if (!psbt_get_serial_id((*set)->rm_outs[0]->out->unknowns, &serial_id))
			abort();

		msg = towire_tx_remove_output(ctx, cid, serial_id);

		/* Is this a kosher way to move the list forward? */
		tal_free((*set)->rm_outs[0]);
		if (count == 1)
			(*set)->rm_outs = NULL;
		else
			(*set)->rm_outs++;
		return msg;
	}
	return NULL;
}

/*~ If we can't agree on parameters, we fail to open the channel.  If we're
 * the opener, we need to tell lightningd, otherwise it never really notices. */
static void negotiation_aborted(struct state *state, bool am_opener,
				const char *why)
{
	status_debug("aborted opening negotiation: %s", why);
	/*~ The "billboard" (exposed as "status" in the JSON listpeers RPC
	 * call) is a transient per-channel area which indicates important
	 * information about what is happening.  It has a "permanent" area for
	 * each state, which can be used to indicate what went wrong in that
	 * state (such as here), and a single transient area for current
	 * status. */
	peer_billboard(true, why);

	/* If necessary, tell master that funding failed. */
	if (am_opener) {
		u8 *msg = towire_dual_open_failed(NULL, why);
		wire_sync_write(REQ_FD, take(msg));
	}

	/* Default is no shutdown_scriptpubkey: free any leftover ones. */
	state->upfront_shutdown_script[LOCAL]
		= tal_free(state->upfront_shutdown_script[LOCAL]);
	state->upfront_shutdown_script[REMOTE]
		= tal_free(state->upfront_shutdown_script[REMOTE]);

	/*~ Reset state.  We keep gossipping with them, even though this open
	* failed. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = tal_free(state->channel);
}

/*~ For negotiation failures: we tell them the parameter we didn't like. */
static void negotiation_failed(struct state *state, bool am_opener,
			       const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	u8 *msg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	msg = towire_errorfmt(NULL, &state->channel_id,
			      "You gave bad parameters: %s", errmsg);
	sync_crypto_write(state->pps, take(msg));

	negotiation_aborted(state, am_opener, errmsg);
}

static void check_channel_id(struct state *state,
			     struct channel_id *id_in,
			     struct channel_id *orig_id)
{
	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as
	 * the `temporary_channel_id` in the `open_channel` message.
	 */
	if (!channel_id_eq(id_in, orig_id))
		peer_failed(state->pps,	id_in,
			    "channel ids don't match. expected %s, got %s",
			    type_to_string(tmpctx, struct channel_id, orig_id),
			    type_to_string(tmpctx, struct channel_id, id_in));
}

static struct amount_sat total_funding(struct state *state)
{
	struct amount_sat total;
	if (!amount_sat_add(&total, state->opener_funding, state->accepter_funding))
		abort();
	return total;
}

static void set_reserve(struct state *state)
{
	struct amount_sat reserve;

	/* BOLT-FIXME #2
	 *
	 * The channel reserve is fixed at 1% of the total channel balance
	 * rounded down (sum of `funding_satoshis` from `open_channel2` and `accept_channel2`)
	 * or the `dust_limit_satoshis`, whichever is greater.
	 */
	reserve.satoshis = total_funding(state).satoshis / 100; /* Raw: rounding */

	if (amount_sat_greater(state->remoteconf.dust_limit, reserve))
		state->remoteconf.channel_reserve = state->remoteconf.dust_limit;
	else
		state->remoteconf.channel_reserve = reserve;

	if (amount_sat_greater(state->localconf.dust_limit, reserve))
		state->localconf.channel_reserve = state->localconf.dust_limit;
	else
		state->localconf.channel_reserve = reserve;
}

static bool is_openers(struct wally_unknowns_map *unknowns)
{
	u16 serial_id;
	if (!psbt_get_serial_id(unknowns, &serial_id))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "PSBTs must have serial_ids set");

	return serial_id % 2 == 0;
}

static size_t psbt_input_weight(struct wally_psbt *psbt,
				size_t in)
{
	size_t weight;
	u16 max_witness_len;
	bool ok;

	/* txid + txout + sequence */
	weight = (32 + 4 + 4) * 4;
	weight +=
		(psbt->inputs[in].redeem_script_len +
			(varint_t) varint_size(psbt->inputs[in].redeem_script_len)) * 4;

	ok = psbt_input_get_max_witness_len(&psbt->inputs[in],
					    &max_witness_len);
	assert(ok);
	weight += max_witness_len;
	return weight;
}

static bool check_balances(struct wally_psbt *psbt,
			   bool check_opener_balance,
			   bool do_full_tx_check,
			   u32 feerate_per_kw_funding)
{
	struct amount_sat side_input_amt, side_output_amt,
			  input_amt, output_amt, fee, diff;
	size_t weight;
	bool ok;

	if (check_opener_balance)
		weight = common_weight(psbt->num_inputs, psbt->num_outputs);
	else
		weight = 0;

	/* Find the total input and output sums for this participant */
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct amount_sat amt;
		/* Add to total balance check */
		ok = amount_sat_add(&input_amt, input_amt, amt);
		assert(ok);
		if (is_openers(psbt->inputs[i].unknowns) == check_opener_balance) {
			amt = psbt_input_get_amount(psbt, i);
			ok = amount_sat_add(&side_input_amt, side_input_amt, amt);
			assert(ok);

			weight += psbt_input_weight(psbt, i);
		}
	}
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		struct amount_sat amt;
		/* Add to total balance check */
		ok = amount_sat_add(&output_amt, output_amt, amt);
		assert(ok);
		if (is_openers(psbt->outputs[i].unknowns) == check_opener_balance) {
			amt = psbt_output_get_amount(psbt, i);
			ok = amount_sat_add(&side_output_amt, side_output_amt, amt);
			assert(ok);

			weight += (8 + psbt->tx->outputs[i].script_len +
					varint_size(psbt->tx->outputs[i].script_len)) * 4;
		}
	}

	/* Inputs must exceed outputs */
	if (do_full_tx_check && !amount_sat_greater(input_amt, output_amt))
		return false;

	/* Find difference, or fail if too small */
	if (!amount_sat_sub(&diff, side_input_amt, side_output_amt))
		return false;

	/* Figure out the fee for their side */
	fee = amount_tx_fee(feerate_per_kw_funding, weight);

	/* Can they cover their fee? */
	return amount_sat_greater_eq(diff, fee);
}


/*~ This is the key function that checks that their configuration is reasonable:
 * it applied for both the case where they're trying to open a channel, and when
 * they've accepted our open. */
static bool check_configs(struct state *state,
			  const struct channel_config *remoteconf,
			  bool am_opener)
{
	struct amount_sat capacity;
	struct amount_sat reserve;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `to_self_delay` is unreasonably large.
	 */
	if (remoteconf->to_self_delay > state->max_to_self_delay) {
		negotiation_failed(state, am_opener,
				   "to_self_delay %u larger than %u",
				   remoteconf->to_self_delay,
				   state->max_to_self_delay);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MAY fail the channel if:
	 *...
	 *   - `funding_satoshis` is too small.
	 *   - it considers `htlc_minimum_msat` too large.
	 *   - it considers `max_htlc_value_in_flight_msat` too small.
	 *   - it considers `channel_reserve_satoshis` too large.
	 *   - it considers `max_accepted_htlcs` too small.
	 */
	/* We accumulate this into an effective bandwidth minimum. */

	/* Add both reserves to deduct from capacity. */
	if (!amount_sat_add(&reserve,
			    remoteconf->channel_reserve,
			    state->localconf.channel_reserve)) {
		negotiation_failed(state, am_opener,
				   "channel_reserve_satoshis %s"
				   " too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve));
		return false;
	}

	/* If reserves are larger than total sat, we fail. */
	if (!amount_sat_sub(&capacity, total_funding(state), reserve)) {
		struct amount_sat amt = total_funding(state);
		negotiation_failed(state, am_opener,
				   "channel_reserve_satoshis %s"
				   " and %s too large for funding %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_sat, &amt));
		return false;
	}

	/* If they set the max HTLC value to less than that number, it caps
	 * the channel capacity. */
	if (amount_sat_greater(capacity,
			       amount_msat_to_sat_round_down(remoteconf->max_htlc_value_in_flight)))
		capacity = amount_msat_to_sat_round_down(remoteconf->max_htlc_value_in_flight);

	/* If the minimum htlc is greater than the capacity, the channel is
	 * useless. */
	if (amount_msat_greater_sat(remoteconf->htlc_minimum, capacity)) {
		struct amount_sat amt = total_funding(state);
		negotiation_failed(state, am_opener,
				   "htlc_minimum_msat %s"
				   " too large for funding %s"
				   " capacity_msat %s",
				   type_to_string(tmpctx, struct amount_msat,
						  &remoteconf->htlc_minimum),
				   type_to_string(tmpctx, struct amount_sat, &amt),
				   type_to_string(tmpctx, struct amount_sat,
						  &capacity));
		return false;
	}

	/* If the resulting channel doesn't meet our minimum "effective capacity"
	 * set by lightningd, don't bother opening it. */
	if (amount_msat_greater_sat(state->min_effective_htlc_capacity,
				    capacity)) {
		struct amount_sat amt = total_funding(state);
		negotiation_failed(state, am_opener,
				   "channel capacity with funding %s,"
				   " reserves %s/%s,"
				   " max_htlc_value_in_flight_msat is %s,"
				   " channel capacity is %s, which is below %s",
				   type_to_string(tmpctx, struct amount_sat, &amt),
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_msat,
						  &remoteconf->max_htlc_value_in_flight),
				   type_to_string(tmpctx, struct amount_sat,
						  &capacity),
				   type_to_string(tmpctx, struct amount_msat,
						  &state->min_effective_htlc_capacity));
		return false;
	}

	/* We don't worry about how many HTLCs they accept, as long as > 0! */
	if (remoteconf->max_accepted_htlcs == 0) {
		negotiation_failed(state, am_opener,
				   "max_accepted_htlcs %u invalid",
				   remoteconf->max_accepted_htlcs);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `max_accepted_htlcs` is greater than 483.
	 */
	if (remoteconf->max_accepted_htlcs > 483) {
		negotiation_failed(state, am_opener,
				   "max_accepted_htlcs %u too large",
				   remoteconf->max_accepted_htlcs);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `dust_limit_satoshis` is greater than `channel_reserve_satoshis`.
	 */
	if (amount_sat_greater(remoteconf->dust_limit,
			       remoteconf->channel_reserve)) {
		negotiation_failed(state, am_opener,
				   "dust_limit_satoshis %s"
				   " too large for channel_reserve_satoshis %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->dust_limit),
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve));
		return false;
	}

	return true;
}

static bool is_segwit_output(struct wally_tx_output *output,
			     const u8 *redeemscript)
{
	u8 *wit_prog;
	if (tal_bytelen(redeemscript) > 0)
		wit_prog = cast_const(u8 *, redeemscript);
	else
		wit_prog = cast_const(u8 *, wally_tx_output_get_script(tmpctx, output));

	return is_p2wsh(wit_prog, NULL) || is_p2wpkh(wit_prog, NULL);
}

static struct wally_psbt *
fetch_next_moves(struct state *state, const struct wally_psbt *psbt)
{
	u8 *msg, msg_type;
	struct wally_psbt *updated_psbt;

	/* Go ask lightningd what other changes we've got */
	msg = towire_dual_open_psbt_changed(NULL, psbt);

	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	msg_type = fromwire_peektype(msg);
	if (msg_type == WIRE_DUAL_OPEN_FAIL) {
		char *err;
		if (!fromwire_dual_open_fail(msg, msg, &err))
			master_badmsg(msg_type, msg);

		peer_failed(state->pps, &state->channel_id, "%s", err);
	} else if (msg_type == WIRE_DUAL_OPEN_PSBT_CHANGED) {
		if (!fromwire_dual_open_psbt_changed(state, msg, &updated_psbt)) {
			master_badmsg(msg_type, msg);
			return NULL;
		}

		/* Does our PSBT meet requirements? */
		if (!check_balances(updated_psbt,
				    state->our_role == OPENER,
				    false, /* peers input/outputs not complete */
				    state->feerate_per_kw_funding))
			peer_failed(state->pps, &state->channel_id,
				    "Peer error updating tx state. "
				    "Local funds insufficient.");

		return updated_psbt;
	} else
		master_badmsg(msg_type, msg);

	return NULL;
}

static bool send_next(struct state *state, struct wally_psbt **psbt)
{
	u8 *msg;
	bool finished = false;
	struct wally_psbt *updated_psbt;
	struct psbt_changeset *cs = state->changeset;

	/* First we check our cached changes */
	msg = changeset_get_next(tmpctx, &state->channel_id,
				 &state->changeset);
	if (msg)
		goto sendmsg;

	/* If we don't have any changes cached, go ask Alice for
	 * what changes they've got for us */
	updated_psbt = fetch_next_moves(state, *psbt);

	/* We should always get a updated psbt back */
	if (!updated_psbt)
		peer_failed(state->pps, &state->channel_id,
			    "Unable to determine next tx update");

	if (psbt_has_diff(state->changeset, *psbt, updated_psbt,
			  &cs->added_ins, &cs->rm_ins,
			  &cs->added_outs, &cs->rm_outs)) {

		*psbt = tal_steal(state, updated_psbt);
		msg = changeset_get_next(tmpctx, &state->channel_id,
					 &state->changeset);
		assert(msg);
		goto sendmsg;
	}

	/*
	 * If there's no more moves, we send tx_complete
	 * and reply that we're finished */
	msg = towire_tx_complete(tmpctx, &state->channel_id);
	finished = true;

sendmsg:
	sync_crypto_write(state->pps, msg);

	return finished;
}

static bool find_txout(struct wally_psbt *psbt, const u8 *wscript, u16 *funding_txout) {
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		if (memeq(wscript, tal_bytelen(wscript), psbt->tx->outputs[i].script,
			  psbt->tx->outputs[i].script_len)) {
			*funding_txout = i;
			return true;
		}
	}
	return false;
}

static void run_tx_interactive(struct state *state, struct wally_psbt **orig_psbt)
{
	/* Opener always sends the first utxo info */
	bool we_complete = false, they_complete = false;
	u8 *msg;
	struct wally_psbt *psbt = *orig_psbt;

	while (!(we_complete && they_complete)) {
		struct channel_id cid;
		enum wire_type t;
		u16 serial_id;

		/* Reset their_complete to false every round,
		 * they have to re-affirm every time  */
		they_complete = false;

		msg = sync_crypto_read(tmpctx, state->pps);
		t = fromwire_peektype(msg);
		switch (t) {
		case WIRE_TX_ADD_INPUT: {
			const u8 *tx_bytes, *redeemscript;
			u16 max_witness_len;
			u32 outnum;
			size_t pulled_len;
			struct bitcoin_tx *tx;
			struct bitcoin_txid txid;
			struct amount_sat amt;
			struct tlv_tx_add_input_tlvs *add_tlvs;

			if (!fromwire_tx_add_input(tmpctx, msg, &cid,
						   &serial_id,
						   cast_const2(u8 **, &tx_bytes),
						   &outnum,
						   &max_witness_len,
						   cast_const2(u8 **, &redeemscript),
						   add_tlvs))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_add_input %s",
					    tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);
			/*
			 * BOLT-FIXME #2:
			 * - if is the `initiator`:
			 *   - MUST send even `serial_id`s
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 * - it receives a `serial_id` from the peer
			 *   with the incorrect parity
			 */
			if (serial_id % 2 != 0)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid serial_id rcvd. %u", serial_id);
			/*
			 * BOLT-FIXME #2:
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *  - it recieves a duplicate `serial_id`
			 */
			if (psbt_has_serial_input(psbt, serial_id))
				peer_failed(state->pps, &state->channel_id,
					    "Duplicate serial_id rcvd. %u", serial_id);

			/* Convert tx_bytes to a tx! */
			tx = pull_bitcoin_tx(state, &tx_bytes, &pulled_len);
			if (pulled_len != tal_bytelen(tx_bytes) || !tx)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid tx sent. %s",
					    type_to_string(tmpctx, struct bitcoin_tx, tx));

			if (outnum >= tx->wtx->num_outputs)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid tx outnum sent. %u", outnum);
			/*
			 * BOLT-FIXME #2:
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *  - it receives an input that would create a
			 *    malleable transaction id (e.g. pre-Segwit)
			 */
			if (!is_segwit_output(&tx->wtx->outputs[outnum], redeemscript))
				peer_failed(state->pps, &state->channel_id,
					    "Invalid tx sent. Not SegWit %s",
					    type_to_string(tmpctx, struct bitcoin_tx, tx));

			/*
			 * BOLT- #2:
			 *  - MUST NOT re-transmit inputs it has already received from the peer
			 *  ...
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *  - it receives a duplicate input to one it sent previously
			 */
			bitcoin_txid(tx, &txid);
			if (psbt_has_input(psbt, &txid, outnum))
				peer_failed(state->pps, &state->channel_id,
					    "Unable to add input");

			/*
			 * FIXME: do this
			 * BOLT- #2:
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 * - it receives an unconfirmed input
			 */

			/*
			 * BOLT- #2:
			 * The receiving node:
			 *  - MUST add all received inputs to the funding transaction
			 */
			struct wally_psbt_input *in =
				psbt_append_input(psbt, &txid, outnum,
						  BITCOIN_TX_DEFAULT_SEQUENCE - 2);
			if (!in)
				peer_failed(state->pps, &state->channel_id,
					    "Unable to add input");
			/* FIXME: elements! */
			bitcoin_tx_output_get_amount_sat(tx, outnum, &amt);
			psbt_input_set_prev_utxo(psbt, psbt->num_inputs - 1,
						 bitcoin_tx_output_get_script(tmpctx,
									      tx, outnum),
						 amt);

			if (tal_bytelen(redeemscript) > 0) {
				psbt_input_set_redeemscript(psbt, psbt->num_inputs - 1,
							    redeemscript);
			}
			psbt_input_add_serial_id(in, serial_id);
			psbt_input_add_max_witness_len(in, max_witness_len);

			/* FIXME: what's in the tlv? */
			break;
		}
		case WIRE_TX_REMOVE_INPUT: {
			bool input_found = false;

			if (!fromwire_tx_remove_input(msg, &cid, &serial_id))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_remove_input %s",
					    tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);

			for (size_t i = 0; i < psbt->num_inputs; i++) {
				u16 input_serial;
				if (!psbt_get_serial_id(psbt->inputs[i].unknowns,
							&input_serial)) {
					peer_failed(state->pps, &state->channel_id,
						    "No input added with serial_id %u",
						    serial_id);
				}
				if (input_serial == serial_id) {
					psbt_rm_input(psbt, i);
					input_found = true;
					break;
				}
			}
			if (!input_found)
				peer_failed(state->pps, &state->channel_id,
					    "No input added with serial_id %u",
					    serial_id);
			break;
		}
		case WIRE_TX_ADD_OUTPUT: {
			u64 value;
			u8 *scriptpubkey;
			struct wally_psbt_output *out;
			struct amount_sat amt;
			if (!fromwire_tx_add_output(tmpctx, msg, &cid,
						    &serial_id, &value,
						    &scriptpubkey))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_add_output %s",
					    tal_hex(tmpctx, msg));
			check_channel_id(state, &cid, &state->channel_id);

			if (psbt_has_serial_output(psbt, serial_id))
				peer_failed(state->pps, &state->channel_id,
					    "Duplicate serial_id rcvd. %u", serial_id);
			amount_sat_from_u64(&amt, value);
			out = psbt_append_out(psbt, scriptpubkey, amt);
			psbt_output_add_serial_id(out, serial_id);
			break;
		}
		case WIRE_TX_REMOVE_OUTPUT: {
			bool out_found = false;

			if (!fromwire_tx_remove_output(msg, &cid, &serial_id))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_remove_output %s",
					    tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);

			for (size_t i = 0; i < psbt->num_outputs; i++) {
				u16 output_serial;
				if (!psbt_get_serial_id(psbt->outputs[i].unknowns,
							&output_serial)) {
					peer_failed(state->pps, &state->channel_id,
						    "No output added with serial_id %u",
						    serial_id);
				}
				if (output_serial == serial_id) {
					psbt_rm_output(psbt, i);
					out_found = true;
					break;
				}
			}
			if (!out_found)
				peer_failed(state->pps, &state->channel_id,
					    "No output added with serial_id %u",
					    serial_id);
			break;
		}
		case WIRE_TX_COMPLETE:
			if (!fromwire_tx_complete(msg, &cid))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_complete %s",
					    tal_hex(tmpctx, msg));
			check_channel_id(state, &cid, &state->channel_id);
			they_complete = true;
			break;
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_OPEN_CHANNEL:
		case WIRE_ACCEPT_CHANNEL:
		case WIRE_FUNDING_CREATED:
		case WIRE_FUNDING_SIGNED:
		case WIRE_FUNDING_LOCKED:
		case WIRE_SHUTDOWN:
		case WIRE_CLOSING_SIGNED:
		case WIRE_UPDATE_ADD_HTLC:
		case WIRE_UPDATE_FULFILL_HTLC:
		case WIRE_UPDATE_FAIL_HTLC:
		case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		case WIRE_COMMITMENT_SIGNED:
		case WIRE_REVOKE_AND_ACK:
		case WIRE_UPDATE_FEE:
		case WIRE_CHANNEL_REESTABLISH:
		case WIRE_ANNOUNCEMENT_SIGNATURES:
		case WIRE_GOSSIP_TIMESTAMP_FILTER:
		case WIRE_ONION_MESSAGE:
		case WIRE_TX_SIGNATURES:
		case WIRE_OPEN_CHANNEL2:
		case WIRE_ACCEPT_CHANNEL2:
		case WIRE_INIT_RBF:
		case WIRE_BLACKLIST_PODLE:
		case WIRE_CHANNEL_ANNOUNCEMENT:
		case WIRE_CHANNEL_UPDATE:
		case WIRE_NODE_ANNOUNCEMENT:
		case WIRE_QUERY_CHANNEL_RANGE:
		case WIRE_REPLY_CHANNEL_RANGE:
		case WIRE_QUERY_SHORT_CHANNEL_IDS:
		case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		case WIRE_PING:
		case WIRE_PONG:
			peer_failed(state->pps, &state->channel_id,
				    "Unexpected wire message %s",
				     tal_hex(tmpctx, msg));
		}

		if (!(we_complete && they_complete))
			we_complete = send_next(state, &psbt);
	}

	/* Return the 'finished' psbt */
	*orig_psbt = psbt;
}

static u8 *accepter_start(struct state *state, const u8 *oc2_msg)
{
	struct bitcoin_blkid chain_hash;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey;
	struct tlv_opening_tlvs open_tlv;
	u8 channel_flags;
	struct wally_psbt *psbt;
	char *err_reason;
	const u8 *wscript;
	struct channel_id cid;
	struct bitcoin_tx *remote_commit, *local_commit;
	struct bitcoin_signature remote_sig, local_sig;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
	secp256k1_ecdsa_signature *htlc_sigs;
	u8 *msg;
	struct penalty_base *pbase;
	u8 msg_type;

	state->our_role = ACCEPTER;

	if (!fromwire_open_channel2(oc2_msg, &chain_hash,
				    &state->feerate_per_kw_funding,
				    &state->opener_funding,
				    &state->remoteconf.dust_limit,
				    &state->remoteconf.max_htlc_value_in_flight,
				    &state->remoteconf.htlc_minimum,
				    &state->feerate_per_kw,
				    &state->remoteconf.to_self_delay,
				    &state->remoteconf.max_accepted_htlcs,
				    &state->tx_locktime,
				    &state->opening_podle_h2,
				    &their_funding_pubkey,
				    &theirs.revocation,
				    &theirs.payment,
				    &theirs.delayed_payment,
				    &theirs.htlc,
				    &state->first_per_commitment_point[REMOTE],
				    &channel_flags,
				    &open_tlv))
		peer_failed(state->pps, &state->channel_id,
			    "Parsing open_channel2 %s",
			    tal_hex(tmpctx, oc2_msg));

	if (open_tlv.option_upfront_shutdown_script) {
		state->upfront_shutdown_script[REMOTE] = tal_steal(state,
			open_tlv.option_upfront_shutdown_script->shutdown_scriptpubkey);
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *  - the `chain_hash` value is set to a hash of a chain
	 *  that is unknown to the receiver.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		negotiation_failed(state, false,
				   "Unknown chain-hash %s",
				   type_to_string(tmpctx,
						  struct bitcoin_blkid,
						  &chain_hash));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 * - `funding_satoshis` is greater than or equal to 2^24 and the receiver does not support
	 *   `option_support_large_channel`. */
	/* We choose to require *negotiation*, not just support! */
	if (!feature_negotiated(state->our_features, state->their_features,
				OPT_LARGE_CHANNELS)
	    && amount_sat_greater(state->opener_funding, chainparams->max_funding)) {
		negotiation_failed(state, false,
				   "opener's funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->opener_funding));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - it considers `feerate_per_kw` too small for timely processing or
	 *    unreasonably large.
	 */
	if (state->feerate_per_kw_funding < state->min_feerate) {
		negotiation_failed(state, false,
				   "feerate_per_kw_funding %u below minimum %u",
				   state->feerate_per_kw_funding, state->min_feerate);
		return NULL;
	}

	/* We can figure out the channel id now */
	derive_channel_id_v2(&state->channel_id,
			     &state->our_points.revocation,
			     &state->their_points.revocation);

	/* FIXME: pass the podle back also */
	msg = towire_dual_open_got_offer(NULL,
					 state->opener_funding,
					 state->remoteconf.dust_limit,
					 state->remoteconf.max_htlc_value_in_flight,
					 state->remoteconf.htlc_minimum,
					 state->feerate_per_kw_funding,
					 state->feerate_per_kw,
					 state->remoteconf.to_self_delay,
					 state->remoteconf.max_accepted_htlcs,
					 channel_flags,
					 state->tx_locktime,
					 state->upfront_shutdown_script[REMOTE]);

	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	if ((msg_type = fromwire_peektype(msg)) == WIRE_DUAL_OPEN_FAIL) {
		if (!fromwire_dual_open_fail(msg, msg, &err_reason))
			master_badmsg(msg_type, msg);

		u8 *errmsg = towire_errorfmt(tmpctx, &state->channel_id,
					     "%s", err_reason);
		sync_crypto_write(state->pps, take(errmsg));
		return NULL;
	}
	if (!fromwire_dual_open_got_offer_reply(state, msg,
						&state->accepter_funding, &psbt,
						&state->upfront_shutdown_script[LOCAL]))
		master_badmsg(WIRE_DUAL_OPEN_GOT_OFFER_REPLY, msg);


	/* Now that we know the total of the channel, we can set the reserve */
	set_reserve(state);

	if (!check_configs(state, &state->remoteconf, false))
	       return NULL;

	/* If we have an upfront shutdown script, send it to our peer */
	struct tlv_accept_tlvs *a_tlv = tlv_accept_tlvs_new(state);
	if (state->upfront_shutdown_script[LOCAL]) {
		a_tlv->option_upfront_shutdown_script = tal(a_tlv,
				struct tlv_accept_tlvs_option_upfront_shutdown_script);
		a_tlv->option_upfront_shutdown_script->shutdown_scriptpubkey =
			tal_dup_arr(a_tlv, u8, state->upfront_shutdown_script[LOCAL],
				    tal_count(state->upfront_shutdown_script[LOCAL]), 0);
	}

	msg = towire_accept_channel2(tmpctx, &state->channel_id,
				     state->accepter_funding,
				     state->localconf.dust_limit,
				     state->localconf.max_htlc_value_in_flight,
				     state->localconf.htlc_minimum,
				     state->minimum_depth,
				     state->localconf.to_self_delay,
				     state->localconf.max_accepted_htlcs,
				     &state->our_funding_pubkey,
				     &state->our_points.revocation,
				     &state->our_points.payment,
				     &state->our_points.delayed_payment,
				     &state->our_points.htlc,
				     &state->first_per_commitment_point[LOCAL],
				     a_tlv);

	sync_crypto_write(state->pps, msg);
	peer_billboard(false, "Channel Opening: accept sent, waiting for reply");

	run_tx_interactive(state, &psbt);

	/* Check that their amounts are sane */
	if (!check_balances(psbt, true, true, state->feerate_per_kw_funding))
		peer_failed(state->pps, &state->channel_id,
			    "Insufficient funds");

	/* Find the funding transaction txid */
	struct wally_tx *funding_tx;
	psbt_txid(psbt, &state->funding_txid, &funding_tx);

	wscript = bitcoin_redeem_2of2(tmpctx,
				      &state->our_funding_pubkey,
				      &their_funding_pubkey);

	/* Figure out the txout */
	if (!find_txout(psbt, wscript, &state->funding_txout))
		peer_failed(state->pps, &state->channel_id,
			    "Expected output not found on funding tx %s",
			    tal_hex(tmpctx, wscript));

	/* Wait for the peer to send us our commitment tx signature */
	msg = sync_crypto_read(tmpctx, state->pps);

	remote_sig.sighash_type = SIGHASH_ALL;
	if (fromwire_commitment_signed(tmpctx, msg, &cid,
				       &remote_sig.s,
				       &htlc_sigs))
		peer_failed(state->pps, &state->channel_id,
			    "Parsing commitment signed %s",
			    tal_hex(tmpctx, msg));

	check_channel_id(state, &cid, &state->channel_id);

	if (htlc_sigs != NULL)
		peer_failed(state->pps, &state->channel_id,
			    "Must not send HTLCs with first"
			     " commitment. %s",
			     tal_hex(tmpctx, msg));
	local_commit = initial_channel_tx(state, &wscript, state->channel,
					  &state->first_per_commitment_point[LOCAL],
					  LOCAL, NULL, &err_reason);

	/* This shouldn't happen either, AFAICT. */
	if (!local_commit) {
		negotiation_failed(state, false,
				   "Could not meet our fees and reserve: %s",
				   err_reason);
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect:
	 *     - MUST fail the channel.
	 */
	if (!check_tx_sig(local_commit, 0, NULL, wscript, &their_funding_pubkey,
			  &remote_sig)) {
		/* BOLT #1:
		 *
		 * ### The `error` Message
		 *...
		 * - when failure was caused by an invalid signature check:
		 *    - SHOULD include the raw, hex-encoded transaction in reply
		 *      to a `funding_created`, `funding_signed`,
		 *      `closing_signed`, or `commitment_signed` message.
		 */
		/*~ This verbosity is not only useful for our own testing, but
		 * a courtesy to other implementaters whose brains may be so
		 * twisted by coding in Go, Scala and Rust that they can no
		 * longer read C code. */
		peer_failed(state->pps,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s (funding txid %s)",
			    type_to_string(tmpctx, struct bitcoin_signature,
					   &remote_sig),
			    type_to_string(tmpctx, struct bitcoin_tx, local_commit),
			    type_to_string(tmpctx, struct pubkey,
					   &their_funding_pubkey),
			    /* This is the first place we'd discover the funding tx
			     * doesn't match up */
			    type_to_string(tmpctx, struct bitcoin_txid,
					   &state->funding_txid));
	}

	state->channel = new_initial_channel(state,
					     &state->funding_txid,
					     state->funding_txout,
					     state->minimum_depth,
					     total_funding(state),
					     AMOUNT_MSAT(0),
					     take(new_fee_states(
							     NULL, REMOTE,
							     &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &theirs,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     true,
					     REMOTE);

	/* Create commitment tx signatures for remote */
	remote_commit = initial_channel_tx(state, &wscript, state->channel,
					   &state->first_per_commitment_point[LOCAL],
					   REMOTE, direct_outputs, &err_reason);

	if (!remote_commit) {
		negotiation_failed(state, false,
				   "Could not meet their fees and reserve: %s", err_reason);
		return NULL;
	}

	/* Make HSM sign it */
	msg = towire_hsm_sign_remote_commitment_tx(NULL,
						   remote_commit,
						   &state->channel->funding_pubkey[REMOTE],
						   &state->first_per_commitment_point[REMOTE],
						   true);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &local_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad sign_tx_reply %s", tal_hex(tmpctx, msg));

	assert(local_sig.sighash_type == SIGHASH_ALL);
	msg = towire_commitment_signed(tmpctx, &state->channel_id,
				       &local_sig.s,
				       NULL);

	if (direct_outputs[LOCAL])
		pbase = penalty_base_new(tmpctx, 0, remote_commit,
					 direct_outputs[LOCAL]);
	else
		pbase = NULL;

	/* Send the commitment_signed controller; will save to db
	 * and pass messages along to channeld to send along! */
	return towire_dual_open_commit_rcvd(tmpctx, remote_commit,
					    pbase,
					    &remote_sig,
					    psbt,
					    &state->channel_id,
					    state->pps,
					    &state->their_points.revocation,
					    &state->their_points.payment,
					    &state->their_points.htlc,
					    &state->their_points.delayed_payment,
					    &state->first_per_commitment_point[REMOTE],
					    &state->their_funding_pubkey,
					    &state->funding_txid,
					    state->funding_txout,
					    total_funding(state),
					    state->accepter_funding,
					    channel_flags,
					    state->feerate_per_kw,
					    msg,
					    state->localconf.channel_reserve,
					    state->upfront_shutdown_script[LOCAL],
					    state->upfront_shutdown_script[REMOTE]);
}
#endif /* EXPERIMENTAL_FEATURES */

/* Memory leak detection is DEVELOPER-only because we go to great lengths to
 * record the backtrace when allocations occur: without that, the leak
 * detection tends to be useless for diagnosing where the leak came from, but
 * it has significant overhead. */
#if DEVELOPER
static void handle_dev_memleak(struct state *state, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	/* Populate a hash table with all our allocations (except msg, which
	 * is in use right now). */
	memtable = memleak_enter_allocations(tmpctx, msg, msg);

	/* Now delete state and things it has pointers to. */
	memleak_remove_referenced(memtable, state);

	/* If there's anything left, dump it to logs, and return true. */
	found_leak = dump_memleak(memtable);
	wire_sync_write(REQ_FD,
			take(towire_dual_open_dev_memleak_reply(NULL,
							        found_leak)));
}

/* We were told to send a custommsg to the peer by `lightningd`. All the
 * verification is done on the side of `lightningd` so we should be good to
 * just forward it here. */
static void dualopend_send_custommsg(struct state *state, const u8 *msg)
{
	sync_crypto_write(state->pps, take(msg));
}
#endif

/*~ If we see the gossip_fd readable, we read a whole message.  Sure, we might
 * block, but we trust gossipd. */
static void handle_gossip_in(struct state *state)
{
	u8 *msg = wire_sync_read(NULL, state->pps->gossip_fd);

	if (!msg)
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Reading gossip: %s", strerror(errno));

	handle_gossip_msg(state->pps, take(msg));
}

static void try_read_gossip_store(struct state *state)
{
	u8 *msg = gossip_store_next(tmpctx, state->pps);

	if (msg)
		sync_crypto_write(state->pps, take(msg));
}

/*~ Is this message of type `error` with the special zero-id
 * "fail-everything"?  If lightningd asked us to send such a thing, we're
 * done. */
static void fail_if_all_error(const u8 *inner)
{
	struct channel_id channel_id;
	u8 *data;

	if (!fromwire_error(tmpctx, inner, &channel_id, &data)
	    || !channel_id_is_all(&channel_id)) {
		return;
	}

	status_info("Master said send err: %s",
		    sanitize_error(tmpctx, inner, NULL));
	exit(0);
}

/* Standard lightningd-fd-is-ready-to-read demux code.  Again, we could hang
 * here, but if we can't trust our parent, who can we trust? */
static u8 *handle_master_in(struct state *state)
{
	u8 *msg = wire_sync_read(tmpctx, REQ_FD);
	enum dual_open_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_DUAL_OPEN_DEV_MEMLEAK:
#if DEVELOPER
		handle_dev_memleak(state, msg);
		return NULL;
#endif
	/* mostly handled inline */
	case WIRE_DUAL_OPEN_DEV_MEMLEAK_REPLY:
	case WIRE_DUAL_OPEN_INIT:
	case WIRE_DUAL_OPEN_FAILED:
	case WIRE_DUAL_OPEN_FAIL:
	case WIRE_DUAL_OPEN_GOT_OFFER:
	case WIRE_DUAL_OPEN_GOT_OFFER_REPLY:
	case WIRE_DUAL_OPEN_COMMIT_RCVD:
	case WIRE_DUAL_OPEN_PSBT_CHANGED:
		break;
	}

	/* Now handle common messages. */
	switch ((enum common_wire_type)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_OUT:
		dualopend_send_custommsg(state, msg);
		return NULL;
#else
	case WIRE_CUSTOMMSG_OUT:
#endif
	/* We send these. */
	case WIRE_CUSTOMMSG_IN:
		break;
	}

	status_failed(STATUS_FAIL_MASTER_IO,
		      "Unknown msg %s", tal_hex(tmpctx, msg));
}

/*~ Standard "peer sent a message, handle it" demuxer.  Though it really only
 * handles one message, we use the standard form as principle of least
 * surprise. */
static u8 *handle_peer_in(struct state *state)
{
	u8 *msg = sync_crypto_read(tmpctx, state->pps);
	enum wire_type t = fromwire_peektype(msg);
	struct channel_id channel_id;

#if EXPERIMENTAL_FEATURES
	if (t == WIRE_OPEN_CHANNEL2)
		return accepter_start(state, msg);
#endif

#if DEVELOPER
	/* Handle custommsgs */
	enum wire_type type = fromwire_peektype(msg);
	if (type % 2 == 1 && !wire_type_is_defined(type)) {
		/* The message is not part of the messages we know how to
		 * handle. Assuming this is a custommsg, we just forward it to the
		 * master. */
		wire_sync_write(REQ_FD, take(towire_custommsg_in(NULL, msg)));
		return NULL;
	}
#endif

	/* Handles standard cases, and legal unknown ones. */
	if (handle_peer_gossip_or_error(state->pps,
					&state->channel_id, false, msg))
		return NULL;

	sync_crypto_write(state->pps,
			  take(towire_errorfmt(NULL,
					       extract_channel_id(msg, &channel_id) ? &channel_id : NULL,
					       "Unexpected message %s: %s",
					       wire_type_name(t),
					       tal_hex(tmpctx, msg))));

	/* FIXME: We don't actually want master to try to send an
	 * error, since peer is transient.  This is a hack.
	 */
	status_broken("Unexpected message %s", wire_type_name(t));
	peer_failed_connection_lost();
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	struct pollfd pollfd[3];
	struct state *state = tal(NULL, struct state);
	struct secret *none;
	u8 *msg, *inner;

	subdaemon_setup(argc, argv);

	/*~ This makes status_failed, status_debug etc work synchronously by
	 * writing to REQ_FD */
	status_setup_sync(REQ_FD);

	/*~ The very first thing we read from lightningd is our init msg */
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_dual_open_init(state, msg,
				     &chainparams,
				     &state->our_features,
				     &state->their_features,
				     &state->localconf,
				     &state->max_to_self_delay,
				     &state->min_effective_htlc_capacity,
				     &state->pps,
				     &state->our_points,
				     &state->our_funding_pubkey,
				     &state->minimum_depth,
				     &state->min_feerate, &state->max_feerate,
				     &inner))
		master_badmsg(WIRE_DUAL_OPEN_INIT, msg);

	/* 3 == peer, 4 == gossipd, 5 = gossip_store, 6 = hsmd */
	per_peer_state_set_fds(state->pps, 3, 4, 5);

	/*~ If lightningd wanted us to send a msg, do so before we waste time
	 * doing work.  If it's a global error, we'll close immediately. */
	if (inner != NULL) {
		sync_crypto_write(state->pps, inner);
		fail_if_all_error(inner);
		tal_free(inner);
	}

	/*~ Initially we're not associated with a channel, but
	 * handle_peer_gossip_or_error compares this. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = NULL;

	/*~ We set these to NULL, meaning no requirements on shutdown */
	state->upfront_shutdown_script[LOCAL]
		= state->upfront_shutdown_script[REMOTE]
		= NULL;

	/*~ We need an initial per-commitment point whether we're funding or
	 * they are, and lightningd has reserved a unique dbid for us already,
	 * so we might as well get the hsm daemon to generate it now. */
	wire_sync_write(HSM_FD,
			take(towire_hsm_get_per_commitment_point(NULL, 0)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_get_per_commitment_point_reply(tmpctx, msg,
							 &state->first_per_commitment_point[LOCAL],
							 &none))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad get_per_commitment_point_reply %s",
			      tal_hex(tmpctx, msg));
	/*~ The HSM gives us the N-2'th per-commitment secret when we get the
	 * N'th per-commitment point.  But since N=0, it won't give us one. */
	assert(none == NULL);

	/*~ Turns out this is useful for testing, to make sure we're ready. */
	status_debug("Handed peer, entering loop");

	/*~ We manually run a little poll() loop here.  With only three fds */
	pollfd[0].fd = REQ_FD;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = state->pps->gossip_fd;
	pollfd[1].events = POLLIN;
	pollfd[2].fd = state->pps->peer_fd;
	pollfd[2].events = POLLIN;

	/* We exit when we get a conclusion to write to lightningd: either
	 * opening_funder_reply or opening_fundee. */
	msg = NULL;
	while (!msg) {
		int t;
		struct timerel trel;
		if (time_to_next_gossip(state->pps, &trel))
			t = time_to_msec(trel);
		else
			t = -1;

		/*~ If we get a signal which aborts the poll() call, valgrind
		 * complains about revents being uninitialized.  I'm not sure
		 * that's correct, but it's easy to be sure. */
		pollfd[0].revents = pollfd[1].revents = pollfd[2].revents = 0;

		poll(pollfd, ARRAY_SIZE(pollfd), t);
		/* Subtle: handle_master_in can do its own poll loop, so
		 * don't try to service more than one fd per loop. */
		/* First priority: messages from lightningd. */
		if (pollfd[0].revents & POLLIN)
			msg = handle_master_in(state);
		/* Second priority: messages from peer. */
		else if (pollfd[2].revents & POLLIN)
			msg = handle_peer_in(state);
		/* Last priority: chit-chat from gossipd. */
		else if (pollfd[1].revents & POLLIN)
			handle_gossip_in(state);
		else
			try_read_gossip_store(state);

		/* Since we're the top-level event loop, we clean up */
		clean_tmpctx();
	}

	/*~ Write message and hand back the peer fd and gossipd fd.  This also
	 * means that if the peer or gossipd wrote us any messages we didn't
	 * read yet, it will simply be read by the next daemon. */
	wire_sync_write(REQ_FD, msg);
	per_peer_state_fdpass_send(REQ_FD, state->pps);
	status_debug("Sent %s with fds",
		     dual_open_wire_type_name(fromwire_peektype(msg)));

	/* This frees the entire tal tree. */
	tal_free(state);
	common_shutdown();
	daemon_shutdown();
	return 0;
}
