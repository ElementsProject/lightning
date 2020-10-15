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
#include <common/gossip_rcvd_filter.h>
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
#include <common/tx_roles.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <openingd/common.h>
#include <openingd/dualopend_wiregen.h>
#include <unistd.h>
#include <wire/common_wiregen.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == lightningd, 3 == peer, 4 == gossipd, 5 = gossip_store, 6 = hsmd */
#define REQ_FD STDIN_FILENO
#define HSM_FD 6

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
	struct pubkey their_funding_pubkey;

	/* Information we need between funding_start and funding_complete */
	struct basepoints their_points;

	/* hsmd gives us our first per-commitment point, and peer tells us
	 * theirs */
	struct pubkey first_per_commitment_point[NUM_SIDES];

	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	struct amount_sat opener_funding;
	struct amount_sat accepter_funding;
	u32 tx_locktime;

	struct sha256 opening_podle_h2;
	enum tx_role our_role;

	u32 feerate_per_kw_funding;
	u32 feerate_per_kw;

	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	/* If non-NULL, this is the scriptpubkey we/they *must* close with */
	u8 *upfront_shutdown_script[NUM_SIDES];

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel. */
	struct channel_config localconf, remoteconf;

	/* The channel structure, as defined in common/initial_channel.h. While
	 * the structure has room for HTLCs, those routines are
	 * channeld-specific as initial channels never have HTLCs. */
	struct channel *channel;

	struct feature_set *our_features;

	/* Set of pending changes to send to peer */
	struct psbt_changeset *changeset;

	/* The serial_id of the funding output */
	u16 funding_serial;
};

#if EXPERIMENTAL_FEATURES
/* psbt_changeset_get_next - Get next message to send
 *
 * This generates the next message to send from a changeset for the
 * interactive transaction protocol.
 *
 * @ctx - allocation context of returned msg
 * @cid - channel_id for the message
 * @set - changeset to get next update from
 *
 * Returns a wire message or NULL if no changes.
 */
static u8 *psbt_changeset_get_next(const tal_t *ctx,
				   struct channel_id *cid,
				   struct psbt_changeset *set)
{
	u16 serial_id;
	u8 *msg;

	if (tal_count(set->added_ins) != 0) {
		const struct input_set *in = &set->added_ins[0];
		u8 *script;

		if (!psbt_get_serial_id(&in->input.unknowns, &serial_id))
			abort();

		const u8 *prevtx = linearize_wtx(ctx,
						 in->input.utxo);

		if (in->input.redeem_script_len)
			script = tal_dup_arr(ctx, u8,
					     in->input.redeem_script,
					     in->input.redeem_script_len, 0);
		else
			script = NULL;

		msg = towire_tx_add_input(ctx, cid, serial_id,
					  prevtx, in->tx_input.index,
					  in->tx_input.sequence,
					  script,
					  NULL);

		tal_arr_remove(&set->added_ins, 0);
		return msg;
	}
	if (tal_count(set->rm_ins) != 0) {
		if (!psbt_get_serial_id(&set->rm_ins[0].input.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_input(ctx, cid, serial_id);

		tal_arr_remove(&set->rm_ins, 0);
		return msg;
	}
	if (tal_count(set->added_outs) != 0) {
		struct amount_sat sats;
		struct amount_asset asset_amt;

		const struct output_set *out = &set->added_outs[0];
		if (!psbt_get_serial_id(&out->output.unknowns, &serial_id))
			abort();

		asset_amt = wally_tx_output_get_amount(&out->tx_output);
		sats = amount_asset_to_sat(&asset_amt);
		const u8 *script = wally_tx_output_get_script(ctx,
							      &out->tx_output);

		msg = towire_tx_add_output(ctx, cid, serial_id,
					   sats.satoshis, /* Raw: wire interface */
					   script);

		tal_arr_remove(&set->added_outs, 0);
		return msg;
	}
	if (tal_count(set->rm_outs) != 0) {
		if (!psbt_get_serial_id(&set->rm_outs[0].output.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_output(ctx, cid, serial_id);

		/* Is this a kosher way to move the list forward? */
		tal_arr_remove(&set->rm_outs, 0);
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

static void set_reserve(struct state *state, struct amount_sat funding_total)
{
	struct amount_sat reserve;

	/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
	 *
	 * The channel reserve is fixed at 1% of the total channel balance
	 * rounded down (sum of `funding_satoshis` from `open_channel2` and `accept_channel2`)
	 * or the `dust_limit_satoshis`, whichever is greater.
	 */
	reserve = amount_sat_div(funding_total, 100);

	if (amount_sat_greater(state->remoteconf.dust_limit, reserve))
		state->remoteconf.channel_reserve = state->remoteconf.dust_limit;
	else
		state->remoteconf.channel_reserve = reserve;

	if (amount_sat_greater(state->localconf.dust_limit, reserve))
		state->localconf.channel_reserve = state->localconf.dust_limit;
	else
		state->localconf.channel_reserve = reserve;
}

static bool is_openers(const struct wally_map *unknowns)
{
	/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
	 * The sending node:
	 * ...
	 *   - if is the `initiator`:
	 *     - MUST send even `serial_id`s
	 *   - if is the `contributor`:
	 *   ...
	 *     - MUST send odd `serial_id`s
	 */
	u16 serial_id;
	if (!psbt_get_serial_id(unknowns, &serial_id))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "PSBTs must have serial_ids set");

	return serial_id % 2 == TX_INITIATOR;
}

static size_t psbt_input_weight(struct wally_psbt *psbt,
				size_t in)
{
	size_t weight;

	/* txid + txout + sequence */
	weight = (32 + 4 + 4) * 4;
	weight +=
		(psbt->inputs[in].redeem_script_len +
			(varint_t) varint_size(psbt->inputs[in].redeem_script_len)) * 4;

	/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2
	 * The minimum witness weight for an input is 110.
	 */
	weight += 110;
	return weight;
}

static size_t psbt_output_weight(struct wally_psbt *psbt,
				 size_t outnum)
{
	return (8 + psbt->tx->outputs[outnum].script_len +
		varint_size(psbt->tx->outputs[outnum].script_len)) * 4;
}

static bool find_txout(struct wally_psbt *psbt, const u8 *wscript, u16 *funding_txout)
{
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		if (memeq(wscript, tal_bytelen(wscript), psbt->tx->outputs[i].script,
			  psbt->tx->outputs[i].script_len)) {
			*funding_txout = i;
			return true;
		}
	}
	return false;
}

static char *check_balances(const tal_t *ctx,
			    struct state *state,
			    struct wally_psbt *psbt,
			    u32 feerate_per_kw_funding)
{
	struct amount_sat initiator_inputs, initiator_outs,
			  accepter_inputs, accepter_outs,
			  tot_input_amt, tot_output_amt,
			  initiator_fee, accepter_fee,
			  initiator_diff, accepter_diff;

	bool ok;
	u16 funding_outnum = psbt->num_outputs;
	size_t accepter_weight = 0;


	/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
	 * The initiator is responsible for paying the fees
	 * for the following fields, to be referred to as
	 * the `common fields`.
	 *   - version
	 *   - segwit marker + flag
	 *   - input count
	 *   - output count
	 *   - locktime */
	size_t initiator_weight =
		bitcoin_tx_core_weight(psbt->num_inputs,
				       psbt->num_outputs);

	u8 *funding_wscript =
		bitcoin_redeem_2of2(tmpctx,
				    &state->our_funding_pubkey,
				    &state->their_funding_pubkey);

	/* Find funding output, check balance */
	if (find_txout(psbt,
		       scriptpubkey_p2wsh(tmpctx, funding_wscript),
		       &funding_outnum)) {
		struct amount_sat output_val, total_funding;

		output_val = psbt_output_get_amount(psbt,
						    funding_outnum);
		if (!amount_sat_add(&total_funding,
				    state->accepter_funding,
				    state->opener_funding)) {
			return "overflow adding desired funding";
		}

		/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
		 * The receiving node:
		 *   ...
		 *   - MUST fail the channel if:
		 *   	...
		 *     - the value of the funding output is incorrect
		 */
		if (!amount_sat_eq(total_funding, output_val)) {
			return "total desired funding != "
			       "funding output";
		}

		/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
		 * The receiving node:
		 *   ...
		 *   - MUST fail the channel if:
		 *   	...
		 *   	- if the `funding_output` of the resulting
		 *   	transaction is less than the `dust_limit`
		 */
		if (!amount_sat_greater(output_val,
				state->remoteconf.dust_limit) ||
		    !amount_sat_greater(output_val,
				state->localconf.dust_limit)) {
			return "funding output is dust";
		}
	} else {
		/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
		 * The receiving node:
		 *   ...
		 *   - MUST fail the channel if:
		 *     - no funding output is received, identified by
		 *       the `script`
		 */
		return "funding output not present";
	}

	/* Find the total input and output sums */
	tot_input_amt = AMOUNT_SAT(0);
	initiator_inputs = AMOUNT_SAT(0);
	accepter_inputs = AMOUNT_SAT(0);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct amount_sat amt =
			psbt_input_get_amount(psbt, i);

		/* Add to total balance check */
		if (!amount_sat_add(&tot_input_amt,
				    tot_input_amt, amt)) {
			return "overflow adding input total";
		}

		if (is_openers(&psbt->inputs[i].unknowns)) {
			/* If the above additon passed,
			 * this should also */
			ok = amount_sat_add(&initiator_inputs,
					    initiator_inputs, amt);
			assert(ok);

			initiator_weight +=
				psbt_input_weight(psbt, i);
		} else {
			ok = amount_sat_add(&accepter_inputs,
					    accepter_inputs, amt);
			assert(ok);

			accepter_weight +=
				psbt_input_weight(psbt, i);
		}
	}
	tot_output_amt = AMOUNT_SAT(0);
	initiator_outs = state->opener_funding;
	accepter_outs = state->accepter_funding;
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		struct amount_sat amt =
			psbt_output_get_amount(psbt, i);

		/* Add to total balance check */
		if (!amount_sat_add(&tot_output_amt,
				    tot_output_amt, amt)) {
			return "overflow adding output total";
		}

		/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
		 * The sending node:
		 *   - MUST specify a `sats` value greater
		 *     than the dust limit
		 */
		if (!amount_sat_greater(amt,
				state->remoteconf.dust_limit) ||
		    !amount_sat_greater(amt,
				state->localconf.dust_limit)) {
			return "output is dust";
		}

		if (is_openers(&psbt->outputs[i].unknowns)) {
			/* Don't add the funding output to
			 * the amount */
			if (i != funding_outnum) {
				/* If the above additon passed,
				 * this should also */
				ok = amount_sat_add(&initiator_outs,
						    initiator_outs,
						    amt);
				assert(ok);
			}

			initiator_weight +=
				psbt_output_weight(psbt, i);
		} else {
			ok = amount_sat_add(&accepter_outs,
					    accepter_outs, amt);
			assert(ok);
			accepter_weight +=
				psbt_output_weight(psbt, i);
		}
	}

	/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
	 * The receiving node: ...
	 * - MUST fail the channel if:
	 *   ...
	 *   - the total satoshis of the inputs is less than
	 *     the outputs
	 */
	if (!amount_sat_greater_eq(tot_input_amt, tot_output_amt)) {
		return "inputs less than total outputs";
	}

	/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
	 * The receiving node: ...
	 * - MUST fail the channel if:
	 *   ...
	 *   - the peer's paid feerate does not meet or exceed
	 *   the agreed `feerate`, (based on the miminum fee).
	 *   - the `initiator`'s fees do not cover the `common`
	 *     fields
	 */
	if (!amount_sat_sub(&accepter_diff, accepter_inputs,
			    accepter_outs)) {
		return "accepter inputs less than outputs";
	}

	if (!amount_sat_sub(&initiator_diff, initiator_inputs,
			    initiator_outs)) {
		return "initiator inputs less than outputs";
	}

	/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
	 * Each party to the transaction is responsible for
	 * paying the fees for their input, output,
	 * and witness at the agreed `feerate`. */
	accepter_fee = amount_tx_fee(feerate_per_kw_funding,
				     accepter_weight);
	initiator_fee = amount_tx_fee(feerate_per_kw_funding,
				      initiator_weight);

	if (!amount_sat_greater_eq(accepter_diff, accepter_fee)) {
		return "accepter fee not covered";
	}

	if (!amount_sat_greater_eq(initiator_diff, initiator_fee)) {
		return tal_fmt(ctx,
			       "initiator fee %s not covered %s",
			       type_to_string(ctx,
					      struct amount_sat,
					      &initiator_fee),
			       type_to_string(ctx,
					      struct amount_sat,
					      &initiator_diff));

	}

	return NULL;
}

static bool is_segwit_output(struct wally_tx_output *output,
			     const u8 *redeemscript)
{
	const u8 *wit_prog;
	if (tal_bytelen(redeemscript) > 0)
		wit_prog = redeemscript;
	else
		wit_prog = wally_tx_output_get_script(tmpctx, output);

	return is_p2wsh(wit_prog, NULL) || is_p2wpkh(wit_prog, NULL);
}

static struct wally_psbt *
fetch_psbt_changes(struct state *state, const struct wally_psbt *psbt)
{
	u8 *msg;
	char *err;
	struct wally_psbt *updated_psbt;

	/* Go ask lightningd what other changes we've got */
	msg = towire_dual_open_psbt_changed(NULL, &state->channel_id,
					    state->funding_serial,
					    psbt);

	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	if (fromwire_dual_open_fail(msg, msg, &err))
		status_failed(STATUS_FAIL_MASTER_IO, "%s", err);
	else if (fromwire_dual_open_psbt_updated(state, msg, &updated_psbt)) {
		return updated_psbt;
	} else
		master_badmsg(fromwire_peektype(msg), msg);

	return NULL;
}

static bool send_next(struct state *state, struct wally_psbt **psbt)
{
	u8 *msg;
	bool finished = false;
	struct wally_psbt *updated_psbt;
	struct psbt_changeset *cs = state->changeset;

	/* First we check our cached changes */
	msg = psbt_changeset_get_next(tmpctx, &state->channel_id, cs);
	if (msg)
		goto sendmsg;

	/* If we don't have any changes cached, go ask Alice for
	 * what changes they've got for us */
	updated_psbt = fetch_psbt_changes(state, *psbt);

	/* We should always get a updated psbt back */
	if (!updated_psbt)
		peer_failed(state->pps, &state->channel_id,
			    "Unable to determine next tx update");

	state->changeset = tal_free(state->changeset);
	state->changeset = psbt_get_changeset(state, *psbt, updated_psbt);

	/* We want this old psbt to be cleaned up when the changeset is freed */
	tal_steal(state->changeset, *psbt);
	*psbt = tal_steal(state, updated_psbt);
	msg = psbt_changeset_get_next(tmpctx, &state->channel_id,
				      state->changeset);
	/*
	 * If there's no more moves, we send tx_complete
	 * and reply that we're finished */
	if (!msg) {
		msg = towire_tx_complete(tmpctx, &state->channel_id);
		finished = true;
	}

sendmsg:
	sync_crypto_write(state->pps, msg);

	return !finished;
}

static void init_changeset(struct state *state, struct wally_psbt *psbt)
{
	/* We need an empty to compare to */
	struct wally_psbt *empty_psbt = create_psbt(tmpctx, 0, 0, 0);

	state->changeset = psbt_get_changeset(state, empty_psbt, psbt);
}

/*~ Handle random messages we might get during opening negotiation, (eg. gossip)
 * returning the first non-handled one, or NULL if we aborted negotiation. */
static u8 *opening_negotiate_msg(const tal_t *ctx, struct state *state,
				 bool am_opener)
{
	/* This is an event loop of its own.  That's generally considered poor
	 * form, but we use it in a very limited way. */
	for (;;) {
		u8 *msg;
		bool from_gossipd;
		char *err;
		bool all_channels;
		struct channel_id actual;

		/* The event loop is responsible for freeing tmpctx, so our
		 * temporary allocations don't grow unbounded. */
		clean_tmpctx();

		/* This helper routine polls both the peer and gossipd. */
		msg = peer_or_gossip_sync_read(ctx, state->pps, &from_gossipd);

		/* Use standard helper for gossip msgs (forwards, if it's an
		 * error, exits). */
		if (from_gossipd) {
			handle_gossip_msg(state->pps, take(msg));
			continue;
		}

		/* Some messages go straight to gossipd. */
		if (is_msg_for_gossipd(msg)) {
			gossip_rcvd_filter_add(state->pps->grf, msg);
			wire_sync_write(state->pps->gossip_fd, take(msg));
			continue;
		}

		/* BOLT #1:
		 *
		 * A receiving node:
		 *   - upon receiving a message of _odd_, unknown type:
		 *     - MUST ignore the received message.
		 */
		if (is_unknown_msg_discardable(msg))
			continue;

		/* Might be a timestamp filter request: handle. */
		if (handle_timestamp_filter(state->pps, msg))
			continue;

		/* A helper which decodes an error. */
		if (is_peer_error(tmpctx, msg, &state->channel_id,
				  &err, &all_channels)) {
			/* BOLT #1:
			 *
			 *  - if no existing channel is referred to by the
			 *    message:
			 *    - MUST ignore the message.
			 */
			/* In this case, is_peer_error returns true, but sets
			 * err to NULL */
			if (!err) {
				tal_free(msg);
				continue;
			}
			/* Close connection on all_channels error. */
			if (all_channels) {
				if (am_opener) {
					msg = towire_dual_open_failed(NULL, err);
					wire_sync_write(REQ_FD, take(msg));
				}
				peer_failed_received_errmsg(state->pps, err,
							    NULL, false);
			}
			negotiation_aborted(state, am_opener,
					    tal_fmt(tmpctx, "They sent error %s",
						    err));
			/* Return NULL so caller knows to stop negotiating. */
			return NULL;
		}

		/*~ We do not support multiple "live" channels, though the
		 * protocol has a "channel_id" field in all non-gossip messages
		 * so it's possible.  Our one-process-one-channel mechanism
		 * keeps things simple: if we wanted to change this, we would
		 * probably be best with another daemon to de-multiplex them;
		 * this could be connectd itself, in fact. */
		if (is_wrong_channel(msg, &state->channel_id, &actual)) {
			status_debug("Rejecting %s for unknown channel_id %s",
				     peer_wire_name(fromwire_peektype(msg)),
				     type_to_string(tmpctx, struct channel_id,
						    &actual));
			sync_crypto_write(state->pps,
					  take(towire_errorfmt(NULL, &actual,
							       "Multiple channels"
							       " unsupported")));
			tal_free(msg);
			continue;
		}

		/* If we get here, it's an interesting message. */
		return msg;
	}
}

static bool run_tx_interactive(struct state *state,
			       struct wally_psbt **orig_psbt,
			       enum tx_role our_role)
{
	/* Opener always sends the first utxo info */
	bool we_complete = false, they_complete = false;
	u8 *msg;
	struct wally_psbt *psbt = *orig_psbt;

	while (!(we_complete && they_complete)) {
		struct channel_id cid;
		enum peer_wire t;
		u16 serial_id;

		/* Reset their_complete to false every round,
		 * they have to re-affirm every time  */
		they_complete = false;

		msg = opening_negotiate_msg(tmpctx, state,
					    our_role == TX_INITIATOR);
		if (!msg)
			return false;
		t = fromwire_peektype(msg);
		switch (t) {
		case WIRE_TX_ADD_INPUT: {
			const u8 *tx_bytes, *redeemscript;
			u32 outnum, sequence;
			size_t len;
			struct bitcoin_tx *tx;
			struct bitcoin_txid txid;
			struct amount_sat amt;
			struct tlv_tx_add_input_tlvs *add_tlvs =
				tlv_tx_add_input_tlvs_new(tmpctx);

			if (!fromwire_tx_add_input(tmpctx, msg, &cid,
						   &serial_id,
						   cast_const2(u8 **,
							       &tx_bytes),
						   &outnum, &sequence,
						   cast_const2(u8 **,
							       &redeemscript),
						   add_tlvs))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_add_input %s",
					    tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);
			/*
			 * BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2:
			 * - if is the `initiator`:
			 *   - MUST send even `serial_id`s
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 * - it receives a `serial_id` from the peer
			 *   with the incorrect parity
			 */
			if (serial_id % 2 == our_role)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid serial_id rcvd. %u",
					    serial_id);
			/*
			 * BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2:
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *  - it recieves a duplicate `serial_id`
			 */
			if (psbt_find_serial_input(psbt, serial_id) != -1)
				peer_failed(state->pps, &state->channel_id,
					    "Duplicate serial_id rcvd. %u", serial_id);

			/* Convert tx_bytes to a tx! */
			len = tal_bytelen(tx_bytes);
			tx = pull_bitcoin_tx(state, &tx_bytes, &len);
			if (!tx || len != 0)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid tx sent.");

			if (outnum >= tx->wtx->num_outputs)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid tx outnum sent. %u", outnum);
			/*
			 * BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2:
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *  - it receives an input that would create a
			 *    malleable transaction id (e.g. pre-Segwit)
			 */
			if (!is_segwit_output(&tx->wtx->outputs[outnum],
					      redeemscript))
				peer_failed(state->pps, &state->channel_id,
					    "Invalid tx sent. Not SegWit %s",
					    type_to_string(tmpctx,
							   struct bitcoin_tx,
							   tx));

			/*
			 * BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2:
			 *  - MUST NOT re-transmit inputs it has already
			 *    received from the peer
			 *  ...
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *  - it receives a duplicate input to one it
			 *    sent previously
			 */
			bitcoin_txid(tx, &txid);
			if (psbt_has_input(psbt, &txid, outnum))
				peer_failed(state->pps, &state->channel_id,
					    "Unable to add input - "
					    "already present");

			/*
			 * BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2:
			 * The receiving node:
			 *  - MUST add all received inputs to the funding
			 *    transaction
			 */
			struct wally_psbt_input *in =
				psbt_append_input(psbt, &txid, outnum,
						  sequence, NULL,
						  NULL,
						  redeemscript);
			if (!in)
				peer_failed(state->pps, &state->channel_id,
					    "Unable to add input");

			wally_psbt_input_set_utxo(in, tx->wtx);

			if (is_elements(chainparams)) {
				struct amount_asset asset;

				bitcoin_tx_output_get_amount_sat(tx, outnum,
								 &amt);

				/* FIXME: persist asset tags */
				asset = amount_sat_to_asset(&amt,
						chainparams->fee_asset_tag);
				/* FIXME: persist nonces */
				psbt_elements_input_set_asset(psbt,
							      outnum,
							      &asset);
			}

			psbt_input_set_serial_id(psbt, in, serial_id);

			/* FIXME: what's in the tlv? */
			break;
		}
		case WIRE_TX_REMOVE_INPUT: {
			int input_index;

			if (!fromwire_tx_remove_input(msg, &cid, &serial_id))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_remove_input %s",
					    tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);

			/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
			 * The sending node:
			 *   - MUST NOT send a `tx_remove_input` for an
			 *     input which is not theirs */
			if (serial_id % 2 == our_role)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid serial_id rcvd. %u",
					    serial_id);

			input_index = psbt_find_serial_input(psbt, serial_id);
			if (input_index == -1)
				peer_failed(state->pps, &state->channel_id,
					    "No input added with serial_id %u",
					    serial_id);

			psbt_rm_input(psbt, input_index);
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

			/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
			 * The receiving node:
			 *  ...
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *   - it receives a `serial_id` from the peer with the
			 *      incorrect parity */
			if (serial_id % 2 == our_role)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid serial_id rcvd. %u",
					    serial_id);

			if (psbt_find_serial_output(psbt, serial_id) != -1)
				peer_failed(state->pps, &state->channel_id,
					    "Duplicate serial_id rcvd. %u",
					    serial_id);
			amt = amount_sat(value);
			out = psbt_append_output(psbt, scriptpubkey, amt);
			psbt_output_set_serial_id(psbt, out, serial_id);
			break;
		}
		case WIRE_TX_REMOVE_OUTPUT: {
			int output_index;

			if (!fromwire_tx_remove_output(msg, &cid, &serial_id))
				peer_failed(state->pps, &state->channel_id,
					    "Parsing tx_remove_output %s",
					    tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);

			/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
			 * The sending node:
			 *   - MUST NOT send a `tx_remove_ouput` for an
			 *     input which is not theirs */
			if (serial_id % 2 == our_role)
				peer_failed(state->pps, &state->channel_id,
					    "Invalid serial_id rcvd. %u",
					    serial_id);

			output_index = psbt_find_serial_output(psbt, serial_id);
			if (output_index == -1)
				peer_failed(state->pps, &state->channel_id,
					    "No output added with serial_id %u",
					    serial_id);
			psbt_rm_output(psbt, output_index);
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
			return false;
		}

		if (!(we_complete && they_complete))
			we_complete = !send_next(state, &psbt);
	}

	/* Sort psbt! */
	psbt_sort_by_serial_id(psbt);

	/* Return the 'finished' psbt */
	*orig_psbt = psbt;
	return true;
}

static u8 *accepter_start(struct state *state, const u8 *oc2_msg)
{
	struct bitcoin_blkid chain_hash;
	struct tlv_opening_tlvs *open_tlv;
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
	struct amount_msat our_msats;
	struct amount_sat total;
	enum dualopend_wire msg_type;

	state->our_role = TX_ACCEPTER;
	open_tlv = tlv_opening_tlvs_new(tmpctx);

	if (!fromwire_open_channel2(oc2_msg, &chain_hash,
				    &state->opening_podle_h2,
				    &state->feerate_per_kw_funding,
				    &state->opener_funding,
				    &state->remoteconf.dust_limit,
				    &state->remoteconf.max_htlc_value_in_flight,
				    &state->remoteconf.htlc_minimum,
				    &state->feerate_per_kw,
				    &state->remoteconf.to_self_delay,
				    &state->remoteconf.max_accepted_htlcs,
				    &state->tx_locktime,
				    &state->their_funding_pubkey,
				    &state->their_points.revocation,
				    &state->their_points.payment,
				    &state->their_points.delayed_payment,
				    &state->their_points.htlc,
				    &state->first_per_commitment_point[REMOTE],
				    &channel_flags,
				    open_tlv))
		peer_failed(state->pps, &state->channel_id,
			    "Parsing open_channel2 %s",
			    tal_hex(tmpctx, oc2_msg));

	if (open_tlv->option_upfront_shutdown_script) {
		state->upfront_shutdown_script[REMOTE] = tal_steal(state,
			open_tlv->option_upfront_shutdown_script->shutdown_scriptpubkey);
	} else
		state->upfront_shutdown_script[REMOTE] = NULL;

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

	if (state->feerate_per_kw_funding > state->max_feerate) {
		negotiation_failed(state, false,
				   "feerate_per_kw_funding %u above maximum %u",
				   state->feerate_per_kw_funding, state->max_feerate);
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

	if (!psbt)
		psbt = create_psbt(state, 0, 0, state->tx_locktime);

	/* Check that total funding doesn't overflow */
	if (!amount_sat_add(&total, state->opener_funding,
			    state->accepter_funding))
		peer_failed(state->pps, &state->channel_id,
			    "Amount overflow. Local sats %s. "
			    "Remote sats %s",
			    type_to_string(tmpctx, struct amount_sat,
					   &state->accepter_funding),
			    type_to_string(tmpctx, struct amount_sat,
					   &state->opener_funding));

	/* Check that total funding doesn't exceed allowed channel capacity */
	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 * - `funding_satoshis` is greater than or equal to 2^24 and the receiver does not support
	 *   `option_support_large_channel`. */
	/* We choose to require *negotiation*, not just support! */
	if (!feature_negotiated(state->our_features, state->their_features,
				OPT_LARGE_CHANNELS)
	    && amount_sat_greater(total, chainparams->max_funding)) {
		negotiation_failed(state, false,
				   "total funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &total));
		return NULL;
	}

	/* Add all of our inputs/outputs to the changeset */
	init_changeset(state, psbt);

	/* Now that we know the total of the channel, we can set the reserve */
	set_reserve(state, total);

	if (!check_config_bounds(tmpctx, total, state->feerate_per_kw,
				 state->max_to_self_delay,
				 state->min_effective_htlc_capacity,
				 &state->remoteconf,
				 &state->localconf,
				 false,
				 true, /* v2 means we use anchor outputs */
				 &err_reason)) {
		negotiation_failed(state, false, "%s", err_reason);
		return NULL;
	}

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
	peer_billboard(false, "channel open: accept sent, waiting for reply");

	/* This is unused in this flow. We re-use
	 * the wire method between accepter + opener, so we set it
	 * to an invalid number, 1 (initiator sets; valid is even) */
	state->funding_serial = 1;
	/* Figure out what the funding transaction looks like! */
	if (!run_tx_interactive(state, &psbt, TX_ACCEPTER))
		return NULL;

	/* Find the funding transaction txid */
	psbt_txid(NULL, psbt, &state->funding_txid, NULL);

	wscript = bitcoin_redeem_2of2(state,
				      &state->our_funding_pubkey,
				      &state->their_funding_pubkey);

	/* Figure out the txout */
	if (!find_txout(psbt, scriptpubkey_p2wsh(tmpctx, wscript), &state->funding_txout))
		peer_failed(state->pps, &state->channel_id,
			    "Expected output %s not found on funding tx %s",
			    tal_hex(tmpctx, scriptpubkey_p2wsh(tmpctx, wscript)),
			    type_to_string(tmpctx, struct wally_psbt, psbt));

	/* Check tx funds are sane */
	err_reason = check_balances(tmpctx, state,
				    psbt,
				    state->feerate_per_kw_funding);
	if (err_reason)
		negotiation_failed(state, false,
				   "Insufficiently funded funding "
				   "tx, %s. %s",
				   err_reason,
				   type_to_string(tmpctx,
						  struct wally_psbt,
						  psbt));

	/* Wait for the peer to send us our commitment tx signature */
	msg = opening_negotiate_msg(tmpctx, state, false);
	if (!msg)
		return NULL;

	remote_sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_commitment_signed(tmpctx, msg, &cid,
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

	if (!amount_sat_to_msat(&our_msats, state->accepter_funding))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow converting accepter_funding "
			      "to msats");

	state->channel = new_initial_channel(state,
					     &state->channel_id,
					     &state->funding_txid,
					     state->funding_txout,
					     state->minimum_depth,
					     total,
					     our_msats,
					     take(new_fee_states(
							     NULL, REMOTE,
							     &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &state->their_points,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     true, true,
					     REMOTE);

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
	if (!check_tx_sig(local_commit, 0, NULL, wscript, &state->their_funding_pubkey,
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
			    "Bad signature %s on tx %s using key %s (funding txid %s, psbt %s)",
			    type_to_string(tmpctx, struct bitcoin_signature,
					   &remote_sig),
			    type_to_string(tmpctx, struct bitcoin_tx, local_commit),
			    type_to_string(tmpctx, struct pubkey,
					   &state->their_funding_pubkey),
			    /* This is the first place we'd discover the funding tx
			     * doesn't match up */
			    type_to_string(tmpctx, struct bitcoin_txid,
					   &state->funding_txid),
			    type_to_string(tmpctx, struct wally_psbt,
					   psbt));
	}

	/* Create commitment tx signatures for remote */
	remote_commit = initial_channel_tx(state, &wscript, state->channel,
					   &state->first_per_commitment_point[REMOTE],
					   REMOTE, direct_outputs, &err_reason);

	if (!remote_commit) {
		negotiation_failed(state, false,
				   "Could not meet their fees and reserve: %s", err_reason);
		return NULL;
	}

	/* Make HSM sign it */
	msg = towire_hsmd_sign_remote_commitment_tx(NULL,
						    remote_commit,
						    &state->channel->funding_pubkey[REMOTE],
						    &state->first_per_commitment_point[REMOTE],
						    true);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_sign_tx_reply(msg, &local_sig))
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
	return towire_dual_open_commit_rcvd(state,
					    &state->remoteconf,
					    remote_commit,
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
					    total,
					    state->accepter_funding,
					    channel_flags,
					    state->feerate_per_kw,
					    msg,
					    state->localconf.channel_reserve,
					    state->upfront_shutdown_script[LOCAL],
					    state->upfront_shutdown_script[REMOTE]);
}
#endif /* EXPERIMENTAL_FEATURES */

static u8 *opener_start(struct state *state, u8 *msg)
{
	struct tlv_opening_tlvs *open_tlv;
	struct tlv_accept_tlvs *a_tlv;
	struct channel_id cid;
	char *err_reason;
	struct amount_sat total;
	struct amount_msat our_msats;
	struct wally_psbt *psbt;
	struct wally_psbt_output *funding_out;
	struct sha256 podle;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
	struct penalty_base *pbase;
	u8 channel_flags;
	const u8 *wscript;
	struct bitcoin_tx *remote_commit, *local_commit;
	struct bitcoin_signature remote_sig, local_sig;
	secp256k1_ecdsa_signature *htlc_sigs;

	if (!fromwire_dual_open_opener_init(state, msg,
					  &psbt,
					  &state->opener_funding,
					  &state->upfront_shutdown_script[LOCAL],
					  &state->feerate_per_kw,
					  &state->feerate_per_kw_funding,
					  &channel_flags))
		master_badmsg(WIRE_DUAL_OPEN_OPENER_INIT, msg);

	state->our_role = TX_INITIATOR;
	state->tx_locktime = psbt->tx->locktime;
	open_tlv = tlv_opening_tlvs_new(tmpctx);

	if (state->upfront_shutdown_script[LOCAL]) {
		open_tlv->option_upfront_shutdown_script =
			tal(open_tlv,
			    struct tlv_opening_tlvs_option_upfront_shutdown_script);
		open_tlv->option_upfront_shutdown_script->shutdown_scriptpubkey =
			state->upfront_shutdown_script[LOCAL];
	}

	/* FIXME: actually set the podle */
	memset(&podle, 0, sizeof(podle));
	msg = towire_open_channel2(NULL,
				   &chainparams->genesis_blockhash,
				   &podle, /* FIXME: podle H2! */
				   state->feerate_per_kw_funding,
				   state->opener_funding,
				   state->localconf.dust_limit,
				   state->localconf.max_htlc_value_in_flight,
				   state->localconf.htlc_minimum,
				   state->feerate_per_kw,
				   state->localconf.to_self_delay,
				   state->localconf.max_accepted_htlcs,
				   state->tx_locktime,
				   &state->our_funding_pubkey,
				   &state->our_points.revocation,
				   &state->our_points.payment,
				   &state->our_points.delayed_payment,
				   &state->our_points.htlc,
				   &state->first_per_commitment_point[LOCAL],
				   channel_flags,
				   open_tlv);

	sync_crypto_write(state->pps, take(msg));

	/* This is usually a very transient state... */
	peer_billboard(false, "channel open: offered, waiting for accept_channel2");

	/* ... since their reply should be immediate. */
	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		return NULL;

	/* Set a cid default value, so on failure it's populated */
	memset(&cid, 0xFF, sizeof(cid));

	a_tlv = tlv_accept_tlvs_new(state);
	if (!fromwire_accept_channel2(msg, &cid,
				      &state->accepter_funding,
				      &state->remoteconf.dust_limit,
				      &state->remoteconf.max_htlc_value_in_flight,
				      &state->remoteconf.htlc_minimum,
				      &state->minimum_depth,
				      &state->remoteconf.to_self_delay,
				      &state->remoteconf.max_accepted_htlcs,
				      &state->their_funding_pubkey,
				      &state->their_points.revocation,
				      &state->their_points.payment,
				      &state->their_points.delayed_payment,
				      &state->their_points.htlc,
				      &state->first_per_commitment_point[REMOTE],
				      a_tlv))
		peer_failed(state->pps, &cid,
			    "Parsing accept_channel2 %s", tal_hex(msg, msg));

	if (a_tlv->option_upfront_shutdown_script) {
		state->upfront_shutdown_script[REMOTE] = tal_steal(state,
			a_tlv->option_upfront_shutdown_script->shutdown_scriptpubkey);
	} else
		state->upfront_shutdown_script[REMOTE] = NULL;

	derive_channel_id_v2(&state->channel_id,
			     &state->our_points.revocation,
			     &state->their_points.revocation);

	if (!channel_id_eq(&cid, &state->channel_id))
		peer_failed(state->pps, &state->channel_id,
			    "accept_channel2 ids don't match: "
			    "expected %s, got %s",
			    type_to_string(msg, struct channel_id,
					   &state->channel_id),
			    type_to_string(msg, struct channel_id, &cid));

	/* Check that total funding doesn't overflow */
	if (!amount_sat_add(&total, state->opener_funding,
			    state->accepter_funding))
		peer_failed(state->pps, &state->channel_id,
			    "Amount overflow. Local sats %s. "
			    "Remote sats %s",
			    type_to_string(tmpctx, struct amount_sat,
					   &state->opener_funding),
			    type_to_string(tmpctx, struct amount_sat,
					   &state->accepter_funding));

	/* Check that total funding doesn't exceed allowed channel capacity */
	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 * - `funding_satoshis` is greater than or equal to 2^24 and
	 *    the receiver does not support `option_support_large_channel`. */
	/* We choose to require *negotiation*, not just support! */
	if (!feature_negotiated(state->our_features, state->their_features,
				OPT_LARGE_CHANNELS)
	    && amount_sat_greater(total, chainparams->max_funding)) {
		negotiation_failed(state, false,
				   "total funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &total));
		return NULL;
	}

	/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
	 * The sending node:
	 *  - if is the `opener`:
	 *   - MUST send at least one `tx_add_output`,  the channel
	 *     funding output.
	 */
	wscript = bitcoin_redeem_2of2(state,
				      &state->our_funding_pubkey,
				      &state->their_funding_pubkey);
	funding_out = psbt_append_output(psbt,
					 scriptpubkey_p2wsh(tmpctx,
							    wscript),
					 total);
	/* Add a serial_id for this output */
	state->funding_serial = psbt_new_input_serial(psbt, TX_INITIATOR);
	psbt_output_set_serial_id(psbt, funding_out, state->funding_serial);

	/* Add all of our inputs/outputs to the changeset */
	init_changeset(state, psbt);

	/* Now that we know the total of the channel, we can
	 * set the reserve */
	set_reserve(state, total);

	if (!check_config_bounds(tmpctx, total, state->feerate_per_kw,
				 state->max_to_self_delay,
				 state->min_effective_htlc_capacity,
				 &state->remoteconf,
				 &state->localconf,
				 true, true, /* v2 means we use anchor outputs */
				 &err_reason)) {
		negotiation_failed(state, false, "%s", err_reason);
		return NULL;
	}

	/* Send our first message, we're opener we initiate here */
	if (!send_next(state, &psbt))
		negotiation_failed(state, true,
				   "Peer error, no updates to send");

	/* Figure out what the funding transaction looks like! */
	if (!run_tx_interactive(state, &psbt, TX_INITIATOR))
		return NULL;

	psbt_txid(NULL, psbt, &state->funding_txid, NULL);

	/* Figure out the txout */
	if (!find_txout(psbt, scriptpubkey_p2wsh(tmpctx, wscript),
			&state->funding_txout))
		peer_failed(state->pps, &state->channel_id,
			    "Expected output %s not found on funding tx %s",
			    tal_hex(tmpctx, scriptpubkey_p2wsh(tmpctx, wscript)),
			    type_to_string(tmpctx, struct wally_psbt, psbt));

	/* Check tx funds are sane */
	err_reason = check_balances(tmpctx, state,
				    psbt,
				    state->feerate_per_kw_funding);
	if (err_reason)
		negotiation_failed(state, true,
				   "Insufficiently funded funding "
				   "tx, %s. %s",
				   err_reason,
				   type_to_string(tmpctx,
						  struct wally_psbt,
						  psbt));

	if (!amount_sat_to_msat(&our_msats, state->opener_funding))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Rounding error, can't convert opener_funding %s"
			      " to msats",
			      type_to_string(tmpctx, struct amount_sat,
					     &state->opener_funding));

	/* Ok, we're mostly good now? Let's do this */
	state->channel = new_initial_channel(state,
					     &cid,
					     &state->funding_txid,
					     state->funding_txout,
					     state->minimum_depth,
					     total,
					     our_msats,
					     take(new_fee_states(NULL, LOCAL,
								 &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points,
					     &state->their_points,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     true, true,
					     /* Opener is local */
					     LOCAL);

	remote_commit = initial_channel_tx(state, &wscript,
					   state->channel,
					   &state->first_per_commitment_point[REMOTE],
					   REMOTE, direct_outputs, &err_reason);

	if (!remote_commit) {
		negotiation_failed(state, true,
				   "Could not meet their fees and reserve: %s",
				   err_reason);
		return NULL;
	}


	/* We ask the HSM to sign their commitment transaction for us: it knows
	 * our funding key, it just needs the remote funding key to create the
	 * witness script.  It also needs the amount of the funding output,
	 * as segwit signatures commit to that as well, even though it doesn't
	 * explicitly appear in the transaction itself. */
	msg = towire_hsmd_sign_remote_commitment_tx(NULL,
						   remote_commit,
						   &state->channel->funding_pubkey[REMOTE],
						   &state->first_per_commitment_point[REMOTE],
						   true);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_sign_tx_reply(msg, &local_sig))
		status_failed(STATUS_FAIL_HSM_IO, "Bad sign_tx_reply %s",
			      tal_hex(tmpctx, msg));

	/* You can tell this has been a problem before, since there's a debug
	 * message here: */
	status_debug("signature %s on tx %s using key %s",
		     type_to_string(tmpctx, struct bitcoin_signature, &local_sig),
		     type_to_string(tmpctx, struct bitcoin_tx, remote_commit),
		     type_to_string(tmpctx, struct pubkey,
				    &state->our_funding_pubkey));

	assert(local_sig.sighash_type == SIGHASH_ALL);
	msg = towire_commitment_signed(tmpctx, &state->channel_id,
				       &local_sig.s,
				       NULL);
	sync_crypto_write(state->pps, msg);
	peer_billboard(false, "channel open: commitment sent, waiting for reply");

	/* Wait for the peer to send us our commitment tx signature */
	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		return NULL;

	remote_sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_commitment_signed(tmpctx, msg, &cid,
					&remote_sig.s,
					&htlc_sigs))
		peer_failed(state->pps, &state->channel_id,
			    "Parsing commitment signed %s",
			    tal_hex(tmpctx, msg));

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
	if (!check_tx_sig(local_commit, 0, NULL, wscript, &state->their_funding_pubkey,
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
			    "Bad signature %s on tx %s using key %s (funding txid %s, psbt %s)",
			    type_to_string(tmpctx, struct bitcoin_signature,
					   &remote_sig),
			    type_to_string(tmpctx, struct bitcoin_tx, local_commit),
			    type_to_string(tmpctx, struct pubkey,
					   &state->their_funding_pubkey),
			    /* This is the first place we'd discover the funding tx
			     * doesn't match up */
			    type_to_string(tmpctx, struct bitcoin_txid,
					   &state->funding_txid),
			    type_to_string(tmpctx, struct wally_psbt,
					   psbt));
	}

	if (direct_outputs[LOCAL])
		pbase = penalty_base_new(state, 0, remote_commit,
					 direct_outputs[LOCAL]);
	else
		pbase = NULL;

	peer_billboard(false, "channel open: commitment received, "
		       "sending to lightningd to save");
	return towire_dual_open_commit_rcvd(state,
					    &state->remoteconf,
					    remote_commit,
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
					    total,
					    state->opener_funding,
					    channel_flags,
					    state->feerate_per_kw,
					    NULL,
					    state->localconf.channel_reserve,
					    state->upfront_shutdown_script[LOCAL],
					    state->upfront_shutdown_script[REMOTE]);

}

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
	memtable = memleak_find_allocations(tmpctx, msg, msg);

	/* Now delete state and things it has pointers to. */
	memleak_remove_region(memtable, state, tal_bytelen(state));

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
	enum dualopend_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_DUAL_OPEN_DEV_MEMLEAK:
#if DEVELOPER
		handle_dev_memleak(state, msg);
		return NULL;
#endif
	case WIRE_DUAL_OPEN_OPENER_INIT:
		return opener_start(state, msg);
	/* mostly handled inline */
	case WIRE_DUAL_OPEN_INIT:
	case WIRE_DUAL_OPEN_DEV_MEMLEAK_REPLY:
	case WIRE_DUAL_OPEN_FAILED:
	case WIRE_DUAL_OPEN_FAIL:
	case WIRE_DUAL_OPEN_GOT_OFFER:
	case WIRE_DUAL_OPEN_GOT_OFFER_REPLY:
	case WIRE_DUAL_OPEN_COMMIT_RCVD:
	case WIRE_DUAL_OPEN_PSBT_CHANGED:
	case WIRE_DUAL_OPEN_PSBT_UPDATED:
		break;
	}

	/* Now handle common messages. */
	switch ((enum common_wire)t) {
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
	enum peer_wire t = fromwire_peektype(msg);
	struct channel_id channel_id;

#if EXPERIMENTAL_FEATURES
	if (t == WIRE_OPEN_CHANNEL2)
		return accepter_start(state, msg);
#endif

#if DEVELOPER
	/* Handle custommsgs */
	enum peer_wire type = fromwire_peektype(msg);
	if (type % 2 == 1 && !peer_wire_is_defined(type)) {
		/* The message is not part of the messages we know how to
		 * handle. Assuming this is a custommsg, we just
		 * forward it to master. */
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
					       extract_channel_id(msg,
								  &channel_id) ?
							&channel_id : NULL,
					       "Unexpected message %s: %s",
					       peer_wire_name(t),
					       tal_hex(tmpctx, msg))));

	/* FIXME: We don't actually want master to try to send an
	 * error, since peer is transient.  This is a hack.
	 */
	status_broken("Unexpected message %s", peer_wire_name(t));
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
			take(towire_hsmd_get_per_commitment_point(NULL, 0)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
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
		     dualopend_wire_name(fromwire_peektype(msg)));

	/* This frees the entire tal tree. */
	tal_free(state);
	daemon_shutdown();
	return 0;
}
