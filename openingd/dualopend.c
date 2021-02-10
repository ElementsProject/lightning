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
#include <common/billboard.h>
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
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/read_peer_msg.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/tx_roles.h>
#include <common/type_to_string.h>
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

/* tx_add_input, tx_add_output, tx_rm_input, tx_rm_output */
#define NUM_TX_MSGS (TX_RM_OUTPUT + 1)
enum tx_msgs {
	TX_ADD_INPUT,
	TX_ADD_OUTPUT,
	TX_RM_INPUT,
	TX_RM_OUTPUT,
};

/*
 * BOLT-544bda7144d91b3f51856189b8932610649f9e93 #2:
  - MUST NOT send more than 2^12 ... messages
 */
#define MAX_TX_MSG_RCVD (1 << 12)

/* State for a 'new' funding transaction. There should be one
 * for every new funding transaction attempt */
struct tx_state {
	/* Funding and feerate: set by opening peer. */
	struct amount_sat opener_funding;
	struct amount_sat accepter_funding;
	u32 tx_locktime;
	u32 feerate_per_kw_funding;

	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel. */
	struct channel_config localconf, remoteconf;

	/* PSBT of the funding tx */
	struct wally_psbt *psbt;

	/* Set of pending changes to send to peer */
	struct psbt_changeset *changeset;

	/* The serial_id of the funding output */
	u64 funding_serial;

	/* Track how many of each tx collab msg we receive */
	u16 tx_msg_count[NUM_TX_MSGS];

	/* Have we gotten the peer's tx-sigs yet? */
	bool remote_funding_sigs_rcvd;
};

static struct tx_state *new_tx_state(const tal_t *ctx)
{
	struct tx_state *tx_state = tal(ctx, struct tx_state);
	tx_state->psbt = NULL;
	tx_state->remote_funding_sigs_rcvd = false;

	for (size_t i = 0; i < NUM_TX_MSGS; i++)
		tx_state->tx_msg_count[i] = 0;

	return tx_state;
}

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
	u8 channel_flags;

	struct sha256 opening_podle_h2;
	enum tx_role our_role;

	u32 feerate_per_kw_funding;
	u32 feerate_per_kw_commitment;

	/* If non-NULL, this is the scriptpubkey we/they *must* close with */
	u8 *upfront_shutdown_script[NUM_SIDES];

	/* The channel structure, as defined in common/initial_channel.h. While
	 * the structure has room for HTLCs, those routines are
	 * channeld-specific as initial channels never have HTLCs. */
	struct channel *channel;

	struct feature_set *our_features;

	/* Tally of which sides are locked, or not */
	bool funding_locked[NUM_SIDES];

	/* Are we shutting down? */
	bool shutdown_sent[NUM_SIDES];

	/* Were we reconnected at start ? */
	bool reconnected;

	/* State of inflight funding transaction attempt */
	struct tx_state *tx_state;
};

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
	u64 serial_id;
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
static void negotiation_aborted(struct state *state, const char *why)
{
	status_debug("aborted opening negotiation: %s", why);
	/*~ The "billboard" (exposed as "status" in the JSON listpeers RPC
	 * call) is a transient per-channel area which indicates important
	 * information about what is happening.  It has a "permanent" area for
	 * each state, which can be used to indicate what went wrong in that
	 * state (such as here), and a single transient area for current
	 * status. */
	peer_billboard(true, why);

	/* Tell master that funding failed. */
	u8 *msg = towire_dualopend_failed(NULL, why);
	wire_sync_write(REQ_FD, take(msg));

	/* Default is no shutdown_scriptpubkey: free any leftover ones. */
	state->upfront_shutdown_script[LOCAL]
		= tal_free(state->upfront_shutdown_script[LOCAL]);
	state->upfront_shutdown_script[REMOTE]
		= tal_free(state->upfront_shutdown_script[REMOTE]);

	/*~ Reset state.  We keep gossipping with them, even though this open
	* failed. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = tal_free(state->channel);
	state->tx_state = tal_free(state->tx_state);
}

static void open_error(struct state *state,
		       const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	u8 *msg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	msg = towire_errorfmt(NULL, &state->channel_id,
			      "%s", errmsg);
	sync_crypto_write(state->pps, take(msg));

	negotiation_aborted(state, errmsg);
}


/*~ For negotiation failures: we tell them the parameter we didn't like. */
static void negotiation_failed(struct state *state,
			       const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	open_error(state, "You gave bad parameters: %s", errmsg);
}

static void rbf_failed(struct state *state, const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	u8 *msg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	msg = towire_fail_rbf(NULL, &state->channel_id,
			      (u8 *)tal_dup_arr(errmsg, char, errmsg,
						strlen(errmsg), 0));
	sync_crypto_write(state->pps, take(msg));

	status_debug("aborted rbf negotiation: %s", errmsg);
	/*~ The "billboard" (exposed as "status" in the JSON listpeers RPC
	 * call) is a transient per-channel area which indicates important
	 * information about what is happening.  It has a "permanent" area for
	 * each state, which can be used to indicate what went wrong in that
	 * state (such as here), and a single transient area for current
	 * status. */
	peer_billboard(true, errmsg);

	/* Tell master that RBF failed. */
	msg = towire_dualopend_rbf_failed(NULL, errmsg);
	wire_sync_write(REQ_FD, take(msg));
}

static void billboard_update(struct state *state)
{
	const char *update = billboard_message(tmpctx, state->funding_locked,
					       NULL,
					       state->shutdown_sent,
					       0, /* Always zero? */
					       0);
	peer_billboard(false, update);
}

static void send_shutdown(struct state *state, const u8 *final_scriptpubkey)
{
	u8 *msg;

	msg = towire_shutdown(NULL, &state->channel_id,
			      final_scriptpubkey);
	sync_crypto_write(state->pps, take(msg));
	state->shutdown_sent[LOCAL] = true;
}

static void handle_peer_shutdown(struct state *state, u8 *msg)
{
	u8 *scriptpubkey;
	struct channel_id cid;

	if (!fromwire_shutdown(tmpctx, msg, &cid, &scriptpubkey))
		peer_failed_warn(state->pps, &state->channel_id,
			    "Bad shutdown %s", tal_hex(msg, msg));

	if (tal_count(state->upfront_shutdown_script[REMOTE])
	    && !memeq(scriptpubkey, tal_count(scriptpubkey),
		      state->upfront_shutdown_script[REMOTE],
		      tal_count(state->upfront_shutdown_script[REMOTE])))
		peer_failed_warn(state->pps, &state->channel_id,
				 "scriptpubkey %s is not as agreed upfront (%s)",
				 tal_hex(state, scriptpubkey),
				 tal_hex(state,
					 state->upfront_shutdown_script[REMOTE]));

	wire_sync_write(REQ_FD,
			take(towire_dualopend_got_shutdown(NULL,
							   scriptpubkey)));
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_dualopend_send_shutdown(tmpctx, msg, &scriptpubkey))
		master_badmsg(fromwire_peektype(msg), msg);

	state->shutdown_sent[REMOTE] = true;
	if (!state->shutdown_sent[LOCAL])
		send_shutdown(state, scriptpubkey);

	billboard_update(state);
}

static void handle_our_shutdown(struct state *state, u8 *msg)
{
	u8 *scriptpubkey;

	if (!fromwire_dualopend_send_shutdown(tmpctx, msg, &scriptpubkey))
		master_badmsg(fromwire_peektype(msg), msg);

	if (!state->shutdown_sent[LOCAL])
		send_shutdown(state, scriptpubkey);

	billboard_update(state);
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
		peer_failed_err(state->pps, id_in,
				"channel ids don't match. expected %s, got %s",
				type_to_string(tmpctx, struct channel_id, orig_id),
				type_to_string(tmpctx, struct channel_id, id_in));
}

static void set_reserve(struct tx_state *tx_state,
			struct amount_sat funding_total)
{
	struct amount_sat reserve;

	/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
	 *
	 * The channel reserve is fixed at 1% of the total channel balance
	 * rounded down (sum of `funding_satoshis` from `open_channel2`
	 * and `accept_channel2`) or the `dust_limit_satoshis`, whichever
	 * is greater.
	 */
	reserve = amount_sat_div(funding_total, 100);

	if (amount_sat_greater(tx_state->remoteconf.dust_limit, reserve))
		tx_state->remoteconf.channel_reserve = tx_state->remoteconf.dust_limit;
	else
		tx_state->remoteconf.channel_reserve = reserve;

	if (amount_sat_greater(tx_state->localconf.dust_limit, reserve))
		tx_state->localconf.channel_reserve = tx_state->localconf.dust_limit;
	else
		tx_state->localconf.channel_reserve = reserve;
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
	u64 serial_id;
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
			    struct tx_state *tx_state,
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
				    tx_state->accepter_funding,
				    tx_state->opener_funding)) {
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
			return tal_fmt(tmpctx, "total desired funding %s != "
				       "funding output %s",
				       type_to_string(tmpctx,
						      struct amount_sat,
						      &total_funding),
				       type_to_string(tmpctx,
						      struct amount_sat,
						      &output_val));
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
				tx_state->remoteconf.dust_limit) ||
		    !amount_sat_greater(output_val,
				tx_state->localconf.dust_limit)) {
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
	initiator_outs = tx_state->opener_funding;
	accepter_outs = tx_state->accepter_funding;
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
				tx_state->remoteconf.dust_limit) ||
		    !amount_sat_greater(amt,
				tx_state->localconf.dust_limit)) {
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
		return tal_fmt(ctx, "accepter fee not covered"
			       " (need %s > have %s)",
			       type_to_string(ctx,
					      struct amount_sat,
					      &accepter_fee),
			       type_to_string(ctx,
					      struct amount_sat,
					      &accepter_diff));
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
			take(towire_dualopend_dev_memleak_reply(NULL,
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

static u8 *psbt_to_tx_sigs_msg(const tal_t *ctx,
			       struct state *state,
			       const struct wally_psbt *psbt)
{
	const struct witness_stack **ws =
		psbt_to_witness_stacks(tmpctx, psbt,
				       state->our_role);

	return towire_tx_signatures(ctx, &state->channel_id,
				    &state->tx_state->funding_txid,
				    ws);
}

static void handle_tx_sigs(struct state *state, const u8 *msg)
{
	struct channel_id cid;
	struct bitcoin_txid txid;
	const struct witness_stack **ws;
	size_t j = 0;
	struct tx_state *tx_state = state->tx_state;
	enum tx_role their_role = state->our_role == TX_INITIATOR ?
		TX_ACCEPTER : TX_INITIATOR;

	if (!fromwire_tx_signatures(tmpctx, msg, &cid, &txid,
				    cast_const3(
					 struct witness_stack ***,
					 &ws)))
		peer_failed_warn(state->pps, &state->channel_id,
				 "Bad tx_signatures %s",
				 tal_hex(msg, msg));

	/* Maybe they didn't get our funding_locked message ? */
	if (state->funding_locked[LOCAL] && !state->reconnected) {
		status_broken("Got WIRE_TX_SIGNATURES after funding locked "
			       "for channel %s, ignoring: %s",
			       type_to_string(tmpctx, struct channel_id,
					      &state->channel_id),
			       tal_hex(tmpctx, msg));
		return;
	}

	/* On reconnect, we expect them to resend tx_sigs if they haven't
	 * gotten our funding_locked yet */
	if (state->funding_locked[REMOTE] && !state->reconnected)
		peer_failed_warn(state->pps, &state->channel_id,
				 "tx_signatures sent after funding_locked %s",
				 tal_hex(msg, msg));

	if (tx_state->remote_funding_sigs_rcvd) {
		status_info("Got duplicate WIRE_TX_SIGNATURES, "
			    "already have their sigs. Ignoring");
		return;
	}

	/* We put the PSBT + sigs all together */
	for (size_t i = 0; i < tx_state->psbt->num_inputs; i++) {
		struct wally_psbt_input *in =
			&tx_state->psbt->inputs[i];
		u64 in_serial;
		const struct witness_element **elem;

		if (!psbt_get_serial_id(&in->unknowns, &in_serial)) {
			status_broken("PSBT input %zu missing serial_id %s",
				      i, type_to_string(tmpctx,
							struct wally_psbt,
							tx_state->psbt));
			return;
		}
		if (in_serial % 2 != their_role)
			continue;

		if (j == tal_count(ws))
			peer_failed_warn(state->pps,
					 &state->channel_id,
					 "Mismatch witness stack count %s",
					 tal_hex(msg, msg));

		elem = cast_const2(const struct witness_element **,
				   ws[j++]->witness_element);
		psbt_finalize_input(tx_state->psbt, in, elem);
	}

	tx_state->remote_funding_sigs_rcvd = true;
	/* Send to the controller, who will broadcast the funding_tx
	 * as soon as we've got our sigs */
	wire_sync_write(REQ_FD,
			take(towire_dualopend_funding_sigs(NULL, tx_state->psbt)));
}

static void handle_send_tx_sigs(struct state *state, const u8 *msg)
{
	struct wally_psbt *psbt;
	struct bitcoin_txid txid;
	struct tx_state *tx_state = state->tx_state;

	if (!fromwire_dualopend_send_tx_sigs(tmpctx, msg, &psbt))
		master_badmsg(WIRE_DUALOPEND_SEND_TX_SIGS, msg);

	/* Check that we've got the same / correct PSBT */
	psbt_txid(NULL, psbt, &txid, NULL);
	if (!bitcoin_txid_eq(&txid, &tx_state->funding_txid))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "TXID for passed in PSBT does not match"
			      " funding txid for channel. Expected %s, "
			      "received %s",
			      type_to_string(tmpctx, struct bitcoin_txid,
					     &tx_state->funding_txid),
			      type_to_string(tmpctx, struct bitcoin_txid,
					     &txid));

	tal_wally_start();
	if (wally_psbt_combine(tx_state->psbt, psbt) != WALLY_OK) {
		tal_wally_end(tal_free(tx_state->psbt));
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable to combine PSBTs. received %s\n"
			      "local %s",
			      type_to_string(tmpctx, struct wally_psbt,
					     psbt),
			      type_to_string(tmpctx, struct wally_psbt,
					     tx_state->psbt));
	}
	tal_wally_end(tx_state->psbt);

	/*  Send our sigs to peer */
	msg = psbt_to_tx_sigs_msg(tmpctx, state, tx_state->psbt);
	sync_crypto_write(state->pps, take(msg));

	/* Notify lightningd that we've sent sigs */
	wire_sync_write(REQ_FD, take(towire_dualopend_tx_sigs_sent(NULL)));
}

static struct wally_psbt *
fetch_psbt_changes(struct state *state,
		   struct tx_state *tx_state,
		   const struct wally_psbt *psbt)
{
	u8 *msg;
	char *err;
	struct wally_psbt *updated_psbt;

	/* Go ask lightningd what other changes we've got */
	msg = towire_dualopend_psbt_changed(NULL, &state->channel_id,
					    tx_state->funding_serial,
					    psbt);

	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	if (fromwire_dualopend_fail(msg, msg, &err)) {
		open_error(state, "%s", err);
	} else if (fromwire_dualopend_psbt_updated(state, msg, &updated_psbt)) {
		return updated_psbt;
#if DEVELOPER
	} else if (fromwire_dualopend_dev_memleak(msg)) {
		handle_dev_memleak(state, msg);
#endif /* DEVELOPER */
	} else
		master_badmsg(fromwire_peektype(msg), msg);

	return NULL;
}

static bool send_next(struct state *state,
		      struct tx_state *tx_state,
		      struct wally_psbt **psbt)
{
	u8 *msg;
	bool finished = false;
	struct wally_psbt *updated_psbt;
	struct psbt_changeset *cs = tx_state->changeset;

	/* First we check our cached changes */
	msg = psbt_changeset_get_next(tmpctx, &state->channel_id, cs);
	if (msg)
		goto sendmsg;

	/* If we don't have any changes cached, go ask Alice for
	 * what changes they've got for us */
	updated_psbt = fetch_psbt_changes(state, tx_state, *psbt);

	/* We should always get a updated psbt back */
	if (!updated_psbt)
		peer_failed_err(state->pps, &state->channel_id,
				"Unable to determine next tx update");

	tx_state->changeset = tal_free(tx_state->changeset);
	tx_state->changeset = psbt_get_changeset(tx_state, *psbt, updated_psbt);

	/* We want this old psbt to be cleaned up when the changeset is freed */
	tal_steal(tx_state->changeset, *psbt);
	*psbt = tal_steal(tx_state, updated_psbt);
	msg = psbt_changeset_get_next(tmpctx, &state->channel_id,
				      tx_state->changeset);
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

static void init_changeset(struct tx_state *tx_state, struct wally_psbt *psbt)
{
	/* We need an empty to compare to */
	struct wally_psbt *empty_psbt = create_psbt(tmpctx, 0, 0, 0);

	tx_state->changeset = psbt_get_changeset(tx_state, empty_psbt, psbt);
}

/*~ Handle random messages we might get during opening negotiation, (eg. gossip)
 * returning the first non-handled one, or NULL if we aborted negotiation. */
static u8 *opening_negotiate_msg(const tal_t *ctx, struct state *state)
{
	/* This is an event loop of its own.  That's generally considered poor
	 * form, but we use it in a very limited way. */
	for (;;) {
		u8 *msg;
		bool from_gossipd;
		char *err;
		bool warning;
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
				  &err, &warning)) {
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
			negotiation_aborted(state,
					    tal_fmt(tmpctx, "They sent %s",
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
			       struct tx_state *tx_state,
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
		u64 serial_id;

		/* Reset their_complete to false every round,
		 * they have to re-affirm every time  */
		they_complete = false;

		msg = opening_negotiate_msg(tmpctx, state);
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
				peer_failed_warn(state->pps, &state->channel_id,
						 "Parsing tx_add_input %s",
						 tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);

			/*
			 * BOLT-544bda7144d91b3f51856189b8932610649f9e93 #2:
			 * The receiving node:
			 * - MUST fail the transaction collaboration if:
			 *   - it receives more than 2^12 `tx_add_input`
			 *   messages */
			if (++tx_state->tx_msg_count[TX_ADD_INPUT] > MAX_TX_MSG_RCVD)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Too many `tx_add_input`s"
						 " received");
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
				peer_failed_warn(state->pps, &state->channel_id,
						 "Invalid serial_id rcvd. %"PRIu64,
						 serial_id);
			/*
			 * BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2:
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *  - it recieves a duplicate `serial_id`
			 */
			if (psbt_find_serial_input(psbt, serial_id) != -1)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Duplicate serial_id rcvd."
						 " %"PRIu64, serial_id);

			/* Convert tx_bytes to a tx! */
			len = tal_bytelen(tx_bytes);
			tx = pull_bitcoin_tx(state, &tx_bytes, &len);
			if (!tx || len != 0)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Invalid tx sent.");

			if (outnum >= tx->wtx->num_outputs)
				peer_failed_warn(state->pps, &state->channel_id,
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
				peer_failed_warn(state->pps, &state->channel_id,
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
				peer_failed_warn(state->pps,
						 &state->channel_id,
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
				peer_failed_warn(state->pps, &state->channel_id,
						 "Unable to add input");

			tal_wally_start();
			wally_psbt_input_set_utxo(in, tx->wtx);
			tal_wally_end(psbt);

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
				peer_failed_warn(state->pps, &state->channel_id,
						 "Parsing tx_remove_input %s",
						 tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);

			/*
			 * BOLT-544bda7144d91b3f51856189b8932610649f9e93 #2:
			 * The receiving node:
			 * - MUST fail the transaction collaboration if:
			 *   - it receives more than 2^12 `tx_rm_input`
			 *   messages */
			if (++tx_state->tx_msg_count[TX_RM_INPUT] > MAX_TX_MSG_RCVD)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Too many `tx_rm_input`s"
						 " received");

			/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
			 * The sending node:
			 *   - MUST NOT send a `tx_remove_input` for an
			 *     input which is not theirs */
			if (serial_id % 2 == our_role)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Invalid serial_id rcvd. %"PRIu64,
						 serial_id);

			input_index = psbt_find_serial_input(psbt, serial_id);
			if (input_index == -1)
				peer_failed_err(state->pps, &state->channel_id,
						"No input added with serial_id"
						" %"PRIu64, serial_id);

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
				peer_failed_warn(state->pps,
						 &state->channel_id,
						 "Parsing tx_add_output %s",
						 tal_hex(tmpctx, msg));
			check_channel_id(state, &cid, &state->channel_id);

			/*
			 * BOLT-544bda7144d91b3f51856189b8932610649f9e93 #2:
			 * The receiving node:
			 * - MUST fail the transaction collaboration if:
			 *   - it receives more than 2^12 `tx_add_output`
			 *   messages */
			if (++tx_state->tx_msg_count[TX_ADD_OUTPUT] > MAX_TX_MSG_RCVD)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Too many `tx_add_output`s"
						 " received");

			/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
			 * The receiving node:
			 *  ...
			 * - MUST fail the transaction collaboration if:
			 *   ...
			 *   - it receives a `serial_id` from the peer with the
			 *      incorrect parity */
			if (serial_id % 2 == our_role)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Invalid serial_id rcvd. %"PRIu64,
						 serial_id);

			if (psbt_find_serial_output(psbt, serial_id) != -1)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Duplicate serial_id rcvd."
						 " %"PRIu64, serial_id);
			amt = amount_sat(value);
			out = psbt_append_output(psbt, scriptpubkey, amt);
			psbt_output_set_serial_id(psbt, out, serial_id);
			break;
		}
		case WIRE_TX_REMOVE_OUTPUT: {
			int output_index;

			if (!fromwire_tx_remove_output(msg, &cid, &serial_id))
				peer_failed_warn(state->pps, &state->channel_id,
						 "Parsing tx_remove_output %s",
						 tal_hex(tmpctx, msg));

			check_channel_id(state, &cid, &state->channel_id);

			/*
			 * BOLT-544bda7144d91b3f51856189b8932610649f9e93 #2:
			 * The receiving node:
			 * - MUST fail the transaction collaboration if:
			 *   - it receives more than 2^12 `tx_rm_output`
			 *   messages */
			if (++tx_state->tx_msg_count[TX_RM_OUTPUT] > MAX_TX_MSG_RCVD)
				peer_failed_warn(state->pps, &state->channel_id,
						 "Too many `tx_rm_output`s"
						 " received");

			/* BOLT-fe0351ca2cea3105c4f2eb18c571afca9d21c85b #2
			 * The sending node:
			 *   - MUST NOT send a `tx_remove_ouput` for an
			 *     input which is not theirs */
			if (serial_id % 2 == our_role)
				peer_failed_warn(state->pps,
						 &state->channel_id,
						 "Invalid serial_id rcvd."
						 " %"PRIu64, serial_id);

			output_index = psbt_find_serial_output(psbt, serial_id);
			if (output_index == -1)
				peer_failed_warn(state->pps,
						 &state->channel_id,
						 "No output added with serial_id"
						 " %"PRIu64, serial_id);
			psbt_rm_output(psbt, output_index);
			break;
		}
		case WIRE_TX_COMPLETE:
			if (!fromwire_tx_complete(msg, &cid))
				peer_failed_warn(state->pps,
						 &state->channel_id,
						 "Parsing tx_complete %s",
						 tal_hex(tmpctx, msg));
			check_channel_id(state, &cid, &state->channel_id);
			they_complete = true;
			break;
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_WARNING:
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
		case WIRE_ACK_RBF:
		case WIRE_FAIL_RBF:
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
			peer_failed_warn(state->pps, &state->channel_id,
					 "Unexpected wire message %s",
					 tal_hex(tmpctx, msg));
			return false;
		}

		if (!(we_complete && they_complete))
			we_complete = !send_next(state, tx_state, &psbt);
	}

	/* Sort psbt! */
	psbt_sort_by_serial_id(psbt);

	/* Return the 'finished' psbt */
	*orig_psbt = psbt;
	return true;
}

static void accepter_start(struct state *state, const u8 *oc2_msg)
{
	struct bitcoin_blkid chain_hash;
	struct tlv_opening_tlvs *open_tlv;
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
	u32 feerate_min, feerate_max, feerate_best;
	struct tx_state *tx_state = state->tx_state;

	state->our_role = TX_ACCEPTER;
	open_tlv = tlv_opening_tlvs_new(tmpctx);

	if (!fromwire_open_channel2(oc2_msg, &chain_hash,
				    &state->channel_id,
				    &state->opening_podle_h2,
				    &feerate_max,
				    &feerate_min,
				    &feerate_best,
				    &tx_state->opener_funding,
				    &tx_state->remoteconf.dust_limit,
				    &tx_state->remoteconf.max_htlc_value_in_flight,
				    &tx_state->remoteconf.htlc_minimum,
				    &state->feerate_per_kw_commitment,
				    &tx_state->remoteconf.to_self_delay,
				    &tx_state->remoteconf.max_accepted_htlcs,
				    &tx_state->tx_locktime,
				    &state->their_funding_pubkey,
				    &state->their_points.revocation,
				    &state->their_points.payment,
				    &state->their_points.delayed_payment,
				    &state->their_points.htlc,
				    &state->first_per_commitment_point[REMOTE],
				    &state->channel_flags,
				    open_tlv))
		peer_failed_err(state->pps, &state->channel_id,
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
		negotiation_failed(state, "Unknown chain-hash %s",
				   type_to_string(tmpctx,
						  struct bitcoin_blkid,
						  &chain_hash));
		return;
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
	    && amount_sat_greater(tx_state->opener_funding,
				  chainparams->max_funding)) {
		negotiation_failed(state,
				   "opener's funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &tx_state->opener_funding));
		return;
	}

	/* We can figure out the channel id now */
	derive_channel_id_v2(&cid,
			     &state->our_points.revocation,
			     &state->their_points.revocation);

	/* FIXME: pass the podle back also */
	msg = towire_dualopend_got_offer(NULL,
					 &cid,
					 tx_state->opener_funding,
					 tx_state->remoteconf.dust_limit,
					 tx_state->remoteconf.max_htlc_value_in_flight,
					 tx_state->remoteconf.htlc_minimum,
					 feerate_max,
					 feerate_min,
					 feerate_best,
					 state->feerate_per_kw_commitment,
					 tx_state->remoteconf.to_self_delay,
					 tx_state->remoteconf.max_accepted_htlcs,
					 state->channel_flags,
					 tx_state->tx_locktime,
					 state->upfront_shutdown_script[REMOTE]);

	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	if ((msg_type = fromwire_peektype(msg)) == WIRE_DUALOPEND_FAIL) {
		if (!fromwire_dualopend_fail(msg, msg, &err_reason))
			master_badmsg(msg_type, msg);

		open_error(state, "%s", err_reason);
		return;
	}

	if (!fromwire_dualopend_got_offer_reply(state, msg,
						&tx_state->accepter_funding,
						&tx_state->feerate_per_kw_funding,
						&tx_state->psbt,
						&state->upfront_shutdown_script[LOCAL]))
		master_badmsg(WIRE_DUALOPEND_GOT_OFFER_REPLY, msg);

	/* Set the state's feerate per kw funding, also. This is
	 * the original feerate we'll base any increases off of. */
	state->feerate_per_kw_funding = tx_state->feerate_per_kw_funding;

	/* Set the channel id now */
	state->channel_id = cid;

	if (!tx_state->psbt)
		tx_state->psbt = create_psbt(tx_state, 0, 0,
					     tx_state->tx_locktime);

	/* Check that total funding doesn't overflow */
	if (!amount_sat_add(&total, tx_state->opener_funding,
			    tx_state->accepter_funding))
		peer_failed_err(state->pps, &state->channel_id,
				"Amount overflow. Local sats %s. "
				"Remote sats %s",
				type_to_string(tmpctx, struct amount_sat,
					       &tx_state->accepter_funding),
				type_to_string(tmpctx, struct amount_sat,
					       &tx_state->opener_funding));

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
		negotiation_failed(state, "total funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &total));
		return;
	}

	/* Add all of our inputs/outputs to the changeset */
	init_changeset(tx_state, tx_state->psbt);

	/* Now that we know the total of the channel, we can set the reserve */
	set_reserve(tx_state, total);

	if (!check_config_bounds(tmpctx, total,
				 state->feerate_per_kw_commitment,
				 state->max_to_self_delay,
				 state->min_effective_htlc_capacity,
				 &tx_state->remoteconf,
				 &tx_state->localconf,
				 false,
				 true, /* v2 means we use anchor outputs */
				 &err_reason)) {
		negotiation_failed(state, "%s", err_reason);
		return;
	}

	/* If we have an upfront shutdown script, send it to our peer */
	struct tlv_accept_tlvs *a_tlv = tlv_accept_tlvs_new(state);
	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL]
			= no_upfront_shutdown_script(state,
						     state->our_features,
						     state->their_features);

	if (tal_bytelen(state->upfront_shutdown_script[LOCAL])) {
		a_tlv->option_upfront_shutdown_script
			= tal(a_tlv, struct tlv_accept_tlvs_option_upfront_shutdown_script);
		a_tlv->option_upfront_shutdown_script->shutdown_scriptpubkey
			= tal_dup_arr(a_tlv, u8,
				      state->upfront_shutdown_script[LOCAL],
				      tal_count(state->upfront_shutdown_script[LOCAL]),
				      0);
	}

	msg = towire_accept_channel2(tmpctx, &state->channel_id,
				     tx_state->accepter_funding,
				     tx_state->feerate_per_kw_funding,
				     tx_state->localconf.dust_limit,
				     tx_state->localconf.max_htlc_value_in_flight,
				     tx_state->localconf.htlc_minimum,
				     state->minimum_depth,
				     tx_state->localconf.to_self_delay,
				     tx_state->localconf.max_accepted_htlcs,
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
	tx_state->funding_serial = 1;
	/* Figure out what the funding transaction looks like! */
	if (!run_tx_interactive(state, tx_state, &tx_state->psbt, TX_ACCEPTER))
		return;

	/* Find the funding transaction txid */
	psbt_txid(NULL, tx_state->psbt, &tx_state->funding_txid, NULL);

	wscript = bitcoin_redeem_2of2(state,
				      &state->our_funding_pubkey,
				      &state->their_funding_pubkey);

	/* Figure out the txout */
	if (!find_txout(tx_state->psbt,
			scriptpubkey_p2wsh(tmpctx, wscript),
			&tx_state->funding_txout))
		peer_failed_err(state->pps, &state->channel_id,
				"Expected output %s not found on funding tx %s",
				tal_hex(tmpctx, scriptpubkey_p2wsh(tmpctx, wscript)),
				type_to_string(tmpctx, struct wally_psbt,
					       tx_state->psbt));

	/* Check tx funds are sane */
	err_reason = check_balances(tmpctx, state, tx_state,
				    tx_state->psbt,
				    tx_state->feerate_per_kw_funding);
	if (err_reason)
		negotiation_failed(state, "Insufficiently funded funding "
				   "tx, %s. %s",
				   err_reason,
				   type_to_string(tmpctx,
						  struct wally_psbt,
						  tx_state->psbt));

	/* Wait for the peer to send us our commitment tx signature */
	msg = opening_negotiate_msg(tmpctx, state);
	if (!msg)
		return;

	remote_sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_commitment_signed(tmpctx, msg, &cid,
					&remote_sig.s,
					&htlc_sigs))
		peer_failed_err(state->pps, &state->channel_id,
				"Parsing commitment signed %s",
				tal_hex(tmpctx, msg));

	check_channel_id(state, &cid, &state->channel_id);

	if (htlc_sigs != NULL)
		peer_failed_err(state->pps, &state->channel_id,
				"Must not send HTLCs with first"
				" commitment. %s",
				tal_hex(tmpctx, msg));

	if (!amount_sat_to_msat(&our_msats, tx_state->accepter_funding))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow converting accepter_funding "
			      "to msats");

	state->channel = new_initial_channel(state,
					     &state->channel_id,
					     &tx_state->funding_txid,
					     tx_state->funding_txout,
					     state->minimum_depth,
					     total,
					     our_msats,
					     take(new_fee_states(
							     NULL, REMOTE,
							     &state->feerate_per_kw_commitment)),
					     &tx_state->localconf,
					     &tx_state->remoteconf,
					     &state->our_points,
					     &state->their_points,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     true, true,
					     REMOTE);

	local_commit = initial_channel_tx(state, &wscript, state->channel,
					  &state->first_per_commitment_point[LOCAL],
					  LOCAL, NULL, &err_reason);

	/* This shouldn't happen either, AFAICT. */
	if (!local_commit) {
		negotiation_failed(state,
				   "Could not meet our fees and reserve: %s",
				   err_reason);
		return;
	}

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect:
	 *     - MUST fail the channel.
	 */
	if (!check_tx_sig(local_commit, 0, NULL, wscript,
			  &state->their_funding_pubkey, &remote_sig)) {
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
		peer_failed_err(state->pps, &state->channel_id,
				"Bad signature %s on tx %s using key %s"
				" (funding txid %s, psbt %s)",
				type_to_string(tmpctx, struct bitcoin_signature,
					       &remote_sig),
				type_to_string(tmpctx, struct bitcoin_tx,
					       local_commit),
				type_to_string(tmpctx, struct pubkey,
					       &state->their_funding_pubkey),
				/* This is the first place we'd discover
				 * the funding tx doesn't match up */
				type_to_string(tmpctx, struct bitcoin_txid,
					       &tx_state->funding_txid),
				type_to_string(tmpctx, struct wally_psbt,
					       tx_state->psbt));
	}

	/* Create commitment tx signatures for remote */
	remote_commit = initial_channel_tx(state, &wscript, state->channel,
					   &state->first_per_commitment_point[REMOTE],
					   REMOTE, direct_outputs, &err_reason);

	if (!remote_commit) {
		negotiation_failed(state, "Could not meet their"
				   " fees and reserve: %s",
				   err_reason);
		return;
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
	if (direct_outputs[LOCAL])
		pbase = penalty_base_new(tmpctx, 0, remote_commit,
					 direct_outputs[LOCAL]);
	else
		pbase = NULL;

	/* Send the commitment_signed controller; will save to db,
	 * then wait to get our sigs back */
	msg = towire_dualopend_commit_rcvd(state,
					   &tx_state->remoteconf,
					   local_commit,
					   pbase,
					   &remote_sig,
					   tx_state->psbt,
					   &state->channel_id,
					   &state->their_points.revocation,
					   &state->their_points.payment,
					   &state->their_points.htlc,
					   &state->their_points.delayed_payment,
					   &state->first_per_commitment_point[REMOTE],
					   &state->their_funding_pubkey,
					   &tx_state->funding_txid,
					   tx_state->funding_txout,
					   total,
					   tx_state->accepter_funding,
					   state->channel_flags,
					   state->feerate_per_kw_commitment,
					   tx_state->localconf.channel_reserve,
					   state->upfront_shutdown_script[LOCAL],
					   state->upfront_shutdown_script[REMOTE]);
	/* Normally we would end dualopend here (and in fact this
	 * is where openingd ends). However, now we wait for both our peer
	 * to send us the tx sigs *and* for master to send us the tx sigs. */
	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	if (fromwire_peektype(msg) != WIRE_DUALOPEND_SEND_TX_SIGS)
		master_badmsg(WIRE_DUALOPEND_SEND_TX_SIGS, msg);

	/* Send our commitment sigs over now */
	sync_crypto_write(state->pps,
			  take(towire_commitment_signed(NULL,
							&state->channel_id,
							&local_sig.s, NULL)));

	/* Finally, send our funding tx sigs */
	handle_send_tx_sigs(state, msg);
}

static void opener_start(struct state *state, u8 *msg)
{
	struct tlv_opening_tlvs *open_tlv;
	struct tlv_accept_tlvs *a_tlv;
	struct channel_id cid;
	char *err_reason;
	struct amount_sat total;
	struct amount_msat our_msats;
	struct wally_psbt_output *funding_out;
	struct sha256 podle;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
	struct penalty_base *pbase;
	const u8 *wscript;
	struct bitcoin_tx *remote_commit, *local_commit;
	struct bitcoin_signature remote_sig, local_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
	u32 feerate_min, feerate_max, feerate_best;
	struct tx_state *tx_state = state->tx_state;

	if (!fromwire_dualopend_opener_init(state, msg,
					    &tx_state->psbt,
					    &tx_state->opener_funding,
					    &state->upfront_shutdown_script[LOCAL],
					    &state->feerate_per_kw_commitment,
					    &tx_state->feerate_per_kw_funding,
					    &state->channel_flags))
		master_badmsg(WIRE_DUALOPEND_OPENER_INIT, msg);

	state->our_role = TX_INITIATOR;
	tx_state->tx_locktime = tx_state->psbt->tx->locktime;
	open_tlv = tlv_opening_tlvs_new(tmpctx);

	/* Set the channel_id to a temporary id, we'll update
	 * this as soon as we hear back from accept, but if they
	 * send us an error in the meantime, we need to be able to
	 * understand it */
	temporary_channel_id(&state->channel_id);

	feerate_min = state->min_feerate;
	feerate_max = state->max_feerate;
	if (tx_state->feerate_per_kw_funding > state->max_feerate) {
		status_info("Selected funding feerate %d is greater than"
			    " current suggested max %d, adjusing max upwards"
			    " to match.",
			    tx_state->feerate_per_kw_funding,
			    state->max_feerate);

		feerate_max = tx_state->feerate_per_kw_funding;
	}
	if (tx_state->feerate_per_kw_funding < state->min_feerate) {
		status_info("Selected funding feerate %d is less than"
			    " current suggested min %d, adjusing min downwards"
			    " to match.",
			    tx_state->feerate_per_kw_funding,
			    state->min_feerate);

		feerate_min = tx_state->feerate_per_kw_funding;
	}
	feerate_best = tx_state->feerate_per_kw_funding;

	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL]
			= no_upfront_shutdown_script(state,
						     state->our_features,
						     state->their_features);

	if (tal_bytelen(state->upfront_shutdown_script[LOCAL])) {
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
				   &state->channel_id,
				   &podle, /* FIXME: podle H2! */
				   feerate_max,
				   feerate_min,
				   feerate_best,
				   tx_state->opener_funding,
				   tx_state->localconf.dust_limit,
				   tx_state->localconf.max_htlc_value_in_flight,
				   tx_state->localconf.htlc_minimum,
				   state->feerate_per_kw_commitment,
				   tx_state->localconf.to_self_delay,
				   tx_state->localconf.max_accepted_htlcs,
				   tx_state->tx_locktime,
				   &state->our_funding_pubkey,
				   &state->our_points.revocation,
				   &state->our_points.payment,
				   &state->our_points.delayed_payment,
				   &state->our_points.htlc,
				   &state->first_per_commitment_point[LOCAL],
				   state->channel_flags,
				   open_tlv);

	sync_crypto_write(state->pps, take(msg));

	/* This is usually a very transient state... */
	peer_billboard(false, "channel open: offered, waiting for"
		       " accept_channel2");

	/* ... since their reply should be immediate. */
	msg = opening_negotiate_msg(tmpctx, state);
	if (!msg)
		return;

	a_tlv = notleak(tlv_accept_tlvs_new(state));
	if (!fromwire_accept_channel2(msg, &cid,
				      &tx_state->accepter_funding,
				      &tx_state->feerate_per_kw_funding,
				      &tx_state->remoteconf.dust_limit,
				      &tx_state->remoteconf.max_htlc_value_in_flight,
				      &tx_state->remoteconf.htlc_minimum,
				      &state->minimum_depth,
				      &tx_state->remoteconf.to_self_delay,
				      &tx_state->remoteconf.max_accepted_htlcs,
				      &state->their_funding_pubkey,
				      &state->their_points.revocation,
				      &state->their_points.payment,
				      &state->their_points.delayed_payment,
				      &state->their_points.htlc,
				      &state->first_per_commitment_point[REMOTE],
				      a_tlv))
		peer_failed_err(state->pps, &state->channel_id,
				"Parsing accept_channel2 %s", tal_hex(msg, msg));

	if (a_tlv->option_upfront_shutdown_script) {
		state->upfront_shutdown_script[REMOTE]
			= tal_steal(state,
				    a_tlv->option_upfront_shutdown_script
					 ->shutdown_scriptpubkey);
	} else
		state->upfront_shutdown_script[REMOTE] = NULL;

	/* Copy the feerate per kw into the state struct as well; this is
	 * the original feerate we'll use to base RBF upgrades on */
	state->feerate_per_kw_funding = tx_state->feerate_per_kw_funding;

	/* Now we can set the 'real channel id' */
	derive_channel_id_v2(&state->channel_id,
			     &state->our_points.revocation,
			     &state->their_points.revocation);

	if (!channel_id_eq(&cid, &state->channel_id))
		peer_failed_err(state->pps, &cid,
				"accept_channel2 ids don't match: "
				"expected %s, got %s",
				type_to_string(msg, struct channel_id,
					       &state->channel_id),
				type_to_string(msg, struct channel_id, &cid));

	/* BOLT-5fcbda56901af9e3b1d057cc41d0c5cfa60a2b94 #2:
	 * The receiving node:
	 * - if the `feerate_funding` is less than the `feerate_funding_min`
	 *   or above the `feerate_funding_max`
	 *   - MUST error.
	 */
	if (feerate_min > tx_state->feerate_per_kw_funding
	    || feerate_max < tx_state->feerate_per_kw_funding)
		peer_failed_warn(state->pps, &state->channel_id,
				 "Invalid feerate %d chosen. Valid min %d,"
				 " valid max %d", tx_state->feerate_per_kw_funding,
				 feerate_min, feerate_max);


	/* Check that total funding doesn't overflow */
	if (!amount_sat_add(&total, tx_state->opener_funding,
			    tx_state->accepter_funding))
		peer_failed_warn(state->pps, &state->channel_id,
				 "Amount overflow. Local sats %s. "
				 "Remote sats %s",
				 type_to_string(tmpctx, struct amount_sat,
						&tx_state->opener_funding),
				 type_to_string(tmpctx, struct amount_sat,
						&tx_state->accepter_funding));

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
		negotiation_failed(state,
				   "total funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &total));
		return;
	}

	/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
	 * The sending node:
	 *  - if is the `opener`:
	 *   - MUST send at least one `tx_add_output`,  the channel
	 *     funding output.
	 */
	/* If fails before returning from `send_next`, this will
	 * be marked as a memleak */
	wscript = notleak(bitcoin_redeem_2of2(state,
					      &state->our_funding_pubkey,
					      &state->their_funding_pubkey));
	funding_out = psbt_append_output(tx_state->psbt,
					 scriptpubkey_p2wsh(tmpctx,
							    wscript),
					 total);
	/* Add a serial_id for this output */
	tx_state->funding_serial = psbt_new_input_serial(tx_state->psbt,
							 TX_INITIATOR);
	psbt_output_set_serial_id(tx_state->psbt,
				  funding_out,
				  tx_state->funding_serial);

	/* Add all of our inputs/outputs to the changeset */
	init_changeset(tx_state, tx_state->psbt);

	/* Now that we know the total of the channel, we can
	 * set the reserve */
	set_reserve(tx_state, total);

	if (!check_config_bounds(tmpctx, total,
				 state->feerate_per_kw_commitment,
				 state->max_to_self_delay,
				 state->min_effective_htlc_capacity,
				 &tx_state->remoteconf,
				 &tx_state->localconf,
				 true, true, /* v2 means we use anchor outputs */
				 &err_reason)) {
		negotiation_failed(state, "%s", err_reason);
		return;
	}

	/* Send our first message, we're opener we initiate here */
	if (!send_next(state, tx_state, &tx_state->psbt))
		open_error(state, "Peer error, no updates to send");

	/* Figure out what the funding transaction looks like! */
	if (!run_tx_interactive(state, tx_state, &tx_state->psbt, TX_INITIATOR))
		return;

	psbt_txid(NULL, tx_state->psbt, &tx_state->funding_txid, NULL);

	/* Figure out the txout */
	if (!find_txout(tx_state->psbt, scriptpubkey_p2wsh(tmpctx, wscript),
			&tx_state->funding_txout))
		peer_failed_warn(state->pps, &state->channel_id,
				 "Expected output %s not found on funding tx %s",
				 tal_hex(tmpctx, scriptpubkey_p2wsh(tmpctx, wscript)),
				 type_to_string(tmpctx, struct wally_psbt,
						tx_state->psbt));

	/* Check tx funds are sane */
	err_reason = check_balances(tmpctx, state, tx_state,
				    tx_state->psbt,
				    tx_state->feerate_per_kw_funding);
	if (err_reason)
		negotiation_failed(state, "Insufficiently funded funding "
				   "tx, %s. %s",
				   err_reason,
				   type_to_string(tmpctx,
						  struct wally_psbt,
						  tx_state->psbt));

	if (!amount_sat_to_msat(&our_msats, tx_state->opener_funding))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Rounding error, can't convert opener_funding %s"
			      " to msats",
			      type_to_string(tmpctx, struct amount_sat,
					     &tx_state->opener_funding));

	/* Ok, we're mostly good now? Let's do this */
	state->channel = new_initial_channel(state,
					     &cid,
					     &tx_state->funding_txid,
					     tx_state->funding_txout,
					     state->minimum_depth,
					     total,
					     our_msats,
					     take(new_fee_states(NULL, LOCAL,
								 &state->feerate_per_kw_commitment)),
					     &tx_state->localconf,
					     &tx_state->remoteconf,
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
		negotiation_failed(state,
				   "Could not meet their fees and reserve: %s",
				   err_reason);
		return;
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
	msg = opening_negotiate_msg(tmpctx, state);
	if (!msg)
		return;

	remote_sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_commitment_signed(tmpctx, msg, &cid,
					&remote_sig.s,
					&htlc_sigs))
		peer_failed_warn(state->pps, &state->channel_id,
				 "Parsing commitment signed %s",
				 tal_hex(tmpctx, msg));

	if (htlc_sigs != NULL)
		peer_failed_warn(state->pps, &state->channel_id,
				 "Must not send HTLCs with first"
				 " commitment. %s",
				 tal_hex(tmpctx, msg));

	local_commit = initial_channel_tx(state, &wscript, state->channel,
					  &state->first_per_commitment_point[LOCAL],
					  LOCAL, NULL, &err_reason);


	/* This shouldn't happen either, AFAICT. */
	if (!local_commit) {
		negotiation_failed(state,
				   "Could not meet our fees and reserve: %s",
				   err_reason);
		return;
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
		peer_failed_err(state->pps, &state->channel_id,
				"Bad signature %s on tx %s using key %s "
				"(funding txid %s, psbt %s)",
				type_to_string(tmpctx, struct bitcoin_signature,
					       &remote_sig),
				type_to_string(tmpctx, struct bitcoin_tx,
					       local_commit),
				type_to_string(tmpctx, struct pubkey,
					       &state->their_funding_pubkey),
				/* This is the first place we'd discover the
				 * funding tx doesn't match up */
				type_to_string(tmpctx, struct bitcoin_txid,
					       &tx_state->funding_txid),
				type_to_string(tmpctx, struct wally_psbt,
					       tx_state->psbt));
	}

	if (direct_outputs[LOCAL])
		pbase = penalty_base_new(state, 0, remote_commit,
					 direct_outputs[LOCAL]);
	else
		pbase = NULL;

	peer_billboard(false, "channel open: commitment received, "
		       "sending to lightningd to save");

	msg = towire_dualopend_commit_rcvd(NULL,
					   &tx_state->remoteconf,
					   local_commit,
					   pbase,
					   &remote_sig,
					   tx_state->psbt,
					   &state->channel_id,
					   &state->their_points.revocation,
					   &state->their_points.payment,
					   &state->their_points.htlc,
					   &state->their_points.delayed_payment,
					   &state->first_per_commitment_point[REMOTE],
					   &state->their_funding_pubkey,
					   &tx_state->funding_txid,
					   tx_state->funding_txout,
					   total,
					   tx_state->opener_funding,
					   state->channel_flags,
					   state->feerate_per_kw_commitment,
					   tx_state->localconf.channel_reserve,
					   state->upfront_shutdown_script[LOCAL],
					   state->upfront_shutdown_script[REMOTE]);

	/* Normally we would end dualopend here (and in fact this
	 * is where openingd ends). However, now we wait for both our peer
	 * to send us the tx sigs *and* for master to send us the tx sigs. */
	wire_sync_write(REQ_FD, take(msg));
}

static bool update_feerate(struct tx_state *tx_state,
			   u32 feerate_funding,
			   u32 last_feerate,
			   u8 fee_step)
{
	u32 feerate = feerate_funding;

	/*
	 * BOLT-487dd4b46aad9b59f7f3480b7bdf15862b52d2f9b #2:
	 * Each `fee_step` adds 1/4 (rounded down) to the initial
	 * transaction feerate, i.e. if the initial `feerate_per_kw_funding`
	 * was 512 satoshis per kiloweight, `fee_step` 1 is
	 * 512 + 512 / 4 or 640 sat/kw, `fee_step` 2
	 * is 640 + 640 / 4 or 800 sat/kw.
	 */
	for (; fee_step > 0; fee_step--)
		feerate += feerate / 4;

	/* It's possible they sent us a 'bad' feerate step,
	 * i.e. less than the last one. */
	if (feerate < last_feerate)
		return false;

	tx_state->feerate_per_kw_funding = feerate;
	return true;
}

static void rbf_start(struct state *state, const u8 *rbf_msg)
{
	struct channel_id cid;
	struct tx_state *tx_state;
	char *err_reason;
	struct amount_sat total;
	enum dualopend_wire msg_type;
	u8 fee_step, *msg;

	/* We need a new tx_state! */
	tx_state = new_tx_state(state);

	if (!fromwire_init_rbf(rbf_msg, &cid,
			       &tx_state->opener_funding,
			       &tx_state->tx_locktime,
			       &fee_step))
		peer_failed_err(state->pps, &state->channel_id,
				"Parsing init_rbf %s",
				tal_hex(tmpctx, rbf_msg));

	/* Is this the correct channel? */
	check_channel_id(state, &cid, &state->channel_id);
	peer_billboard(false, "channel rbf: init received from peer");

	/* Have you sent us everything we need yet ? */
	if (!state->tx_state->remote_funding_sigs_rcvd)
		rbf_failed(state, "Last funding attempt not complete:"
			   " missing your funding tx_sigs");

	/* FIXME: should we check for currently in progress? */

	/* Copy over the channel config info -- everything except
	 * the reserve will be the same */
	tx_state->localconf = state->tx_state->localconf;
	tx_state->remoteconf = state->tx_state->remoteconf;

	if (!update_feerate(tx_state,
			    state->feerate_per_kw_funding,
			    state->tx_state->feerate_per_kw_funding,
			    fee_step)) {
		rbf_failed(state, "Fee step not greater than last."
			   " Fee step %d, last feerate %d",
			   fee_step,
			   state->tx_state->feerate_per_kw_funding);
		return;
	}

	/* We ask master if this is ok */
	msg = towire_dualopend_got_rbf_offer(NULL,
					     &state->channel_id,
					     tx_state->opener_funding,
					     tx_state->feerate_per_kw_funding,
					     tx_state->tx_locktime);

	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	if ((msg_type = fromwire_peektype(msg)) == WIRE_DUALOPEND_FAIL) {
		if (!fromwire_dualopend_fail(msg, msg, &err_reason))
			master_badmsg(msg_type, msg);
		rbf_failed(state, "%s", err_reason);
		tal_free(tx_state);
		return;
	}

	if (!fromwire_dualopend_got_rbf_offer_reply(state, msg,
						    &tx_state->accepter_funding,
						    &tx_state->psbt))
		master_badmsg(WIRE_DUALOPEND_GOT_RBF_OFFER_REPLY, msg);

	if (!tx_state->psbt)
		tx_state->psbt = create_psbt(tx_state, 0, 0,
					     tx_state->tx_locktime);

	/* Check that total funding doesn't overflow */
	if (!amount_sat_add(&total, tx_state->opener_funding,
			    tx_state->accepter_funding)) {
		rbf_failed(state, "Amount overflow. Local sats %s. "
			   "Remote sats %s",
			   type_to_string(tmpctx, struct amount_sat,
					  &tx_state->accepter_funding),
			   type_to_string(tmpctx, struct amount_sat,
					  &tx_state->opener_funding));
		tal_free(tx_state);
		return;
	}

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
		rbf_failed(state, "total funding_satoshis %s too large",
			   type_to_string(tmpctx, struct amount_sat, &total));
		tal_free(tx_state);
		return;
	}

	/* Add all of our inputs/outputs to the changeset */
	init_changeset(tx_state, tx_state->psbt);

	/* Now that we know the total of the channel, we can set the reserve */
	set_reserve(tx_state, total);

	if (!check_config_bounds(tmpctx, total,
				 state->feerate_per_kw_commitment,
				 state->max_to_self_delay,
				 state->min_effective_htlc_capacity,
				 &tx_state->remoteconf,
				 &tx_state->localconf,
				 false,
				 true, /* v2 means we use anchor outputs */
				 &err_reason)) {
		rbf_failed(state, "%s", err_reason);
		tal_free(tx_state);
		return;
	}

	msg = towire_ack_rbf(tmpctx, &state->channel_id,
			     state->our_role == TX_INITIATOR ?
				tx_state->opener_funding :
				tx_state->accepter_funding);
	sync_crypto_write(state->pps, msg);
	peer_billboard(false, "channel rbf: ack sent, waiting for reply");


	/* This is unused in this flow. We re-use
	 * the wire method between accepter + opener, so we set it
	 * to an invalid number, 1 (initiator sets; valid is even) */
	tx_state->funding_serial = 1;
	/* Now we figure out what the proposed new open transaction is */
	if (!run_tx_interactive(state, tx_state,
				&tx_state->psbt, TX_ACCEPTER))
		return;

	/* Find the funding transaction txid */
	psbt_txid(NULL, tx_state->psbt, &tx_state->funding_txid, NULL);

	// FIXME: same as accepter run now?
}

static u8 *handle_funding_locked(struct state *state, u8 *msg)
{
	struct channel_id cid;
	struct pubkey remote_per_commit;

	if (!fromwire_funding_locked(msg, &cid, &remote_per_commit))
		peer_failed_warn(state->pps, &state->channel_id,
				 "Bad funding_locked %s", tal_hex(msg, msg));

	if (!channel_id_eq(&cid, &state->channel_id))
		peer_failed_err(state->pps, &cid,
				"funding_locked ids don't match: "
				"expected %s, got %s",
				type_to_string(msg, struct channel_id,
					       &state->channel_id),
				type_to_string(msg, struct channel_id, &cid));

	/* If we haven't gotten their tx_sigs yet, this is a protocol error */
	if (!state->tx_state->remote_funding_sigs_rcvd) {
		peer_failed_warn(state->pps, &state->channel_id,
				 "funding_locked sent before tx_signatures %s",
				 tal_hex(msg, msg));
	}

	state->funding_locked[REMOTE] = true;
	billboard_update(state);

	/* We save when the peer locks, so we do the right
	 * thing on reconnects */
	msg = towire_dualopend_peer_locked(NULL, &remote_per_commit);
	wire_sync_write(REQ_FD, take(msg));

	if (state->funding_locked[LOCAL])
		return towire_dualopend_channel_locked(state, state->pps);

	return NULL;
}

static void hsm_per_commitment_point(u64 index, struct pubkey *point)
{
	struct secret *s;
	const u8 *msg;

	msg = towire_hsmd_get_per_commitment_point(NULL, index);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);

	if (!fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
							  point, &s))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad per_commitment_point reply %s",
			      tal_hex(tmpctx, msg));
}

static void send_funding_locked(struct state *state)
{
	u8 *msg;
	struct pubkey next_local_per_commit;

	/* Figure out the next local commit */
	hsm_per_commitment_point(1, &next_local_per_commit);

	msg = towire_funding_locked(NULL,
				    &state->channel_id,
				    &next_local_per_commit);
	sync_crypto_write(state->pps, take(msg));

	state->funding_locked[LOCAL] = true;
	billboard_update(state);
}

static u8 *handle_funding_depth(struct state *state, u8 *msg)
{
	u32 depth;

	if (!fromwire_dualopend_depth_reached(msg, &depth))
		master_badmsg(WIRE_DUALOPEND_DEPTH_REACHED, msg);

	/* Too late, shutting down already */
	if (state->shutdown_sent[LOCAL])
		return NULL;

	/* We check this before we arrive here, but for sanity */
	assert(state->minimum_depth <= depth);

	send_funding_locked(state);
	if (state->funding_locked[REMOTE])
		return towire_dualopend_channel_locked(state,
						       state->pps);

	return NULL;
}

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

/* Try to handle a custommsg Returns true if it was a custom message and has
 * been handled, false if the message was not handled.
 */
static bool dualopend_handle_custommsg(const u8 *msg)
{
#if DEVELOPER
	enum peer_wire type = fromwire_peektype(msg);
	if (type % 2 == 1 && !peer_wire_is_defined(type)) {
		/* The message is not part of the messages we know how to
		 * handle. Assuming this is a custommsg, we just forward it to the
		 * master. */
		wire_sync_write(REQ_FD, take(towire_custommsg_in(NULL, msg)));
		return true;
	} else {
		return false;
	}
#else
	return false;
#endif
}

/* BOLT #2:
 *
 * A receiving node:
 *  - if `option_static_remotekey` applies to the commitment transaction:
 *    - if `next_revocation_number` is greater than expected above, AND
 *    `your_last_per_commitment_secret` is correct for that
 *    `next_revocation_number` minus 1:
 *...
 *  - otherwise, if it supports `option_data_loss_protect`:
 *    - if `next_revocation_number` is greater than expected above,
 *      AND `your_last_per_commitment_secret` is correct for that
 *     `next_revocation_number` minus 1:
 */
static void
check_future_dataloss_fields(struct state *state,
			     u64 next_revocation_number,
			     const struct secret *last_local_per_commit_secret)
{
	const u8 *msg;
	bool correct;

	/* We're always at zero in dualopend */
	assert(next_revocation_number > 0);

	msg = towire_hsmd_check_future_secret(NULL,
					      next_revocation_number - 1,
					      last_local_per_commit_secret);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);

	if (!fromwire_hsmd_check_future_secret_reply(msg, &correct))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsm_check_future_secret_reply: %s",
			      tal_hex(tmpctx, msg));

	if (!correct)
		peer_failed_err(state->pps,
				&state->channel_id,
				"bad future last_local_per_commit_secret: %"PRIu64
				" vs %d",
				next_revocation_number, 0);

	/* Oh shit, they really are from the future! */
	peer_billboard(true, "They have future commitment number %"PRIu64
		       " vs our %d. We must wait for them to close!",
		       next_revocation_number, 0);


	/* BOLT #2:
	 * - MUST NOT broadcast its commitment transaction.
	 * - SHOULD fail the channel.
	 */
	wire_sync_write(REQ_FD,
			take(towire_dualopend_fail_fallen_behind(NULL)));

	/* We have to send them an error to trigger dropping to chain. */
	peer_failed_err(state->pps, &state->channel_id,
		    "Awaiting unilateral close");
}


static void do_reconnect_dance(struct state *state)
{
	u8 *msg;
	struct channel_id cid;
	/* Note: BOLT #2 uses these names! */
	u64 next_commitment_number, next_revocation_number;
	struct secret last_local_per_commit_secret,
		last_remote_per_commit_secret;
	struct pubkey remote_current_per_commit_point;
	struct tx_state *tx_state = state->tx_state;

	/* BOLT #2:
	 *     - if `next_revocation_number` equals 0:
	 *       - MUST set `your_last_per_commitment_secret` to all zeroes
	 */
	/* We always have no revocations in dualopend */
	memset(&last_remote_per_commit_secret, 0,
	       sizeof(last_remote_per_commit_secret));

	/* We always send reconnect/reestablish */
	msg = towire_channel_reestablish
		(NULL, &state->channel_id, 1, 0,
		 &last_remote_per_commit_secret,
		 &state->first_per_commitment_point[LOCAL]);
	sync_crypto_write(state->pps, take(msg));

	peer_billboard(false, "Sent reestablish, waiting for theirs");
	bool soft_error = state->funding_locked[REMOTE]
		|| state->funding_locked[LOCAL];

	/* Read until they say something interesting (don't forward
	 * gossip *to* them yet: we might try sending channel_update
	 * before we've reestablished channel). */
	do {
		clean_tmpctx();
		msg = sync_crypto_read(tmpctx, state->pps);
	} while (dualopend_handle_custommsg(msg)
		 || handle_peer_gossip_or_error(state->pps,
						&state->channel_id,
						soft_error, msg));

	if (!fromwire_channel_reestablish
			(msg, &cid,
			 &next_commitment_number,
			 &next_revocation_number,
			 &last_local_per_commit_secret,
			 &remote_current_per_commit_point))
		peer_failed_warn(state->pps, &state->channel_id,
				 "Bad reestablish msg: %s %s",
				 peer_wire_name(fromwire_peektype(msg)),
				 tal_hex(msg, msg));

	check_channel_id(state, &cid, &state->channel_id);

	status_debug("Got dualopend reestablish commit=%"PRIu64
		     " revoke=%"PRIu64,
		     next_commitment_number,
		     next_revocation_number);

	/* BOLT #2:
	 *    - if it has not sent `revoke_and_ack`, AND
	 *      `next_revocation_number` is not equal to 0:
	 *      - SHOULD fail the channel.
	 */
	/* It's possible that we've opened an outdated copy of the
	 * database, and the peer is very much ahead of us.
	 */
	if (next_revocation_number != 0) {
		/* Remote claims it's ahead of us: can it prove it?
		 * Does not return. */
		check_future_dataloss_fields(state,
					     next_revocation_number,
					     &last_local_per_commit_secret);
	}

	if (next_commitment_number != 1)
		peer_failed_err(state->pps, &state->channel_id,
				"bad reestablish commitment_number: %"PRIu64
				" vs %d",
				next_commitment_number, 1);

	/* It's possible we sent our sigs, but they didn't get them.
	 * Resend our signatures, just in case */
	if (psbt_side_finalized(tx_state->psbt, state->our_role)
	    && !state->funding_locked[REMOTE]) {
		msg = psbt_to_tx_sigs_msg(NULL, state, tx_state->psbt);
		sync_crypto_write(state->pps, take(msg));
	}

	if (state->funding_locked[LOCAL]) {
		status_debug("Retransmitting funding_locked for channel %s",
		             type_to_string(tmpctx,
					    struct channel_id,
					    &state->channel_id));
		send_funding_locked(state);
	}

	peer_billboard(true, "Reconnected, and reestablished.");
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
	case WIRE_DUALOPEND_DEV_MEMLEAK:
#if DEVELOPER
		handle_dev_memleak(state, msg);
#endif
		return NULL;
	case WIRE_DUALOPEND_OPENER_INIT:
		opener_start(state, msg);
		return NULL;
	case WIRE_DUALOPEND_SEND_TX_SIGS:
		handle_send_tx_sigs(state, msg);
		return NULL;
	case WIRE_DUALOPEND_DEPTH_REACHED:
		return handle_funding_depth(state, msg);
	case WIRE_DUALOPEND_SEND_SHUTDOWN:
		handle_our_shutdown(state, msg);
		return NULL;

	/* Handled inline */
	case WIRE_DUALOPEND_INIT:
	case WIRE_DUALOPEND_REINIT:
	case WIRE_DUALOPEND_DEV_MEMLEAK_REPLY:
	case WIRE_DUALOPEND_FAIL:
	case WIRE_DUALOPEND_PSBT_UPDATED:
	case WIRE_DUALOPEND_GOT_OFFER_REPLY:
	case WIRE_DUALOPEND_GOT_RBF_OFFER_REPLY:

	/* Messages we send */
	case WIRE_DUALOPEND_GOT_OFFER:
	case WIRE_DUALOPEND_GOT_RBF_OFFER:
	case WIRE_DUALOPEND_PSBT_CHANGED:
	case WIRE_DUALOPEND_COMMIT_RCVD:
	case WIRE_DUALOPEND_FUNDING_SIGS:
	case WIRE_DUALOPEND_TX_SIGS_SENT:
	case WIRE_DUALOPEND_PEER_LOCKED:
	case WIRE_DUALOPEND_CHANNEL_LOCKED:
	case WIRE_DUALOPEND_GOT_SHUTDOWN:
	case WIRE_DUALOPEND_SHUTDOWN_COMPLETE:
	case WIRE_DUALOPEND_FAIL_FALLEN_BEHIND:
	case WIRE_DUALOPEND_FAILED:
	case WIRE_DUALOPEND_RBF_FAILED:
		break;
	}

	/* Now handle common messages. */
	switch ((enum common_wire)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_OUT:
		dualopend_send_custommsg(state, msg);
#else
		return NULL;
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
 * handles a few messages, we use the standard form as principle of least
 * surprise. */
static u8 *handle_peer_in(struct state *state)
{
	u8 *msg = sync_crypto_read(tmpctx, state->pps);
	enum peer_wire t = fromwire_peektype(msg);
	struct channel_id channel_id;

	switch (t) {
	case WIRE_OPEN_CHANNEL2:
		if (state->channel) {
			status_broken("Unexpected message %s",
				      peer_wire_name(t));
			peer_failed_connection_lost();
		}
		accepter_start(state, msg);
		return NULL;
	case WIRE_TX_SIGNATURES:
		handle_tx_sigs(state, msg);
		return NULL;
	case WIRE_FUNDING_LOCKED:
		return handle_funding_locked(state, msg);
	case WIRE_SHUTDOWN:
		handle_peer_shutdown(state, msg);
		return NULL;
	case WIRE_INIT_RBF:
		rbf_start(state, msg);
		return NULL;
	/* Otherwise we fall through */
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
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
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_ACK_RBF:
	case WIRE_FAIL_RBF:
	case WIRE_BLACKLIST_PODLE:
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_WARNING:
	case WIRE_PING:
	case WIRE_PONG:
		break;
	}

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
			  take(towire_warningfmt(NULL,
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

static bool shutdown_complete(const struct state *state)
{
	return state->shutdown_sent[LOCAL]
		&& state->shutdown_sent[REMOTE];
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	struct pollfd pollfd[3];
	struct state *state = tal(NULL, struct state);
	struct secret *none;
	struct fee_states *fee_states;
	enum side opener;
	u8 *msg, *inner;
	struct amount_sat total_funding;
	struct amount_msat our_msat;

	subdaemon_setup(argc, argv);

	/* Init the holder for the funding transaction attempt */
	state->tx_state = new_tx_state(state);

	/*~ This makes status_failed, status_debug etc work synchronously by
	 * writing to REQ_FD */
	status_setup_sync(REQ_FD);

	/*~ The very first thing we read from lightningd is our init msg */
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (fromwire_dualopend_init(state, msg,
				    &chainparams,
				    &state->our_features,
				    &state->their_features,
				    &state->tx_state->localconf,
				    &state->max_to_self_delay,
				    &state->min_effective_htlc_capacity,
				    &state->pps,
				    &state->our_points,
				    &state->our_funding_pubkey,
				    &state->minimum_depth,
				    &state->min_feerate,
				    &state->max_feerate,
				    &inner)) {
		/*~ Initially we're not associated with a channel, but
		 * handle_peer_gossip_or_error compares this. */
		memset(&state->channel_id, 0, sizeof(state->channel_id));
		state->channel = NULL;
		state->tx_state->remote_funding_sigs_rcvd = false;

		/*~ We set these to NULL, meaning no requirements on shutdown */
		state->upfront_shutdown_script[LOCAL]
			= state->upfront_shutdown_script[REMOTE]
			= NULL;

		/*~ We're not locked or shutting down quite yet */
		state->funding_locked[LOCAL]
			= state->funding_locked[REMOTE]
			= false;
		state->shutdown_sent[LOCAL]
			= state->shutdown_sent[REMOTE]
			= false;

	} else if (fromwire_dualopend_reinit(state, msg,
					     &chainparams,
					     &state->our_features,
					     &state->their_features,
					     &state->tx_state->localconf,
					     &state->tx_state->remoteconf,
					     &state->channel_id,
					     &state->max_to_self_delay,
					     &state->min_effective_htlc_capacity,
					     &state->pps,
					     &state->our_points,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     &state->minimum_depth,
					     &state->min_feerate,
					     &state->max_feerate,
					     &state->tx_state->funding_txid,
					     &state->tx_state->funding_txout,
					     &total_funding,
					     &our_msat,
					     &state->their_points,
					     &state->first_per_commitment_point[REMOTE],
					     &state->tx_state->psbt,
					     &opener,
					     &state->funding_locked[LOCAL],
					     &state->funding_locked[REMOTE],
					     &state->shutdown_sent[LOCAL],
					     &state->shutdown_sent[REMOTE],
					     &state->upfront_shutdown_script[LOCAL],
					     &state->upfront_shutdown_script[REMOTE],
					     &state->tx_state->remote_funding_sigs_rcvd,
					     &fee_states,
					     &state->channel_flags,
					     &inner)) {

		/*~ We only reconnect on channels that the
		 * saved the the database (exchanged commitment sigs) */
		state->channel = new_initial_channel(state,
						     &state->channel_id,
						     &state->tx_state->funding_txid,
						     state->tx_state->funding_txout,
						     state->minimum_depth,
						     total_funding,
						     our_msat,
						     fee_states,
						     &state->tx_state->localconf,
						     &state->tx_state->remoteconf,
						     &state->our_points,
						     &state->their_points,
						     &state->our_funding_pubkey,
						     &state->their_funding_pubkey,
						     true, true, opener);

		if (opener == LOCAL)
			state->our_role = TX_INITIATOR;
		else
			state->our_role = TX_ACCEPTER;
	} else
		master_badmsg(fromwire_peektype(msg), msg);



	/* 3 == peer, 4 == gossipd, 5 = gossip_store, 6 = hsmd */
	per_peer_state_set_fds(state->pps, 3, 4, 5);

	/*~ If lightningd wanted us to send a msg, do so before we waste time
	 * doing work.  If it's a global error, we'll close immediately. */
	if (inner != NULL) {
		sync_crypto_write(state->pps, inner);
		fail_if_all_error(inner);
		tal_free(inner);
	}

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

	/* Do reconnect, if need be */
	if (state->channel) {
		do_reconnect_dance(state);
		state->reconnected = true;
	}

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

		/* If we've shutdown, we're done */
		if (shutdown_complete(state))
			msg = towire_dualopend_shutdown_complete(state,
								 state->pps);
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
