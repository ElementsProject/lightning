/* This is the lightningd handler for messages to/from various
 * dualopend subdaemons. It manages the callbacks and database
 * saves and funding tx watching for a channel open */

#include <bitcoin/psbt.h>
#include <ccan/ccan/take/take.h>
#include <ccan/short_types/short_types.h>
#include <common/channel_id.h>
#include <common/htlc.h>
#include <common/json_tok.h>
#include <common/psbt_open.h>
#include <lightningd/log.h>
#include <wire/gen_peer_wire.h>

#if EXPERIMENTAL_FEATURES
/* Channel we're still opening. */
struct precommit_channel {
	/* peer->c.precommit_channel == this */
	struct peer *peer;

	/* dualopend which is running now */
	struct subd *dualopend;

	/* Reserved dbid for if we become a real struct channel */
	u64 dbid;

	/* For logging */
	struct log *log;

	/* dualopend tells us stuff. */
	const char *transient_billboard;

	/* Our basepoints for the channel. */
	struct basepoints local_basepoints;

	/* Public key for funding tx. */
	struct pubkey local_funding_pubkey;

	/* These are *not* filled in by new_precommit_channel: */

	/* Minimum funding depth (if opener == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;
};

static const struct witness_stack **
psbt_to_witness_stacks(const tal_t *ctx, struct wally_psbt *psbt, enum side opener)
{
	struct witness_stack **stacks = tal_arr(ctx, struct witness_stack *, psbt->num_inputs);
	size_t num_inputs;
	u32 serial_id;

	/* Sort first so stacks are ordered correctly */
	psbt_sort_by_serial_id(psbt);

	j = 0;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (!psbt_get_serial_id(psbt->inputs[i].unknowns, &serial_id))
			fatal("dual funding PSBT must have serial_id for each "
			      "input, none found for input %zu", i);

		if (serial_id % 2 == opener) {
			struct wally_tx_witness_stack *wtx_s = psbt->inputs[i].witness;
			struct witness_stack *stack = tal(stacks, struct witness_stack);
			/* Convert the wally_tx_witness_stack to a witness_stack entry */
			stack->witness_element = tal_arr(stack, u8 *, wtx_s->num_items);
			for (size_t j = 0; j < wsx->num_items; j++)
				stack->witness_element->witness =
					tal_dup_arr(stack, u8,
						    wtx_s[j]->witness,
						    wtx_s[j]->len, 0);

			stacks[num_inputs++] = stack;
		}

	}

	return tal_resize(stacks, num_inputs);
}

static bool psbt_side_finalized(struct wally_psbt *psbt, enum side opener)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (!psbt_get_serial_id(psbt->inputs[i].unknowns, &serial_id))
			fatal("dual funding PSBT must have serial_id for each "
			      "input, none found for input %zu", i);
		/* It's our input if parity matches -- this shorthand
		 * works because LOCAL == 0. If the parity is even and
		 * we're the opener then it's ours; if the parity is odd
		 * and the REMOTE's the opener (opener == 1), then it's also
		 * ours. */
		if (serial_id % 2 == opener) {
			if (!psbt->inputs[i].witness ||
					psbt->inputs[i].witness->num_items == 0)
				return false;
		}
	}
	return true;
}


static void handle_signed_psbt(struct subd *dualopend,
			       struct wally_psbt *psbt,
			       struct commit_recvd *rcvd)
{
	const struct witness_stack *ws =
		psbt_to_witness_stacks(NULL, psbt, REMOTE);

	u8 **channeld_msgs = tal_arr(NULL, u8 *, 2);


	/* We've already confirmed that all of the supplied info is good,
	 * so now go ahead and create a tx_signatures msg.
	 * We'll pass the tx_sigs msg and the already-created
	 * commitment_signed tx to channeld, who will send
	 * both of them to the peer. */
	channeld_msgs[0] = tal_steal(channeld_msgs, rcvd->commitment_msg);
	channeld_msgs[1] = towire_tx_signatures(channeld_msgs,
						&channel->channel_id,
						&channel->funding_txid,
						ws);

	/* Watch for funding confirms */
	channel_watch_funding(dualopend->ld, rcvd->channel);

	funding_success(channel);
	peer_start_channeld(rcvd->channel, rcvd->pps, channeld_msgs, false);
}

/* ~Map of the Territory~
 *
 * openchannel hook
   - reserveinputs feerate [{"amt": amt, "script": ""}] excludecommon=true -> psbt
   -> psbt_set
 *
 * openchannel_changed hook
   - psbt --> most recent
   -> psbt_set (if same as orig) | complete flag
 *
 * openchannel_sign hook
  - signpsbt psbt -> partially_signed_psbt
  -> partially_signed_psbt
*/
struct openchannel2_payload {
	struct subd *dualopend;
	struct peer_id *peer_id;
	struct amount_sat their_funding;
	struct amount_sat dust_limit_satoshis;
	struct amount_msat max_htlc_value_in_flight_msat;
	struct amount_msat htlc_minimum_msat;
	u32 feerate_per_kw_funding;
	u32 feerate_per_kw;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
	u8 channel_flags;
	u16 locktime;
	u8 *shutdown_scriptpubkey;
	/* FIXME: include the podle? */
};

static void
openchannel2_hook_serialize(struct openchannel_payload *payload,
			    struct json_stream *stream)
{
	json_object_start(stream, "openchannel2");
	json_add_node_id(stream, "id", payload->peer_id);
	json_add_amount_sat_only(stream, "their_funding",
				 payload->their_funding);
	json_add_amount_sat_only(stream, "dust_limit_satoshis",
				 payload->dust_limit_satoshis);
	json_add_amount_msat_only(stream, "max_htlc_value_in_flight_msat",
				  payload->max_htlc_value_in_flight_msat);
	json_add_amount_msat_only(stream, "htlc_minimum_msat",
				  payload->htlc_minimum_msat);
	json_add_num(stream, "feerate_per_kw_funding",
		     payload->feerate_per_kw_funding);
	json_add_num(stream, "feerate_per_kw", payload->feerate_per_kw);
	json_add_num(stream, "to_self_delay", payload->to_self_delay);
	json_add_num(stream, "max_accepted_htlcs", payload->max_accepted_htlcs);
	json_add_num(stream, "channel_flags", payload->channel_flags);
	json_add_num(stream, "locktime", payload->locktime);
	if (tal_count(payload->shutdown_scriptpubkey) != 0)
		json_add_hex_talarr(stream, "shutdown_scriptpubkey",
				    payload->shutdown_scriptpubkey);
	/* FIXME: include the podle? */
	json_object_end(stream);
}

struct commit_recvd {
	struct channel *channel;
	struct per_peer_state *pps;
	u8 *commitment_msg;
	struct precommit_channel *pc;
};

struct openchannel2_psbt_payload {
	struct subd *dualopend;
	struct channel_id *cid;
	struct wally_psbt *psbt;
	struct commit_recvd *rcvd;
};

static void
openchannel2_changed_hook_serialize(struct openchannel2_psbt_payload *payload,
				    struct json_stream *stream)
{
	json_object_start(stream, "openchannel2_changed");
	json_add_psbt(stream, "psbt", payload->psbt);
	json_add_string(stream, "channel_id",
			type_to_stream(tmpctx, struct channel_id, payload->cid));
	json_object_end(stream);
}

static void
openchannel2_sign_hook_serialize(struct openchannel2_psbt_payload *payload,
				 struct json_stream *stream)
{
	json_object_start(stream, "openchannel2_sign");
	json_add_psbt(stream, "psbt", payload->psbt);
	json_add_string(stream, "channel_id",
			type_to_stream(tmpctx, struct channel_id, payload->cid));
	json_object_end(stream);
}

static const u8 *hook_extract_shutdown_script(struct subd* dualopend,
					      const char *buffer,
					      const jsmntok_t *toks)
{
	u8 *close_to_script;
	enum address_parse_result parse_res;

	if (!buffer)
		return NULL;

	const jsmntok_t *t = json_get_member(buffer, toks, "result");
	if (!t)
		fatal("Plugin must return a 'result' to %s"
		      "%.*s", hook_name, toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	if (!json_tok_streq(buffer, t, "continue")) {
		char *errmsg = "Client error. Unable to continue";
		subd_send_msg(dualopend,
			      take(towire_dual_open_fail(NULL, errmsg)));
		return NULL;
	}

	const jsmntok_t *close_to_tok = json_get_member(buffer, toks, "close_to");
	if (!close_to_tok)
		return NULL;

	parse_res = json_to_address_scriptpubkey(tmpctx, chainparams, buffer,
						 close_to_tok, &close_to_script);
	switch (parse_res) {
		case ADDRESS_PARSE_UNRECOGNIZED:
			fatal("Plugin returned an invalid response to the"
			      " openchannel2.close_to hook: %.*s",
			      t->end - t->start, buffer + t->start);
		case ADDRESS_PARSE_WRONG_NETWORK:
			fatal("Plugin returned invalid response to the"
			      " openchannel2.close_to hook: address %s is"
			      " not on network %s",
			      tal_hex(NULL, our_upfront_shutdown_script),
			      chainparams->network_name);
		case ADDRESS_PARSE_SUCCESS:
			return close_to_script;
	}

	return NULL;
}


static wally_pst *hook_extract_psbt(struct subd *dualopend,
				    const char *buffer,
				    const jsmntok_t *toks,
				    char *hook_name)
{
	struct wally_psbt *returned_psbt;

	/* You'd better return a PSBT for this hook */
	if (!buffer)
		fatal("Plugin must return a valid response to %s", hook_name);

	const jsmntok_t *t = json_get_member(buffer, toks, "result");
	if (!t)
		fatal("Plugin must return a 'result' to %s"
		      "%.*s", hook_name, toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	if (!json_tok_streq(buffer, t, "continue")) {
		char *errmsg = "Client error. Unable to continue";
		subd_send_msg(dualopend,
			      take(towire_dual_open_fail(NULL, errmsg)));
		return NULL;
	}

	const jsmntok_t *psbt_tok = json_get_member(buffer, toks, "psbt");
	if (!psbt_tok)
		fatal("Plugin must return a 'psbt' to a 'continue'd"
		      "%s %.*s", hook_name,
		      toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	if (!json_to_psbt(tmpctx, buffer, psbt_tok, returned_psbt))
		fatal("Plugin must return a valid 'psbt' to a 'continue'd"
		      "%s %.*s", hook_name,
		      toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	return returned_psbt;
}

/* The field is *always* assumed msats, as that's the unit
 * amount we're transitioning our API over to. A 'xxxsat'
 * unit will be interpreted correctly, but a value given
 * without a unit will always be interpreted as msats */
static amount_sat hook_extract_amount(struct subd *dualopend,
				      const char *buffer,
				      const jsmntok_t *toks,
				      char *field_name)
{
	struct amount_msat msats;

	if (!buffer)
		fatal("Plugin must return a valid response");

	const jsmntok_t *t = json_get_member(buffer, toks, "result");
	if (!t)
		fatal("Plugin must return a 'result' "
		      " %.*s", toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	if (!json_tok_streq(buffer, t, "continue")) {
		char *errmsg = "Client error. Unable to continue";
		subd_send_msg(dualopend,
			      take(towire_dual_open_fail(NULL, errmsg)));
		return NULL;
	}

	const jsmntok_t *amt_tok = json_get_member(buffer, toks, field_name);
	if (!amt_tok)
		fatal("Plugin must return a '%s' to a 'continue'd"
		      " %.*s", field_name,
		      toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	if (!json_to_msat(buffer, amt_tok, &msats))
		fatal("Plugin must return a valid '%s' to a 'continue'd"
		      " %.*s", field_name,
		      toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	return amount_msat_to_sat_round_down(msats);
}

#define CHECK_CHANGES(set, dir) 						\
	do {		   							\
	for (size_t i = 0; i < tal_count(set); i++) { 				\
		ok = psbt_get_serial_id(set[i]->dir->unknowns, &serial_id); 	\
		assert(ok); 							\
		if (serial_id % 2 != opener_side)				\
			return true;						\
	}									\
	} while (false);							\

static bool psbt_side_contribs_changed(struct wally_psbt *orig,
				       struct wally_psbt *new,
				       enum side opener_side)
{
	struct input_set *added_in, rm_in;
	struct output_set *added_out, rm_out;
	u32 serial_id;
	bool ok;

	if (!psbt_has_diff(tmpctx, orig, new,
			   &added_in, &rm_in,
			   &added_out, &rm_out))
		return false;

	/* If there were *any* changes, then the answer to the 'both sides'
	 * question is "yes, there were changes" */
	if (opener_side == NUM_SIDES)
		return true;

	/* Check that none of the included updates have a serial
	 * id that's the peer's parity */
	CHECK_CHANGES(added_in, in);
	CHECK_CHANGES(rm_in, in);
	CHECK_CHANGES(added_out, out);
	CHECK_CHANGES(rm_out, out);

	return false;
}

/* Adds serials indiscriminately to any input/output that doesn't
 * have one yet */
static void psbt_add_serials(struct wally_psbt *psbt, enum side opener)
{
	u32 serial_id;
	const u64 serial_space = 100000;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		/* Skip ones that already have a serial id */
		if (psbt_get_serial_id(psbt->inputs[i].unknowns, &serial_id))
			continue;

		while ((serial_id = pseudorand(serial_space)) % 2 != opener ||
			psbt_has_serial_input(psbt, serial_id)) {
			/* keep going; */
		}
		psbt_input_add_serial_id(&psbt->inputs[i], serial_id);
	}
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		/* Skip ones that already have a serial id */
		if (psbt_get_serial_id(psbt->outputs[i].unknowns, &serial_id))
			continue;

		while ((serial_id = pseudorand(serial_space)) % 2 != opener ||
			psbt_has_serial_output(psbt, serial_id)) {
			/* keep going; */
		}
		psbt_output_add_serial_id(&psbt->outputs[i], serial_id);
	}
}

static void
openchannel2_hook_cb(struct openchannel2_payload *payload STEALS,
			    const char *buffer,
			    const jsmntok_t *toks)
{
	struct subd *dualopend = payload->dualopend;
	struct wally_psbt *psbt;
	struct amount_sat accepter_funding;

	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	/* If our daemon died, we're done */
	if (!dualopend)
		return;

	tal_del_destructor2(dualopend, openchannel2_remove_dualopend, payload);
	psbt = hook_extract_psbt(dualopend, buffer, toks, "openchannel2");

	/* We handle errors in hook_extract_psbt, so just end. */
	if (!psbt)
		return;

	const u8 *our_shutdown_scriptpubkey =
		hook_extract_shutdown_script(dualopend, buffer, toks);

	/* Add a serial_id to everything that doesn't have one yet */
	psbt_add_serials(psbt);

	if (!psbt_has_required_fields(psbt))
		fatal("Plugin supplied PSBT that's missing required fields. %s",
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	accepter_funding =
		hook_extract_amount(dualopend, buffer, toks, "accepter_funding_msat");

	subd_send_msg(dualopend,
		      take(towire_dual_open_got_offer_reply(NULL,
							    accepter_funding,
							    psbt,
							    our_shutdown_scriptpubkey)));
}

static void
openchannel2_changed_hook_cb(struct openchannel2_psbt_payload *payload STEALS,
			     const char *buffer,
			     const jsmntok_t *toks)
{
	struct subd *dualopend = payload->dualopend;
	struct wally_psbt *psbt;

	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	/* If our daemon died, we're done */
	if (!dualopend)
		return;

	tal_del_destructor2(dualopend, openchannel2_psbt_remove_dualopend, payload);
	psbt = hook_extract_psbt(dualopend, buffer, toks, "openchannel2_changed");
	if (!psbt)
		return;

	/* Add serials to everything that doesn't have one yet. Note
	 * that if the external merger left data off this will fail
	 * the contribs_changed check */
	psbt_add_serials(psbt);

	if (!psbt_has_required_fields(psbt))
		fatal("Plugin supplied PSBT that's missing required fields. %s",
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	if (psbt_side_contribs_changed(payload->psbt, psbt, REMOTE))
		fatal("Plugin must not change peer's contributions. "
		      "orig: %s. updated: %s",
		      type_to_string(tmpctx, struct wally_psbt, payload->psbt),
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	subd_send_msg(dualopend,
		      take(towire_dual_open_psbt_changed(NULL, psbt)));
}

static void
openchannel2_sign_hook_cb(struct openchannel2_psbt_payload *payload STEALS,
			  const char *buffer,
			  const jsmntok_t *toks)
{
	struct subd *dualopend = payload->dualopend;
	struct wally_psbt *signed_psbt;

	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	/* If our daemon died, we're done */
	if (!dualopend)
		return;

	tal_del_destructor2(dualopend, openchannel2_psbt_remove_dualopend, payload);
	signed_psbt = hook_extract_psbt(dualopend, buffer, toks, "openchannel2_sign");
	if (!signed_psbt)
		return;

	if (!psbt_has_required_fields(psbt))
		fatal("Plugin supplied PSBT that's missing required fields. %s",
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	/* Verify that inputs/outputs are the same. Note that this is a
	 * 'de minimus' check -- we just look at serial_ids. If you've
	 * totally managled the data here but left the serial_ids intact,
	 * you'll get a failure back from the peer when you send
	 * commitment sigs */
	if (psbt_side_contribs_changed(payload->psbt, psbt, NUM_SIDES))
		fatal("Plugin must not change psbt input/output set. "
		      "orig: %s. updated: %s",
		      type_to_string(tmpctx, struct wally_psbt, payload->psbt),
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	if (!psbt_side_finalized(signed_psbt, REMOTE))
		fatal("Plugin must return a 'psbt' with signatures for their inputs"
		      "%s", type_to_string(tmpctx, struct wally_psbt, signed_psbt));

	handle_signed_psbt(dualopend, payload->rcvd, signed_psbt);
}

REGISTER_PLUGIN_HOOK(openchannel2,
		     openchannel2_hook_cb,
		     openchannel2_hook_serialize,
		     struct openchannel2_payload *);

REGISTER_PLUGIN_HOOK(openchannel2_changed,
		     openchannel2_changed_hook_cb,
		     openchannel2_changed_hook_serialize,
		     struct openchannel2_psbt_payload *);

REGISTER_PLUGIN_HOOK(openchannel2_sign,
		     openchannel2_sign_hook_cb,
		     openchannel2_sign_hook_serialize,
		     struct openchannel2_psbt_payload *);

/* dualopend dies?  Remove dualopend ptr from payload */
static void openchannel2_remove_dualopend(struct subd *dualopend,
					  struct openchannel2_payload *payload)
{
	assert(payload->dualopend == dualopend);
	payload->dualopend = NULL;
}

/* dualopend dies?  Remove dualopend ptr from payload */
static void openchannel2_psbt_remove_dualopend(struct subd *dualopend,
					       struct openchannel2_psbt_payload *payload)
{
	assert(payload->dualopend == dualopend);
	payload->dualopend = NULL;
}

/* Steals fields from precommit_channel: returns NULL if can't generate a
 * key for this channel (shouldn't happen!). */
static struct channel *
wallet_commit_channel(struct lightningd *ld,
		      struct precommit_channel *pc,
		      struct bitcoin_tx *remote_commit,
		      struct bitcoin_signature *remote_commit_sig,
		      const struct bitcoin_txid *funding_txid,
		      u16 funding_outnum,
		      struct amount_sat total_funding,
		      struct amount_sat our_funding,
		      u8 channel_flags,
		      struct channel_info *channel_info,
		      u32 feerate,
		      enum side opener,
		      const u8 *our_upfront_shutdown_script,
		      const u8 *remote_upfront_shutdown_script)
{
	struct channel *channel;
	s64 final_key_idx;
	bool option_static_remotekey;
	struct amount_msat our_msat;

	/* Get a key to use for closing outputs from this tx */
	final_key_idx = wallet_get_newindex(ld);
	if (final_key_idx == -1) {
		log_broken(pc->log, "Can't get final key index");
		return NULL;
	}

	if (!amount_sat_to_msat(&our_msat, our_funding)) {
		log_broken(pc->log, "Unable to convert funds");
		return NULL;
	}

	channel_info->fee_states = new_fee_states(pc, opener, &feerate);

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* BOLT #2:
	 * 1. type: 35 (`funding_signed`)
	 * 2. data:
	 *     * [`channel_id`:`channel_id`]
	 *     * [`signature`:`signature`]
	 *
	 * #### Requirements
	 *
	 * Both peers:
	 *   - if `option_static_remotekey` was negotiated:
	 *     - `option_static_remotekey` applies to all commitment
	 *       transactions
	 *   - otherwise:
	 *     - `option_static_remotekey` does not apply to any commitment
	 *        transactions
	 */
	/* i.e. We set it now for the channel permanently. */
	option_static_remotekey
		= feature_negotiated(ld->our_features,
				     pc->peer->their_features,
				     OPT_STATIC_REMOTEKEY);

	channel = new_channel(pc->peer, pc->dbid,
			      NULL, /* No shachain yet */
			      CHANNELD_AWAITING_LOCKIN,
			      opener,
			      pc->log,
			      take(pc->transient_billboard),
			      channel_flags,
			      &pc->our_config,
			      pc->minimum_depth,
			      1, 1, 0,
			      funding_txid,
			      funding_outnum,
			      total_funding,
			      AMOUNT_MSAT(0),
			      our_funding,
			      false, /* !remote_funding_locked */
			      NULL, /* no scid yet */
			      /* The three arguments below are msatoshi_to_us,
			       * msatoshi_to_us_min, and msatoshi_to_us_max.
			       * Because, this is a newly-funded channel,
			       * all three are same value. */
			      our_msat,
			      our_msat, /* msat_to_us_min */
			      our_msat, /* msat_to_us_max */
			      remote_commit,
			      remote_commit_sig,
			      NULL, /* No HTLC sigs yet */
			      channel_info,
			      NULL, /* No shutdown_scriptpubkey[REMOTE] yet */
			      our_upfront_shutdown_script,
			      final_key_idx, false,
			      NULL, /* No commit sent yet */
			      /* If we're fundee, could be a little before this
			       * in theory, but it's only used for timing out. */
			      get_block_height(ld->topology),
			      feerate, feerate,
			      /* We are connected */
			      true,
			      &pc->local_basepoints,
			      &pc->local_funding_pubkey,
			      NULL,
			      ld->config.fee_base,
			      ld->config.fee_per_satoshi,
			      remote_upfront_shutdown_script,
			      option_static_remotekey);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	return channel;
}

static void accepter_commit_received(struct subd *dualopend,
				     struct precommit_channel *pc,
				     const u8 *msg)
{
	struct opening_channel *oc;
	struct openchannel2_psbt_payload *payload;

	struct lightningd *ld = dualopend->ld;
	struct channel_info channel_info;
	struct bitcoin_tx *remote_commit;
	struct bitcoin_signature remote_commit_sig;
	struct bitcoin_txid funding_txid;
	u16 funding_outnum;
	u32 feerate;
	struct amount_sat total_funding, our_funding, channel_reserve;
	u8 channel_flags, *remote_upfront_shutdown_script,
	   *local_upfront_shutdown_script;
	struct penalty_base *pbase;

	payload = tal(dualopend, struct openchannel2_psbt_payload);
	payload->dualopend = dualopend;
	payload->recvd = tal(payload, struct commit_recvd);

	if (!fromwire_dual_open_commit_rcvd(tmpctx, msg,
					    &remote_commit,
					    &pbase,
					    &remote_commit_sig,
					    &payload->psbt,
					    &payload->cid,
					    &payload->rcvd->pps,
					    &channel_info.theirbase.revocation,
					    &channel_info.theirbase.payment,
					    &channel_info.theirbase.htlc,
					    &channel_info.theirbase.delayed_payment,
					    &channel_info.remote_per_commit,
					    &channel_info.remote_fundingkey,
					    &funding_txid,
					    &funding_outnum,
					    &total_funding,
					    &funding_ours,
					    &channel_flags,
					    &feerate,
					    &payload->rcvd->commitment_msg,
					    &channel_reserve,
					    &local_upfront_shutdown_script,
					    &remote_upfront_shutdown_script)) {
		log_broken(pc->log, "bad DUAL_OPEN_COMMIT_RCVD %s",
			   tal_hex(msg, msg));
		precommit_channel_disconnect(pc, LOG_BROKEN, "bad DUAL_OPEN_COMMIT_RCVD");
		goto failed;
	}

	if (peer_active_channel(oc->peer)) {
		precommit_channel_disconnect(pc, LOG_BROKEN, "already have active channel");
		goto failed;
	}

	payload->rcvd->channel =
		wallet_commit_channel(ld, pc,
				      channel_id,
				      remote_commit,
				      &remote_commit_sig,
				      &funding_txid,
				      funding_outnum,
				      total_funding,
				      funding_ours,
				      AMOUNT_MSAT(0),
				      channel_flags,
				      &channel_info,
				      feerate,
				      REMOTE,
				      local_upfront_shutdown_script,
				      remote_upfront_shutdown_script);

	if (!channel) {
		precommit_channel_disconnect(pc, LOG_BROKEN, "commit channel failed");
		goto failed;
	}

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	/* We call out to our hook friend who will provide signatures for us! */
	tal_add_destructor2(dualopend, openchannel2_psbt_remove_dualopend, payload);
	plugin_hook_call_openchannel2_sign(dualopend->ld, payload);

	pc->dualopend = NULL;
	tal_free(pc);
	return;

failed:
	close(fds[0]);
	close(fds[1]);
	close(fds[3]);
	tal_free(pc);
}

static void accepter_psbt_changed(struct subd *dualopend, u8 *msg)
{
	struct openchannel2_psbt_payload *payload;

	if (!fromwire_dual_open_psbt_changed(payload, msg,
					     payload->psbt)) {
		log_broken(dualopend->log, "Malformed dual_open_psbt_changed %s",
			   tal_hex(tmpctx, msg));
		tal_free(dualopend);
		return;
	}


	tal_add_destructor2(dualopend, openchannel2_psbt_remove_dualopend, payload);
	plugin_hook_call_openchannel2_changed(dualopend->ld, payload);
}

static void accepter_got_offer(struct subd *dualopend,
			       struct precommit_channel *pc,
			       u8 *msg)
{
	struct openchannel2_payload *payload;

	if (peer_active_channel(pc->peer)) {
		subd_send_msg(dualopend,
				take(towire_dual_open_fail(NULL, "Already have active channel")));
		return;
	}

	payload = tal(dualopend, struct openchannel2_payload);
	payload->dualopend = dualopend;
	if (!fromwire_dual_open_got_offer(payload, msg,
					  &payload->their_funding,
					  &payload->dust_limit_satoshis,
					  &payload->max_htlc_value_in_flight_msat,
					  &payload->htlc_minimum_msat,
					  &payload->feerate_per_kw_funding,
					  &payload->feerate_per_kw,
					  &payload->to_self_delay,
					  &payload->max_accepted_htlcs,
					  &payload->channel_flags,
					  &payload->locktime,
					  &payload->shutdown_scriptpubkey)) {
		log_broken(pc->log, "Malformed dual_open_got_offer %s",
			   tal_hex(tmpctx, msg));
		tal_free(dualopend);
		return;
	}

	tal_add_destructor2(dualopend, openchannel2_remove_dualopend, payload);
	plugin_hook_call_openchannel2(dualopend->ld, payload);
}

static unsigned int dual_opend_msg(struct subd *dualopend,
				   const u8 *msg, const int *fds)
{
	enum dual_open_wire_type t = fromwire_peektype(msg);
	struct precommit_channel *pc = dualopend->channel;

	switch (t) {
		case DUAL_OPEN_GOT_OFFER:
			accepter_got_offer(dualopend, pc, msg);
			return 0;
		case DUAL_OPEN_PSBT_CHANGED:
			accepter_psbt_changed(dualopend, msg);
			return 0;
		case DUAL_OPEN_COMMIT_RCVD:
			if (tal_count(fds) != 3)
				return 3;
			accepter_commit_received(dualopend, pc, msg);
			return 0;
		case DUAL_OPEN_FAILED:
		case DUAL_OPEN_DEV_MEMLEAK_REPLY:

		/* Messages we send */
		case DUAL_OPEN_INIT:
		case DUAL_OPEN_GOT_OFFER_REPLY:
		case DUAL_OPEN_FAIL:
		case DUAL_OPEN_DEV_MEMLEAK:
			break;
	}

	switch ((enum common_wire_type)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_IN:
		handle_custommsg_in(openingd->ld, openingd->node_id, msg);
		return 0;
#else
	case WIRE_CUSTOMMSG_IN:
#endif
	/* We send these. */
	case WIRE_CUSTOMMSG_OUT:
		break;
	}

	log_broken(dualopend->log, "Unexpected msg %s: %s",
		   dual_open_wire_type_name(t), tal_hex(tmpctx, msg));
	tal_free(dualopend);
	return 0;
}

static void destroy_precommit_channel(struct precommit_channel *pc)
{
	if (pc->dualopend) {
		struct subd *dualopend = pc->dualopend;
		pc->dualopend = NULL;
		subd_release_channel(dualopend, pc);
	}

	/* This is how shutdown_subdaemons tells us not to delete from db! */
	if (!uc->peer->c.precommit_channel)
		return;

	pc->peer->c = NULL;

	maybe_delete_peer(pc->peer);
}


static struct precommit_channel *
new_precommit_channel(struct peer *peer)
{
	struct lightningd *ld = peer->ld;
	struct precommit_channel *pc = tal(ld, struct precommit_channel);

	pc->peer = peer;
	assert(!peer->c);

	pc->transient_billboard = NULL;
	pc->dbid = wallet_get_channel_dbid(ld->wallet);

	pc->log = new_log(pc, ld->log_book, &pc->peer->id,
			  "chan#%"PRIu64, pc->dbid);

	pc->our_config.id = 0;

	get_channel_basepoints(ld, &pc->peer->id, pc->dbid,
			       &pc->local_basepoints, &pc->local_funding_pubkey);

	pc->peer->c.precommit_channel = pc;
	tal_add_destructor(pc, destroy_precommit_channel);

	return pc;
}

static void precommit_channel_disconnect(struct precommit_channel *pc,
					 enum log_level level,
					 const char *desc)
{
	u8 *msg = towire_connectctl_peer_disconnected(tmpctx, &pc->peer->id);
	log_(pc->log, level, NULL, false, "%s", desc);
	subd_send_msg(pc->peer->ld->connectd, msg);
	/* FIXME: if cmd here, send command fail */
	/* this is a plugin notification that a channel's disconnected */
	notify_disconnect(pc->peer->ld, &pc->peer->id);
}


static void dualopen_channel_errmsg(struct precommit_channel *pc,
				    struct per_peer_state *pps,
				    const struct channel_id *channel_id UNUSED,
				    const char *desc,
				    bool soft_error UNUSED,
				    const u8 *err_for_them UNUSED)
{
	/* Close fds, if any. */
	tal_free(pps);
	precommit_channel_disconnect(uc, LOG_INFORM, desc);
	tal_free(uc);
}

void peer_start_dualopend(struct peer *peer,
			  struct per_peer_state *pps,
			  const u8 *send_msg)
{

	int hsmfd;
	u32 max_to_self_delay;
	struct amount_msat min_effective_htlc_capacity;
	struct precommit_channel *pc;
	const u8 *msg;

	assert(!peer->c);

	pc = peer->c.precommit_channel = new_precommit_channel(peer);

	hsmfd = hsm_get_client_fd(peer->ld, &pc->peer->id, pc->dbid,
				  HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	pc->dualopend = new_channel_subd(peer->ld,
					 "lightning_dualopend",
					 pc, &peer->id, pc->log,
					 true, dual_open_wire_type_name,
					 dual_opend_msg,
					 opening_channel_errmsg,
					 opening_channel_set_billboard,
					 take(&pps->peer_fd),
					 take(&pps->gossip_fd),
					 take(&pps->gossip_store_fd),
					 take(&hsmfd), NULL);
	if (!pc->dualopend) {
		precommit_channel_disconnect(pc, LOG_BROKEN,
					     tal_fmt(tmpctx,
						     "Running lightning_dualopend: %s",
						     strerror(errno)));
		tal_free(pc);
		return;
	}

	channel_config(peer->ld, &pc->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	/* BOLT #2:
	 *
	 * The sender:
	 *   - SHOULD set `minimum_depth` to a number of blocks it considers
	 *     reasonable to avoid double-spending of the funding transaction.
	 */
	pc->minimum_depth = peer->ld->config.anchor_confirms;

	msg = towire_dual_open_init(NULL,
				  chainparams,
				  peer->ld->our_features,
				  &pc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity,
				  pps, &uc->local_basepoints,
				  &pc->local_funding_pubkey,
				  pc->minimum_depth,
				  feerate_min(peer->ld, NULL),
				  feerate_max(peer->ld, NULL),
				  peer->their_features,
				  feature_negotiated(peer->ld->our_features,
						     peer->their_features,
						     OPT_STATIC_REMOTEKEY),
				  send_msg,
				  IFDEV(peer->ld->dev_fast_gossip, false));
	subd_send_msg(pc->dualopend, take(msg));
}
#endif /* EXPERIMENTAL_FEATURES */
