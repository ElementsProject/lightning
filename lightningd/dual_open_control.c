/* This is the lightningd handler for messages to/from various
 * dualopend subdaemons. It manages the callbacks and database
 * saves and funding tx watching for a channel open */

#include <bitcoin/psbt.h>
#include <ccan/ccan/take/take.h>
#include <ccan/short_types/short_types.h>
#include <common/amount.h>
#include <common/channel_config.h>
#include <common/channel_id.h>
#include <common/derive_basepoints.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/htlc.h>
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/per_peer_state.h>
#include <common/psbt_open.h>
#include <common/type_to_string.h>
#include <hsmd/capabilities.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <openingd/dualopend_wiregen.h>
#include <wire/common_wiregen.h>
#include <wire/peer_wire.h>

struct commit_rcvd {
	struct channel *channel;
	struct channel_id cid;
	struct per_peer_state *pps;
	u8 *commitment_msg;
	struct uncommitted_channel *uc;
};

static bool psbt_side_finalized(struct log *log, struct wally_psbt *psbt, enum side opener)
{
	u16 serial_id;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns, &serial_id)) {
			log_broken(log, "dual funding PSBT must have serial_id for each "
				   "input, none found for input %zu", i);
			return false;
		}
		/* It's our input if parity matches -- this shorthand
		 * works because LOCAL == 0. If the parity is even and
		 * we're the opener then it's ours; if the parity is odd
		 * and the REMOTE's the opener (opener == 1), then it's also
		 * ours. */
		if (serial_id % 2 == opener) {
			if (!psbt->inputs[i].final_witness ||
					psbt->inputs[i].final_witness->num_items == 0)
				return false;
		}
	}
	return true;
}

static void handle_signed_psbt(struct lightningd *ld,
			       const struct wally_psbt *psbt,
			       struct commit_rcvd *rcvd)
{
	/* Now that we've got the signed PSBT, save it */
	rcvd->channel->psbt = tal_steal(rcvd->channel, psbt);
	wallet_channel_save(ld->wallet, rcvd->channel);

	channel_watch_funding(ld, rcvd->channel);

	peer_start_channeld(rcvd->channel,
			    rcvd->pps,
			    rcvd->commitment_msg,
			    psbt, false);
	tal_free(rcvd->uc);
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
	struct node_id peer_id;
	struct amount_sat their_funding;
	struct amount_sat dust_limit_satoshis;
	struct amount_msat max_htlc_value_in_flight_msat;
	struct amount_msat htlc_minimum_msat;
	u32 feerate_per_kw_funding;
	u32 feerate_per_kw;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
	u8 channel_flags;
	u32 locktime;
	u8 *shutdown_scriptpubkey;
	/* FIXME: include the podle? */

	struct amount_sat accepter_funding;
	struct wally_psbt *psbt;
	const u8 *our_shutdown_scriptpubkey;
};

static void
openchannel2_hook_serialize(struct openchannel2_payload *payload,
			    struct json_stream *stream)
{
	json_object_start(stream, "openchannel2");
	json_add_node_id(stream, "id", &payload->peer_id);
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
	if (tal_bytelen(payload->shutdown_scriptpubkey) != 0)
		json_add_hex_talarr(stream, "shutdown_scriptpubkey",
				    payload->shutdown_scriptpubkey);
	/* FIXME: include the podle? */
	json_object_end(stream);
}

struct openchannel2_psbt_payload {
	struct subd *dualopend;
	struct wally_psbt *psbt;
	struct commit_rcvd *rcvd;
	struct lightningd *ld;
};

static void
openchannel2_changed_hook_serialize(struct openchannel2_psbt_payload *payload,
				    struct json_stream *stream)
{
	json_object_start(stream, "openchannel2_changed");
	json_add_psbt(stream, "psbt", payload->psbt);
	json_add_string(stream, "channel_id",
			type_to_string(tmpctx, struct channel_id,
				       &payload->rcvd->cid));
	json_object_end(stream);
}

static void
openchannel2_sign_hook_serialize(struct openchannel2_psbt_payload *payload,
				 struct json_stream *stream)
{
	json_object_start(stream, "openchannel2_sign");
	json_add_psbt(stream, "psbt", payload->psbt);
	json_add_string(stream, "channel_id",
			type_to_string(tmpctx, struct channel_id,
				       &payload->rcvd->channel->cid));
	json_object_end(stream);
}

static const u8 *hook_extract_shutdown_script(struct subd* dualopend,
					      const char *buffer,
					      const jsmntok_t *toks)
{
	const u8 *close_to_script;
	enum address_parse_result parse_res;

	if (!buffer)
		return NULL;

	const jsmntok_t *t = json_get_member(buffer, toks, "result");
	if (!t)
		fatal("Plugin must return a 'result'"
		      "%.*s", toks[0].end - toks[0].start,
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
			      tal_hex(NULL, close_to_script),
			      chainparams->network_name);
		case ADDRESS_PARSE_SUCCESS:
			return close_to_script;
	}

	return NULL;
}


static bool
hook_extract_psbt(const tal_t *ctx, struct subd *dualopend, const char *buffer,
		  const jsmntok_t *toks, char *hook_name,
		  bool allow_empty,
		  struct wally_psbt **out)
{
	struct wally_psbt *returned_psbt;

	if (!buffer)
		fatal("Plugin must return a valid response to %s", hook_name);

	const jsmntok_t *t = json_get_member(buffer, toks, "result");
	if (!t)
		fatal("Plugin must return a 'result' to %s"
		      "%.*s", hook_name, toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	if (!json_tok_streq(buffer, t, "continue")) {
		/* dualopend might have closed if we're on the signed round */
		if (dualopend) {
			char *errmsg = "Client error. Unable to continue";
			subd_send_msg(dualopend,
				      take(towire_dual_open_fail(NULL, errmsg)));
		}
		return false;
	}

	const jsmntok_t *psbt_tok = json_get_member(buffer, toks, "psbt");
	if (!psbt_tok) {
		if (!allow_empty)
			fatal("Plugin must return a 'psbt' to a 'continue'd"
			      "%s %.*s", hook_name,
			      toks[0].end - toks[0].start,
			      buffer + toks[0].start);
		*out = NULL;
		return true;
	}

	if (!json_to_psbt(ctx, buffer, psbt_tok, &returned_psbt))
		fatal("Plugin must return a valid 'psbt' to a 'continue'd"
		      "%s %.*s", hook_name,
		      toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	*out = returned_psbt;
	return true;
}

/* The field is *always* assumed msats, as that's the unit
 * amount we're transitioning our API over to. A 'xxxsat'
 * unit will be interpreted correctly, but a value given
 * without a unit will always be interpreted as msats */
static bool
hook_extract_amount(struct subd *dualopend,
		    const char *buffer,
		    const jsmntok_t *toks,
		    char *field_name,
		    struct amount_sat *amount)
{
	struct amount_msat msats;

	if (!buffer)
		return false;

	const jsmntok_t *t = json_get_member(buffer, toks, "result");
	if (!t)
		fatal("Plugin must return a 'result' "
		      " %.*s", toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	if (!json_tok_streq(buffer, t, "continue")) {
		char *errmsg = "Client error. Unable to continue";
		subd_send_msg(dualopend,
			      take(towire_dual_open_fail(NULL, errmsg)));
		return false;
	}

	/* If there's no amount_sat field, that's ok */
	const jsmntok_t *amt_tok = json_get_member(buffer, toks, field_name);
	if (!amt_tok) {
		*amount = AMOUNT_SAT(0);
		return true;
	}

	if (!json_to_msat(buffer, amt_tok, &msats))
		fatal("Plugin must return a valid '%s' to a 'continue'd"
		      " %.*s", field_name,
		      toks[0].end - toks[0].start,
		      buffer + toks[0].start);

	*amount = amount_msat_to_sat_round_down(msats);
	return true;
}

#define CHECK_CHANGES(set, dir) 						\
	do {		   							\
	for (size_t i = 0; i < tal_count(set); i++) { 				\
		ok = psbt_get_serial_id(&set[i].dir.unknowns, &serial_id); 	\
		assert(ok); 							\
		if (serial_id % 2 != opener_side)				\
			return true;						\
	}									\
	} while (false)								\

static bool psbt_side_contribs_changed(struct wally_psbt *orig,
				       struct wally_psbt *new,
				       enum side opener_side)
{
	struct psbt_changeset *cs;
	u16 serial_id;
	bool ok;

	cs = psbt_get_changeset(tmpctx, orig, new);

	if (tal_count(cs->added_ins) == 0 &&
	    tal_count(cs->rm_ins) == 0 &&
	    tal_count(cs->added_outs) == 0 &&
	    tal_count(cs->rm_outs) == 0)
		return false;

	/* If there were *any* changes, then the answer to the 'both sides'
	 * question is "yes, there were changes" */
	if (opener_side == NUM_SIDES)
		return true;

	/* Check that none of the included updates have a serial
	 * id that's the peer's parity */
	CHECK_CHANGES(cs->added_ins, input);
	CHECK_CHANGES(cs->rm_ins, input);
	CHECK_CHANGES(cs->added_outs, output);
	CHECK_CHANGES(cs->rm_outs, output);

	return false;
}

/* Adds serials to inputs + outputs that don't have one yet */
static void psbt_add_serials(struct wally_psbt *psbt, enum tx_role role)
{
	u16 serial_id;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		/* Skip ones that already have a serial id */
		if (psbt_get_serial_id(&psbt->inputs[i].unknowns, &serial_id))
			continue;

		serial_id = psbt_new_input_serial(psbt, role);
		psbt_input_add_serial_id(psbt, &psbt->inputs[i], serial_id);
	}
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		/* Skip ones that already have a serial id */
		if (psbt_get_serial_id(&psbt->outputs[i].unknowns, &serial_id))
			continue;

		serial_id = psbt_new_output_serial(psbt, role);
		psbt_output_add_serial_id(psbt, &psbt->outputs[i], serial_id);
	}
}

/* dualopend dies?  Remove dualopend ptr from payload */
static void openchannel2_remove_dualopend(struct subd *dualopend,
					  struct openchannel2_payload *payload)
{
	assert(payload->dualopend == dualopend);
	payload->dualopend = NULL;
}

static bool
openchannel2_hook_deserialize(struct openchannel2_payload *payload,
			      const char *buffer,
			      const jsmntok_t *toks)
{
	struct subd *dualopend = payload->dualopend;

	/* If our daemon died, we're done */
	if (!dualopend) {
		tal_free(payload);
		return false;
	}

	if (!hook_extract_psbt(payload, dualopend, buffer, toks,
			       "openchannel2", true, &payload->psbt))
		return false;

	payload->our_shutdown_scriptpubkey =
		hook_extract_shutdown_script(dualopend, buffer, toks);

	/* Add a serial_id to everything that doesn't have one yet */
	if (payload->psbt)
		psbt_add_serials(payload->psbt, TX_ACCEPTER);

	if (payload->psbt && !psbt_has_required_fields(payload->psbt))
		fatal("Plugin supplied PSBT that's missing required fields. %s",
		      type_to_string(tmpctx, struct wally_psbt, payload->psbt));

	if (!hook_extract_amount(dualopend, buffer, toks, "accepter_funding_msat",
				 &payload->accepter_funding))
		fatal("Plugin failed to supply accepter_funding_msat field");

	if (!payload->psbt &&
		!amount_sat_eq(payload->accepter_funding, AMOUNT_SAT(0))) {
		/* Gotta give a PSBT if you set the accepter_funding amount */
		return false;
	}

	return true;
}

static void
openchannel2_hook_cb(struct openchannel2_payload *payload STEALS)
{
	struct subd *dualopend = payload->dualopend;

	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	/* If our daemon died, we're done */
	if (!dualopend)
		return;

	tal_del_destructor2(dualopend, openchannel2_remove_dualopend, payload);

	/* If there's no plugin, the psbt will be NULL. We should pass an empty
	 * PSBT over, in this case */
	subd_send_msg(dualopend,
		      take(towire_dual_open_got_offer_reply(NULL,
							    payload->accepter_funding,
							    payload->psbt,
							    payload->our_shutdown_scriptpubkey)));
}

/* dualopend dies?  Remove dualopend ptr from payload */
static void openchannel2_psbt_remove_dualopend(struct subd *dualopend,
					       struct openchannel2_psbt_payload *payload)
{
	assert(payload->dualopend == dualopend);
	payload->dualopend = NULL;
}

static bool
openchannel2_changed_deserialize(struct openchannel2_psbt_payload *payload,
				 const char *buffer, const jsmntok_t *toks)
{
	struct subd *dualopend = payload->dualopend;
	struct wally_psbt *psbt;

	if (!hook_extract_psbt(NULL, dualopend, buffer,
			       toks, "openchannel2_sign",
			       false, &psbt))
		return false;

	/* Add serials to PSBT, before checking for required fields */
	psbt_add_serials(psbt, REMOTE);

	if (!psbt_has_required_fields(psbt))
		fatal("Plugin supplied PSBT that's missing required fields. %s",
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	if (payload->psbt)
		tal_free(payload->psbt);

	payload->psbt = tal_steal(payload, psbt);
	return true;
}

static void
openchannel2_changed_hook_cb(struct openchannel2_psbt_payload *payload STEALS)
{
	struct subd *dualopend = payload->dualopend;

	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	/* If our daemon died, we're done */
	if (!dualopend)
		return;

	tal_del_destructor2(dualopend,
			    openchannel2_psbt_remove_dualopend,
			    payload);

	subd_send_msg(dualopend,
		      take(towire_dual_open_psbt_changed(NULL,
							 &payload->rcvd->cid,
							 payload->psbt)));
}

static bool
openchannel2_signed_deserialize(struct openchannel2_psbt_payload *payload,
				const char *buffer, const jsmntok_t *toks)
{
	struct subd *dualopend = payload->dualopend;
	struct wally_psbt *psbt;

	if (!hook_extract_psbt(NULL, dualopend, buffer,
			       toks, "openchannel2_sign",
			       false, &psbt))
		return false;

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
		      type_to_string(tmpctx, struct wally_psbt,
			      	     payload->psbt),
		      type_to_string(tmpctx, struct wally_psbt,
			      	     psbt));

	if (payload->psbt)
		tal_free(payload->psbt);
	payload->psbt = tal_steal(payload, psbt);
	return true;
}

static void
openchannel2_sign_hook_cb(struct openchannel2_psbt_payload *payload STEALS)
{
	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	/* Finalize it, if not already. It shouldn't work entirely */
	psbt_finalize(payload->psbt);

	if (!psbt_side_finalized(payload->ld->log, payload->psbt, REMOTE))
		fatal("Plugin must return a 'psbt' with signatures for their inputs"
		      " %s", type_to_string(tmpctx, struct wally_psbt, payload->psbt));

	handle_signed_psbt(payload->ld, payload->psbt, payload->rcvd);
}

REGISTER_PLUGIN_HOOK(openchannel2,
		     openchannel2_hook_deserialize,
		     openchannel2_hook_cb,
		     openchannel2_hook_serialize,
		     struct openchannel2_payload *);

REGISTER_PLUGIN_HOOK(openchannel2_changed,
		     openchannel2_changed_deserialize,
		     openchannel2_changed_hook_cb,
		     openchannel2_changed_hook_serialize,
		     struct openchannel2_psbt_payload *);

REGISTER_PLUGIN_HOOK(openchannel2_sign,
		     openchannel2_signed_deserialize,
		     openchannel2_sign_hook_cb,
		     openchannel2_sign_hook_serialize,
		     struct openchannel2_psbt_payload *);

/* Steals fields from uncommitted_channel: returns NULL if can't generate a
 * key for this channel (shouldn't happen!). */
static struct channel *
wallet_commit_channel(struct lightningd *ld,
		      struct uncommitted_channel *uc,
		      struct channel_id *cid,
		      struct bitcoin_tx *remote_commit,
		      struct bitcoin_signature *remote_commit_sig,
		      const struct bitcoin_txid *funding_txid,
		      u16 funding_outnum,
		      struct amount_sat total_funding,
		      struct amount_sat our_funding,
		      u8 channel_flags,
		      const struct channel_info *channel_info,
		      u32 feerate,
		      enum side opener,
		      const u8 *our_upfront_shutdown_script,
		      const u8 *remote_upfront_shutdown_script)
{
	struct channel *channel;
	s64 final_key_idx;
	bool option_static_remotekey;
	bool option_anchor_outputs;
	struct amount_msat our_msat;

	/* Get a key to use for closing outputs from this tx */
	final_key_idx = wallet_get_newindex(ld);
	if (final_key_idx == -1) {
		log_broken(uc->log, "Can't get final key index");
		return NULL;
	}

	if (!amount_sat_to_msat(&our_msat, our_funding)) {
		log_broken(uc->log, "Unable to convert funds");
		return NULL;
	}

	/* BOLT-7b04b1461739c5036add61782d58ac490842d98b #9
	 * | 222/223 | `option_dual_fund`
	 * | Use v2 of channel open, enables dual funding
	 * | IN9
	 * | `option_anchor_outputs`    */
	option_static_remotekey = true;
	option_anchor_outputs = true;

	channel = new_channel(uc->peer, uc->dbid,
			      NULL, /* No shachain yet */
			      CHANNELD_AWAITING_LOCKIN,
			      opener,
			      uc->log,
			      take(uc->transient_billboard),
			      channel_flags,
			      &uc->our_config,
			      uc->minimum_depth,
			      1, 1, 0,
			      funding_txid,
			      funding_outnum,
			      total_funding,
			      AMOUNT_MSAT(0),
			      our_funding,
			      false, /* !remote_funding_locked */
			      NULL, /* no scid yet */
			      cid,
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
			      take(new_fee_states(NULL, opener, &feerate)),
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
			      &uc->local_basepoints,
			      &uc->local_funding_pubkey,
			      NULL,
			      ld->config.fee_base,
			      ld->config.fee_per_satoshi,
			      remote_upfront_shutdown_script,
			      option_static_remotekey,
			      option_anchor_outputs,
			      NULL);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	return channel;
}

static void opener_psbt_changed(struct subd *dualopend,
				struct uncommitted_channel *uc,
				const u8 *msg)
{
	struct channel_id cid;
	struct wally_psbt *psbt;
	struct json_stream *response;
	struct command *cmd = uc->fc->cmd;

	if (!fromwire_dual_open_psbt_changed(cmd, msg,
					     &cid,
					     &psbt)) {
		log_broken(dualopend->log,
			   "Malformed dual_open_psbt_changed %s",
			   tal_hex(tmpctx, msg));
		tal_free(dualopend);
		return;
	}

	response = json_stream_success(cmd);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &cid));
	json_add_psbt(response, "psbt", psbt);
	json_add_bool(response, "commitments_secured", false);

	uc->fc->inflight = true;
	uc->fc->cmd = NULL;
	was_pending(command_success(cmd, response));
}

static void accepter_commit_received(struct subd *dualopend,
				     struct uncommitted_channel *uc,
				     const int *fds,
				     const u8 *msg)
{
	struct openchannel2_psbt_payload *payload;

	struct lightningd *ld = dualopend->ld;
	struct channel_info channel_info;
	struct bitcoin_tx *remote_commit;
	struct bitcoin_signature remote_commit_sig;
	struct channel_id cid;
	struct bitcoin_txid funding_txid;
	struct per_peer_state *pps;
	u16 funding_outnum;
	u32 feerate;
	struct amount_sat total_funding, funding_ours, channel_reserve;
	u8 channel_flags, *remote_upfront_shutdown_script,
	   *local_upfront_shutdown_script, *commitment_msg;
	struct penalty_base *pbase;
	struct wally_psbt *psbt;

	payload = tal(uc, struct openchannel2_psbt_payload);
	payload->rcvd = tal(payload, struct commit_rcvd);

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_dual_open_commit_rcvd(tmpctx, msg,
					    &channel_info.their_config,
					    &remote_commit,
					    &pbase,
					    &remote_commit_sig,
					    &psbt,
					    &cid,
					    &pps,
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
					    &commitment_msg,
					    &channel_reserve,
					    &local_upfront_shutdown_script,
					    &remote_upfront_shutdown_script)) {
		log_broken(uc->log, "bad WIRE_DUAL_OPEN_COMMIT_RCVD %s",
			   tal_hex(msg, msg));
		uncommitted_channel_disconnect(uc, LOG_BROKEN, "bad WIRE_DUAL_OPEN_COMMIT_RCVD");
		close(fds[0]);
		close(fds[1]);
		close(fds[3]);
		goto failed;
	}

	per_peer_state_set_fds_arr(pps, fds);
	payload->psbt = tal_steal(payload, psbt);
	payload->rcvd->pps = tal_steal(payload, pps);
	payload->rcvd->commitment_msg = tal_steal(payload, commitment_msg);
	payload->ld = ld;

	if (peer_active_channel(uc->peer)) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN, "already have active channel");
		goto failed;
	}

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info.old_remote_per_commit = channel_info.remote_per_commit;

	payload->rcvd->channel =
		wallet_commit_channel(ld, uc,
				      &cid,
				      remote_commit,
				      &remote_commit_sig,
				      &funding_txid,
				      funding_outnum,
				      total_funding,
				      funding_ours,
				      channel_flags,
				      &channel_info,
				      feerate,
				      REMOTE,
				      local_upfront_shutdown_script,
				      remote_upfront_shutdown_script);

	if (!payload->rcvd->channel) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN, "commit channel failed");
		goto failed;
	}

	if (pbase)
		wallet_penalty_base_add(ld->wallet, payload->rcvd->channel->dbid,
					pbase);

	/* dualopend is going away! */
	/* We steal onto `NULL` because `payload` is tal'd off of `uc`;
	 * we free `uc` at the end though */
	payload->rcvd->uc = tal_steal(NULL, uc);

	/* We call out to our hook friend who will provide signatures for us! */
	plugin_hook_call_openchannel2_sign(ld, payload);

	/* We release the things here; dualopend is going away ?? */
	subd_release_channel(dualopend, uc);
	uc->open_daemon = NULL;
	return;

failed:
	subd_release_channel(dualopend, uc);
	uc->open_daemon = NULL;
	tal_free(uc);
}

static void opener_commit_received(struct subd *dualopend,
				   struct uncommitted_channel *uc,
				   const int *fds,
				   const u8 *msg)
{
	struct lightningd *ld = dualopend->ld;
	struct channel_info channel_info;
	struct bitcoin_tx *remote_commit;
	struct bitcoin_signature remote_commit_sig;
	struct channel_id cid;
	struct bitcoin_txid funding_txid;
	struct per_peer_state *pps;
	struct json_stream *response;
	u16 funding_outnum;
	u32 feerate;
	struct amount_sat total_funding, funding_ours, channel_reserve;
	u8 channel_flags, *remote_upfront_shutdown_script,
	   *local_upfront_shutdown_script, *commitment_msg;
	struct penalty_base *pbase;
	struct wally_psbt *psbt;
	struct channel *channel;
	char *err_reason;

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_dual_open_commit_rcvd(tmpctx, msg,
					    &channel_info.their_config,
					    &remote_commit,
					    &pbase,
					    &remote_commit_sig,
					    &psbt,
					    &cid,
					    &pps,
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
					    &commitment_msg,
					    &channel_reserve,
					    &local_upfront_shutdown_script,
					    &remote_upfront_shutdown_script)) {
		log_broken(uc->log, "bad WIRE_DUAL_OPEN_COMMIT_RCVD %s",
			   tal_hex(msg, msg));
		err_reason = "bad WIRE_DUAL_OPEN_COMMIT_RCVD";
		uncommitted_channel_disconnect(uc, LOG_BROKEN, err_reason);
		close(fds[0]);
		close(fds[1]);
		close(fds[3]);
		goto failed;
	}

	/* We shouldn't have a commitment message, this is an
	 * accepter flow item */
	assert(!commitment_msg);

	per_peer_state_set_fds_arr(pps, fds);
	if (peer_active_channel(uc->peer)) {
		err_reason = "already have active channel";
		uncommitted_channel_disconnect(uc, LOG_BROKEN, err_reason);
		goto failed;
	}

	/* Our end game is to save the channel to the database, and return the
	 * command with 'commitments_secured' set to true */
	channel = wallet_commit_channel(ld, uc, &cid,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_outnum,
					total_funding,
					funding_ours,
					channel_flags,
					&channel_info,
					feerate,
					LOCAL,
					local_upfront_shutdown_script,
					remote_upfront_shutdown_script);

	if (!channel) {
		err_reason = "commit channel failed";
		uncommitted_channel_disconnect(uc, LOG_BROKEN, err_reason);
		goto failed;
	}

	channel->pps = tal_steal(channel, pps);
	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	response = json_stream_success(uc->fc->cmd);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &cid));
	json_add_psbt(response, "psbt", psbt);
	json_add_bool(response, "commitments_secured", true);
	was_pending(command_success(uc->fc->cmd, response));

	subd_release_channel(dualopend, uc);
	uc->open_daemon = NULL;
	tal_free(uc);
	return;

failed:
	was_pending(command_fail(uc->fc->cmd, LIGHTNINGD,
				   "%s", err_reason));
	subd_release_channel(dualopend, uc);
	uc->open_daemon = NULL;
	tal_free(uc);
}

static void accepter_psbt_changed(struct subd *dualopend,
				  const u8 *msg)
{
	struct openchannel2_psbt_payload *payload =
		tal(dualopend, struct openchannel2_psbt_payload);
	payload->dualopend = dualopend;
	payload->psbt = NULL;
	payload->rcvd = tal(payload, struct commit_rcvd);

	if (!fromwire_dual_open_psbt_changed(payload, msg,
					     &payload->rcvd->cid,
					     &payload->psbt)) {
		log_broken(dualopend->log, "Malformed dual_open_psbt_changed %s",
			   tal_hex(tmpctx, msg));
		tal_free(dualopend);
		return;
	}

	tal_add_destructor2(dualopend, openchannel2_psbt_remove_dualopend, payload);
	plugin_hook_call_openchannel2_changed(dualopend->ld, payload);
}

static void accepter_got_offer(struct subd *dualopend,
			       struct uncommitted_channel *uc,
			       const u8 *msg)
{
	struct openchannel2_payload *payload;

	if (peer_active_channel(uc->peer)) {
		subd_send_msg(dualopend,
				take(towire_dual_open_fail(NULL, "Already have active channel")));
		return;
	}

	payload = tal(dualopend, struct openchannel2_payload);
	payload->dualopend = dualopend;
	payload->psbt = NULL;
	payload->accepter_funding = AMOUNT_SAT(0);
	payload->our_shutdown_scriptpubkey = NULL;
	payload->peer_id = uc->peer->id;

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
		log_broken(uc->log, "Malformed dual_open_got_offer %s",
			   tal_hex(tmpctx, msg));
		tal_free(dualopend);
		return;
	}

	tal_add_destructor2(dualopend, openchannel2_remove_dualopend, payload);
	plugin_hook_call_openchannel2(dualopend->ld, payload);
}

static struct command_result *json_open_channel_signed(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	struct wally_psbt *psbt;
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	struct bitcoin_txid txid;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("signed_psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer)
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");

	channel = peer_active_channel(peer);
	if (!channel)
		return command_fail(cmd, LIGHTNINGD,
				    "Peer has no active channel");

	if (!channel->pps)
		return command_fail(cmd, LIGHTNINGD,
				    "Missing per-peer-state for channel, "
				    "are you in the right state to call "
				    "this method?");

	if (channel->psbt)
		return command_fail(cmd, LIGHTNINGD,
				    "Already have a finalized PSBT for "
				    "this channel");

	/* Verify that the psbt's txid matches that of the
	 * funding txid for this channel */
	psbt_txid(NULL, psbt, &txid, NULL);
	if (!bitcoin_txid_eq(&txid, &channel->funding_txid))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Txid for passed in PSBT does not match"
				    " funding txid for channel. Expected %s, "
				    "received %s",
				    type_to_string(tmpctx, struct bitcoin_txid,
						   &channel->funding_txid),
				    type_to_string(tmpctx, struct bitcoin_txid,
						   &txid));


	/* Go ahead and try to finalize things, or what we can */
	psbt_finalize(psbt);

	/* Check that all of *our* outputs are finalized */
	if (!psbt_side_finalized(cmd->ld->log, psbt, LOCAL))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Local PSBT input(s) not finalized");

	/* Now that we've got the signed PSBT, save it */
	channel->psbt = tal_steal(channel, psbt);
	wallet_channel_save(cmd->ld->wallet, channel);

	channel_watch_funding(cmd->ld, channel);

	register_open_command(cmd->ld, cmd, channel);
	peer_start_channeld(channel, channel->pps,
			    NULL, psbt, false);
	channel->pps = tal_free(channel->pps);

	return command_still_pending(cmd);
}

static struct command_result *json_open_channel_update(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	struct wally_psbt *psbt;
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	struct channel_id chan_id_unused;
	u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, id);
	if (!peer)
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");

	channel = peer_active_channel(peer);
	if (channel)
		return command_fail(cmd, LIGHTNINGD, "Peer already %s",
				    channel_state_name(channel));

	if (!peer->uncommitted_channel)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");

	if (!peer->uncommitted_channel->fc || !peer->uncommitted_channel->fc->inflight)
		return command_fail(cmd, LIGHTNINGD, "No channel funding in progress");

	if (peer->uncommitted_channel->fc->cmd)
		return command_fail(cmd, LIGHTNINGD, "Channel funding in progress");

	/* Add serials to PSBT */
	psbt_add_serials(psbt, TX_INITIATOR);
	if (!psbt_has_required_fields(psbt))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "PSBT is missing required fields %s",
				    type_to_string(tmpctx, struct wally_psbt, psbt));

	peer->uncommitted_channel->fc->cmd = cmd;

	memset(&chan_id_unused, 0, sizeof(chan_id_unused));
	msg = towire_dual_open_psbt_changed(NULL, &chan_id_unused, psbt);
	subd_send_msg(peer->uncommitted_channel->open_daemon, take(msg));
	return command_still_pending(cmd);
}


static struct command_result *json_open_channel_init(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	struct funding_channel *fc = tal(cmd, struct funding_channel);
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	bool *announce_channel;
	u32 *feerate_per_kw_funding;
	u32 *feerate_per_kw;
	struct amount_sat *amount, psbt_val;
	struct wally_psbt *psbt;

	u8 *msg = NULL;

	fc->cmd = cmd;
	fc->cancels = tal_arr(fc, struct command *, 0);
	fc->uc = NULL;
	fc->inflight = false;

	if (!param(fc->cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("amount", param_sat, &amount),
		   p_req("initialpsbt", param_psbt, &psbt),
		   p_opt("commitment_feerate", param_feerate, &feerate_per_kw),
		   p_opt("funding_feerate", param_feerate, &feerate_per_kw_funding),
		   p_opt_def("announce", param_bool, &announce_channel, true),
		   p_opt("close_to", param_bitcoin_address, &fc->our_upfront_shutdown_script),
		   NULL))
		return command_param_failed();

	psbt_val = AMOUNT_SAT(0);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct amount_sat in_amt = psbt_input_get_amount(psbt, i);
		if (!amount_sat_add(&psbt_val, psbt_val, in_amt))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Overflow in adding PSBT input values. %s",
					    type_to_string(tmpctx, struct wally_psbt, psbt));
	}

	/* If they don't pass in at least enough in the PSBT to cover
	 * their amount, nope */
	if (!amount_sat_greater(psbt_val, *amount))
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Provided PSBT cannot afford funding of "
				    "amount %s. %s",
				    type_to_string(tmpctx, struct amount_sat, amount),
				    type_to_string(tmpctx, struct wally_psbt, psbt));

	fc->funding = *amount;
	if (!feerate_per_kw) {
		feerate_per_kw = tal(cmd, u32);
		/* Anchors exist, set the commitment feerate to min */
		*feerate_per_kw = feerate_min(cmd->ld, NULL);
	}
	if (!feerate_per_kw_funding) {
		feerate_per_kw_funding = tal(cmd, u32);
		*feerate_per_kw_funding = opening_feerate(cmd->ld->topology);
		if (!*feerate_per_kw_funding)
			return command_fail(cmd, LIGHTNINGD,
					    "`funding_feerate` not specified and fee "
					    "estimation failed");
	}

	if (!topology_synced(cmd->ld->topology)) {
		return command_fail(cmd, FUNDING_STILL_SYNCING_BITCOIN,
				    "Still syncing with bitcoin network");
	}

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	channel = peer_active_channel(peer);
	if (channel) {
		return command_fail(cmd, LIGHTNINGD, "Peer already %s",
				    channel_state_name(channel));
	}

	if (!peer->uncommitted_channel) {
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");
	}

	if (peer->uncommitted_channel->fc) {
		return command_fail(cmd, LIGHTNINGD, "Already funding channel");
	}

#if EXPERIMENTAL_FEATURES
	if (!feature_negotiated(cmd->ld->our_features,
			        peer->their_features,
				OPT_DUAL_FUND)) {
		return command_fail(cmd, FUNDING_V2_NOT_SUPPORTED,
				    "v2 openchannel not supported "
				    "by peer");
	}
#endif /* EXPERIMENTAL_FEATURES */

	/* BOLT #2:
	 *  - if both nodes advertised `option_support_large_channel`:
	 *    - MAY set `funding_satoshis` greater than or equal to 2^24 satoshi.
	 *  - otherwise:
	 *    - MUST set `funding_satoshis` to less than 2^24 satoshi.
	 */
	if (!feature_negotiated(cmd->ld->our_features,
				peer->their_features, OPT_LARGE_CHANNELS)
	    && amount_sat_greater(*amount, chainparams->max_funding))
		return command_fail(cmd, FUND_MAX_EXCEEDED,
				    "Amount exceeded %s",
				    type_to_string(tmpctx, struct amount_sat,
						   &chainparams->max_funding));

	fc->channel_flags = OUR_CHANNEL_FLAGS;
	if (!*announce_channel) {
		fc->channel_flags &= ~CHANNEL_FLAGS_ANNOUNCE_CHANNEL;
		log_info(peer->ld->log, "Will open private channel with node %s",
			type_to_string(fc, struct node_id, id));
	}

	/* Add serials to any input that's missing them */
	psbt_add_serials(psbt, TX_INITIATOR);
	if (!psbt_has_required_fields(psbt))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "PSBT is missing required fields %s",
				    type_to_string(tmpctx, struct wally_psbt,
						   psbt));

	peer->uncommitted_channel->fc = tal_steal(peer->uncommitted_channel, fc);
	fc->uc = peer->uncommitted_channel;

	/* Needs to be stolen away from cmd */
	if (fc->our_upfront_shutdown_script)
		fc->our_upfront_shutdown_script
			= tal_steal(fc, fc->our_upfront_shutdown_script);

	msg = towire_dual_open_opener_init(NULL,
					   psbt, *amount,
					   fc->our_upfront_shutdown_script,
					   *feerate_per_kw,
					   *feerate_per_kw_funding,
					   fc->channel_flags);

	subd_send_msg(peer->uncommitted_channel->open_daemon, take(msg));
	return command_still_pending(cmd);
}

static unsigned int dual_opend_msg(struct subd *dualopend,
				   const u8 *msg, const int *fds)
{
	enum dualopend_wire t = fromwire_peektype(msg);
	struct uncommitted_channel *uc = dualopend->channel;

	switch (t) {
		case WIRE_DUAL_OPEN_GOT_OFFER:
			accepter_got_offer(dualopend, uc, msg);
			return 0;
		case WIRE_DUAL_OPEN_PSBT_CHANGED:
			if (uc->fc) {
				if (!uc->fc->cmd) {
					log_unusual(dualopend->log,
						    "Unexpected PSBT_CHANGED %s",
						    tal_hex(tmpctx, msg));
					tal_free(dualopend);
					return 0;
				}
				opener_psbt_changed(dualopend, uc, msg);
			} else
				accepter_psbt_changed(dualopend, msg);
			return 0;
		case WIRE_DUAL_OPEN_COMMIT_RCVD:
			if (tal_count(fds) != 3)
				return 3;
			if (uc->fc) {
				if (!uc->fc->cmd) {
					log_unusual(dualopend->log,
						    "Unexpected COMMIT_RCVD %s",
						    tal_hex(tmpctx, msg));
					tal_free(dualopend);
					return 0;
				}
				opener_commit_received(dualopend,
						       uc, fds, msg);
			} else
				accepter_commit_received(dualopend,
							 uc, fds, msg);
			return 0;
		case WIRE_DUAL_OPEN_FAILED:
		case WIRE_DUAL_OPEN_DEV_MEMLEAK_REPLY:

		/* Messages we send */
		case WIRE_DUAL_OPEN_INIT:
		case WIRE_DUAL_OPEN_OPENER_INIT:
		case WIRE_DUAL_OPEN_GOT_OFFER_REPLY:
		case WIRE_DUAL_OPEN_FAIL:
		case WIRE_DUAL_OPEN_DEV_MEMLEAK:
			break;
	}

	switch ((enum common_wire)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_IN:
		handle_custommsg_in(dualopend->ld, dualopend->node_id, msg);
		return 0;
#else
	case WIRE_CUSTOMMSG_IN:
#endif
	/* We send these. */
	case WIRE_CUSTOMMSG_OUT:
		break;
	}

	log_broken(dualopend->log, "Unexpected msg %s: %s",
		   dualopend_wire_name(t), tal_hex(tmpctx, msg));
	tal_free(dualopend);
	return 0;
}

static const struct json_command open_channel_init_command = {
	"openchannel_init",
	"channels",
	json_open_channel_init,
	"Init an open channel to {id} with {initialpsbt} for {amount} satoshis. "
	"Returns updated {psbt} with (partial) contributions from peer"
};

static const struct json_command open_channel_update_command = {
	"openchannel_update",
	"channels",
	json_open_channel_update,
	"Update {channel_id} with {psbt}. "
	"Returns updated {psbt} with (partial) contributions from peer. "
	"If {commitments_secured} is true, next call should be to openchannel_signed"
};

static const struct json_command open_channel_signed_command = {
	"openchannel_signed",
	"channels",
	json_open_channel_signed,
	"Finish opening {channel_id} with {signed_psbt}. "
};

#if EXPERIMENTAL_FEATURES
AUTODATA(json_command, &open_channel_init_command);
AUTODATA(json_command, &open_channel_update_command);
AUTODATA(json_command, &open_channel_signed_command);
#endif /* EXPERIMENTAL_FEATURES */

void peer_start_dualopend(struct peer *peer,
			  struct per_peer_state *pps,
			  const u8 *send_msg)
{

	int hsmfd;
	u32 max_to_self_delay;
	struct amount_msat min_effective_htlc_capacity;
	struct uncommitted_channel *uc;
	const u8 *msg;

	assert(!peer->uncommitted_channel);

	uc = peer->uncommitted_channel = new_uncommitted_channel(peer);

	hsmfd = hsm_get_client_fd(peer->ld, &uc->peer->id, uc->dbid,
				  HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	uc->open_daemon = new_channel_subd(peer->ld,
					   "lightning_dualopend",
					   uc, &peer->id, uc->log,
					   true, dualopend_wire_name,
					   dual_opend_msg,
					   opend_channel_errmsg,
					   opend_channel_set_billboard,
					   take(&pps->peer_fd),
					   take(&pps->gossip_fd),
					   take(&pps->gossip_store_fd),
					   take(&hsmfd), NULL);
	if (!uc->open_daemon) {
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       tal_fmt(tmpctx,
						       "Running lightning_dualopend: %s",
						       strerror(errno)));
		tal_free(uc);
		return;
	}

	channel_config(peer->ld, &uc->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	/* BOLT #2:
	 *
	 * The sender:
	 *   - SHOULD set `minimum_depth` to a number of blocks it considers
	 *     reasonable to avoid double-spending of the funding transaction.
	 */
	uc->minimum_depth = peer->ld->config.anchor_confirms;

	msg = towire_dual_open_init(NULL,
				  chainparams,
				  peer->ld->our_features,
				  peer->their_features,
				  &uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity,
				  pps, &uc->local_basepoints,
				  &uc->local_funding_pubkey,
				  uc->minimum_depth,
				  feerate_min(peer->ld, NULL),
				  feerate_max(peer->ld, NULL),
				  send_msg);
	subd_send_msg(uc->open_daemon, take(msg));
}
