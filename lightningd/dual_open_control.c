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
#include <lightningd/notification.h>
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

static void handle_signed_psbt(struct lightningd *ld,
			       const struct wally_psbt *psbt,
			       struct commit_rcvd *rcvd)
{
	/* Now that we've got the signed PSBT, save it */
	rcvd->channel->psbt =
		tal_steal(rcvd->channel,
			  cast_const(struct wally_psbt *, psbt));
	wallet_channel_save(ld->wallet, rcvd->channel);

	channel_watch_funding(ld, rcvd->channel);

	peer_start_channeld(rcvd->channel,
			    rcvd->pps,
			    rcvd->commitment_msg,
			    false);
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
	u32 funding_feerate_max;
	u32 funding_feerate_min;
	u32 funding_feerate_best;
	u32 feerate_our_max;
	u32 feerate_our_min;
	u32 commitment_feerate_per_kw;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
	u8 channel_flags;
	u32 locktime;
	u8 *shutdown_scriptpubkey;
	/* FIXME: include the podle? */

	struct amount_sat accepter_funding;
	u32 funding_feerate_per_kw;
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
	json_add_num(stream, "funding_feerate_max",
		     payload->funding_feerate_max);
	json_add_num(stream, "funding_feerate_min",
		     payload->funding_feerate_min);
	json_add_num(stream, "funding_feerate_best",
		     payload->funding_feerate_best);
	json_add_num(stream, "feerate_our_max",
		     payload->feerate_our_max);
	json_add_num(stream, "feerate_our_min",
		     payload->feerate_our_min);
	json_add_num(stream, "commitment_feerate_per_kw",
		     payload->commitment_feerate_per_kw);
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
			      take(towire_dualopend_fail(NULL, errmsg)));
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
				      take(towire_dualopend_fail(NULL, errmsg)));
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

	*out = json_to_psbt(ctx, buffer, psbt_tok);
	if (!*out)
		fatal("Plugin must return a valid 'psbt' to a 'continue'd"
		      "%s %.*s", hook_name,
		      toks[0].end - toks[0].start,
		      buffer + toks[0].start);

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
			      take(towire_dualopend_fail(NULL, errmsg)));
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

#define CHECK_CHANGES(set, dir) 					\
	do {		   						\
		for (size_t i = 0; i < tal_count(set); i++) { 		\
			ok = psbt_get_serial_id(&set[i].dir.unknowns,	\
						&serial_id); 		\
			assert(ok); 					\
			if (serial_id % 2 != opener_side)		\
				return true;				\
		}							\
	} while (false)

static bool psbt_side_contribs_changed(struct wally_psbt *orig,
				       struct wally_psbt *new,
				       enum side opener_side)
{
	struct psbt_changeset *cs;
	u64 serial_id;
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

	if (!hook_extract_amount(dualopend, buffer, toks,
				 "accepter_funding_msat",
				 &payload->accepter_funding))
		fatal("Plugin failed to supply accepter_funding_msat field");

	const jsmntok_t *t = json_get_member(buffer, toks, "funding_feerate");
	/* If they don't return a feerate, we use the best */
	if (!t)
		payload->funding_feerate_per_kw = payload->funding_feerate_best;
	else {
		if (!json_to_number(buffer, t,
				    &payload->funding_feerate_per_kw))
			fatal("Unable to parse 'funding-feerate'");
		if (payload->funding_feerate_per_kw
				< payload->funding_feerate_min
		    || payload->funding_feerate_per_kw
				> payload->funding_feerate_max)
			/* FIXME: return an error instead of failing? */
			fatal("Plugin supplied invalid funding feerate %d."
			      " Outside valid range %d - %d",
			      payload->funding_feerate_per_kw,
			      payload->funding_feerate_min,
			      payload->funding_feerate_max);
	}

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
	u8 *msg;

	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	/* If our daemon died, we're done */
	if (!dualopend)
		return;

	tal_del_destructor2(dualopend, openchannel2_remove_dualopend, payload);

	/* If there's no plugin, the funding_feerate_per_kw will be zero.
	 * In this case, we set the funding_feerate_per_kw to the default,
	 * the 'best' */
	if (payload->funding_feerate_per_kw == 0)
		payload->funding_feerate_per_kw = payload->funding_feerate_best;

	/* If there's no plugin, the psbt will be NULL. We should pass an empty
	 * PSBT over, in this case */
	msg = towire_dualopend_got_offer_reply(NULL, payload->accepter_funding,
					       payload->funding_feerate_per_kw,
					       payload->psbt,
					       payload->our_shutdown_scriptpubkey);
	subd_send_msg(dualopend, take(msg));
}

/* dualopend dies?  Remove dualopend ptr from payload */
static void
openchannel2_psbt_remove_dualopend(struct subd *dualopend,
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
	psbt_add_serials(psbt, TX_ACCEPTER);

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
		      take(towire_dualopend_psbt_updated(NULL,
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

	if (!psbt_side_finalized(payload->psbt, TX_ACCEPTER))
		fatal("Plugin must return a 'psbt' with signatures "
		      "for their inputs %s",
		      type_to_string(tmpctx, struct wally_psbt, payload->psbt));

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
			      NULL,
			      NUM_SIDES, /* closer not yet known */
			      opener == LOCAL ? REASON_USER : REASON_REMOTE);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	return channel;
}

static void opener_psbt_changed(struct subd *dualopend,
				struct uncommitted_channel *uc,
				const u8 *msg)
{
	struct channel_id cid;
	u64 funding_serial;
	struct wally_psbt *psbt;
	struct json_stream *response;
	struct command *cmd = uc->fc->cmd;

	if (!fromwire_dualopend_psbt_changed(cmd, msg,
					     &cid, &funding_serial,
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
	json_add_u64(response, "funding_serial", funding_serial);

	uc->cid = cid;
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
	struct amount_sat total_funding, funding_ours;
	u8 channel_flags, *remote_upfront_shutdown_script,
	   *local_upfront_shutdown_script, *commitment_msg;
	struct penalty_base *pbase;
	struct wally_psbt *psbt;

	payload = tal(uc, struct openchannel2_psbt_payload);
	payload->rcvd = tal(payload, struct commit_rcvd);

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_dualopend_commit_rcvd(tmpctx, msg,
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
					    &uc->our_config.channel_reserve,
					    &local_upfront_shutdown_script,
					    &remote_upfront_shutdown_script)) {
		log_broken(uc->log, "bad WIRE_DUALOPEND_COMMIT_RCVD %s",
			   tal_hex(msg, msg));
		uncommitted_channel_disconnect(uc, LOG_BROKEN, "bad WIRE_DUALOPEND_COMMIT_RCVD");
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
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       "already have active channel");
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
		uncommitted_channel_disconnect(uc, LOG_BROKEN,
					       "commit channel failed");
		goto failed;
	}

	if (pbase)
		wallet_penalty_base_add(ld->wallet,
					payload->rcvd->channel->dbid,
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
	struct amount_sat total_funding, funding_ours;
	u8 channel_flags, *remote_upfront_shutdown_script,
	   *local_upfront_shutdown_script, *commitment_msg;
	struct penalty_base *pbase;
	struct wally_psbt *psbt;
	struct channel *channel;
	char *err_reason;

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_dualopend_commit_rcvd(tmpctx, msg,
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
					    &uc->our_config.channel_reserve,
					    &local_upfront_shutdown_script,
					    &remote_upfront_shutdown_script)) {
		log_broken(uc->log, "bad WIRE_DUALOPEND_COMMIT_RCVD %s",
			   tal_hex(msg, msg));
		err_reason = "bad WIRE_DUALOPEND_COMMIT_RCVD";
		uncommitted_channel_disconnect(uc, LOG_BROKEN, err_reason);
		close(fds[0]);
		close(fds[1]);
		close(fds[3]);
		goto failed;
	}

	/* We shouldn't have a commitment message, this is an
	 * accepter flow item */
	assert(!commitment_msg);

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info.old_remote_per_commit = channel_info.remote_per_commit;

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

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	response = json_stream_success(uc->fc->cmd);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &cid));
	json_add_psbt(response, "psbt", psbt);
	json_add_bool(response, "commitments_secured", true);
	/* For convenience sake, we include the funding outnum */
	json_add_num(response, "funding_outnum", funding_outnum);
	if (local_upfront_shutdown_script)
		json_add_hex_talarr(response, "close_to",
				    local_upfront_shutdown_script);
	/* Now that we've got the final PSBT, save it */
	channel->psbt = tal_steal(channel, psbt);
	wallet_channel_save(uc->fc->cmd->ld->wallet, channel);

	peer_start_channeld(channel, pps,
			    NULL, false);

	was_pending(command_success(uc->fc->cmd, response));
	goto cleanup;

failed:
	was_pending(command_fail(uc->fc->cmd, LIGHTNINGD,
				   "%s", err_reason));
cleanup:
	subd_release_channel(dualopend, uc);
	uc->open_daemon = NULL;
	tal_free(uc);
}

static void accepter_psbt_changed(struct subd *dualopend,
				  const u8 *msg)
{
	u64 unused;
	struct openchannel2_psbt_payload *payload =
		tal(dualopend, struct openchannel2_psbt_payload);
	payload->dualopend = dualopend;
	payload->psbt = NULL;
	payload->rcvd = tal(payload, struct commit_rcvd);

	if (!fromwire_dualopend_psbt_changed(payload, msg,
					     &payload->rcvd->cid,
					     &unused,
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
				take(towire_dualopend_fail(NULL, "Already have active channel")));
		return;
	}

	payload = tal(dualopend, struct openchannel2_payload);
	payload->dualopend = dualopend;
	payload->psbt = NULL;
	payload->accepter_funding = AMOUNT_SAT(0);
	payload->our_shutdown_scriptpubkey = NULL;
	payload->peer_id = uc->peer->id;

	if (!fromwire_dualopend_got_offer(payload, msg,
					  &payload->their_funding,
					  &payload->dust_limit_satoshis,
					  &payload->max_htlc_value_in_flight_msat,
					  &payload->htlc_minimum_msat,
					  &payload->funding_feerate_max,
					  &payload->funding_feerate_min,
					  &payload->funding_feerate_best,
					  &payload->commitment_feerate_per_kw,
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

	/* As a convenience to the plugin, we provide our current known
	 * min + max feerates. Ideally, the plugin will fail to
	 * contribute funds if the peer's feerate range is outside of
	 * this acceptable range, but we delegate that decision to
	 * the plugin's logic */
	payload->feerate_our_min = feerate_min(dualopend->ld, NULL);
	payload->feerate_our_max = feerate_max(dualopend->ld, NULL);

	/* Set the inital to feerate to zero, in case there is no plugin */
	payload->funding_feerate_per_kw = 0;

	tal_add_destructor2(dualopend, openchannel2_remove_dualopend, payload);
	plugin_hook_call_openchannel2(dualopend->ld, payload);
}

struct channel_send {
	const struct wally_tx *wtx;
	struct channel *channel;
};

static void sendfunding_done(struct bitcoind *bitcoind UNUSED,
			     bool success, const char *msg,
			     struct channel_send *cs)
{
	struct lightningd *ld = cs->channel->peer->ld;
	struct channel *channel = cs->channel;
	const struct wally_tx *wtx = cs->wtx;
	struct json_stream *response;
	struct bitcoin_txid txid;
	struct amount_sat unused;
	int num_utxos;
	struct command *cmd = channel->openchannel_signed_cmd;
	channel->openchannel_signed_cmd = NULL;

	if (!cmd && channel->opener == LOCAL)
		log_broken(channel->log,
			   "No outstanding command for channel %s,"
			   " funding sent was success? %d",
			   type_to_string(tmpctx, struct channel_id,
					  &channel->cid),
			   success);

	if (!success) {
		if (cmd)
			was_pending(command_fail(cmd,
						 FUNDING_BROADCAST_FAIL,
						 "Error broadcasting funding "
						 "tx: %s. Unsent tx discarded "
						 "%s.",
						 msg,
						 type_to_string(tmpctx,
								struct wally_tx,
								wtx)));
		log_unusual(channel->log,
			    "Error broadcasting funding "
			    "tx: %s. Unsent tx discarded "
			    "%s.",
			    msg,
			    type_to_string(tmpctx, struct wally_tx, wtx));
		tal_free(cs);
		return;
	}

	/* This might have spent UTXOs from our wallet */
	num_utxos = wallet_extract_owned_outputs(ld->wallet,
						 wtx, NULL,
						 &unused);
	if (num_utxos)
		wallet_transaction_add(ld->wallet, wtx, 0, 0);

	if (cmd) {
		response = json_stream_success(cmd);
		wally_txid(wtx, &txid);
		json_add_hex_talarr(response, "tx", linearize_wtx(tmpctx, wtx));
		json_add_txid(response, "txid", &txid);
		json_add_string(response, "channel_id",
				type_to_string(tmpctx, struct channel_id,
					       &channel->cid));
		was_pending(command_success(cmd, response));
	}

	tal_free(cs);
}


static void send_funding_tx(struct channel *channel,
			    const struct wally_tx *wtx TAKES)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_send *cs;

	cs = tal(channel, struct channel_send);
	cs->channel = channel;
	if (taken(wtx))
		cs->wtx = tal_steal(cs, wtx);
	else {
		tal_wally_start();
		wally_tx_clone_alloc(wtx, 0,
				     cast_const2(struct wally_tx **,
						 &cs->wtx));
		tal_wally_end(tal_steal(cs, cs->wtx));
	}

	log_debug(channel->log,
		  "Broadcasting funding tx for channel %s. %s",
		  type_to_string(tmpctx, struct channel_id, &channel->cid),
		  type_to_string(tmpctx, struct wally_tx, cs->wtx));

	bitcoind_sendrawtx(ld->topology->bitcoind,
			   tal_hex(tmpctx, linearize_wtx(tmpctx, cs->wtx)),
			   sendfunding_done, cs);
}

static void peer_tx_sigs_msg(struct subd *dualopend,
			     const u8 *msg)
{
	struct wally_psbt *psbt;
	const struct wally_tx *wtx;
	struct lightningd *ld = dualopend->ld;
	struct channel *channel = dualopend->channel;

	if (!fromwire_dualopend_funding_sigs(tmpctx, msg, &psbt)) {
		channel_internal_error(channel,
				       "bad dualopend_funding_sigs: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	tal_wally_start();
	if (wally_psbt_combine(channel->psbt, psbt) != WALLY_OK) {
		channel_internal_error(channel,
				       "Unable to combine PSBTs: %s, %s",
				       type_to_string(tmpctx,
						      struct wally_psbt,
						      channel->psbt),
				       type_to_string(tmpctx,
						      struct wally_psbt,
						      psbt));
		tal_wally_end(channel->psbt);
		return;
	}
	tal_wally_end(channel->psbt);

	if (psbt_finalize(cast_const(struct wally_psbt *, channel->psbt))) {
		wtx = psbt_final_tx(NULL, channel->psbt);
		if (wtx)
			send_funding_tx(channel, take(wtx));
	}

	wallet_channel_save(ld->wallet, channel);

	/* Send notification with peer's signed PSBT */
	notify_openchannel_peer_sigs(ld, &channel->cid,
				     channel->psbt);
}


static struct command_result *
json_openchannel_signed(struct command *cmd,
			 const char *buffer,
			 const jsmntok_t *obj UNNEEDED,
			 const jsmntok_t *params)
{
	struct wally_psbt *psbt;
	const struct wally_tx *wtx;
	struct uncommitted_channel *uc;
	struct channel_id *cid;
	struct channel *channel;
	struct bitcoin_txid txid;

	if (!param(cmd, buffer, params,
		   p_req("channel_id", param_channel_id, &cid),
		   p_req("signed_psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	channel = channel_by_cid(cmd->ld, cid, &uc);
	if (uc)
		return command_fail(cmd, LIGHTNINGD,
				    "Commitments for this channel not "
				    "yet secured, see `openchannl_update`");
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel");
	if (channel->psbt && psbt_is_finalized(channel->psbt))
		return command_fail(cmd, LIGHTNINGD,
				    "Already have a finalized PSBT for "
				    "this channel");
	if (channel->openchannel_signed_cmd)
		return command_fail(cmd, LIGHTNINGD,
				    "Already sent sigs, waiting for"
				    " peer's");

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
	if (!psbt_side_finalized(psbt, TX_INITIATOR))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Local PSBT input(s) not finalized");

	/* Now that we've got the signed PSBT, save it */
	tal_wally_start();
	if (wally_psbt_combine(cast_const(struct wally_psbt *,
					  channel->psbt),
			       psbt) != WALLY_OK) {
		tal_wally_end(tal_free(channel->psbt));
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Failed adding sigs");
	}
	tal_wally_end(tal_steal(channel, channel->psbt));

	wallet_channel_save(cmd->ld->wallet, channel);
	channel_watch_funding(cmd->ld, channel);

	/* Send our tx_sigs to the peer */
	subd_send_msg(channel->owner,
		      take(towire_dualopend_send_tx_sigs(NULL, channel->psbt)));

	if (psbt_finalize(cast_const(struct wally_psbt *, channel->psbt))) {
		wtx = psbt_final_tx(NULL, channel->psbt);
		if (wtx)
			send_funding_tx(channel, take(wtx));
	}

	channel->openchannel_signed_cmd = tal_steal(channel, cmd);
	return command_still_pending(cmd);
}


static struct command_result *json_openchannel_update(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	struct wally_psbt *psbt;
	struct channel_id *cid;
	struct channel *channel;
	struct uncommitted_channel *uc;
	u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("channel_id", param_channel_id, &cid),
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	/* We expect this to return NULL, as the channel hasn't been
	 * created yet. Instead, the uncommitted channel is populated */
	channel = channel_by_cid(cmd->ld, cid, &uc);
	if (channel)
		return command_fail(cmd, LIGHTNINGD, "Channel already %s",
				    channel_state_name(channel));

	if (!uc)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    type_to_string(tmpctx, struct channel_id,
						   cid));

	if (!uc->fc || !uc->fc->inflight)
		return command_fail(cmd, LIGHTNINGD,
				    "No channel funding in progress");

	if (uc->fc->cmd)
		return command_fail(cmd, LIGHTNINGD,
				    "Channel funding in progress");

	/* Add serials to PSBT */
	psbt_add_serials(psbt, TX_INITIATOR);
	if (!psbt_has_required_fields(psbt))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "PSBT is missing required fields %s",
				    type_to_string(tmpctx, struct wally_psbt,
						   psbt));

	uc->fc->cmd = cmd;

	msg = towire_dualopend_psbt_updated(NULL, psbt);
	subd_send_msg(uc->open_daemon, take(msg));
	return command_still_pending(cmd);
}

static struct command_result *json_openchannel_init(struct command *cmd,
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

	msg = towire_dualopend_opener_init(NULL,
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

	/* FIXME: might be channel? */
	struct uncommitted_channel *uc = dualopend->channel;

	switch (t) {
		case WIRE_DUALOPEND_GOT_OFFER:
			accepter_got_offer(dualopend, uc, msg);
			return 0;
		case WIRE_DUALOPEND_PSBT_CHANGED:
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
		case WIRE_DUALOPEND_COMMIT_RCVD:
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
		case WIRE_DUALOPEND_FUNDING_SIGS:
			peer_tx_sigs_msg(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_FAILED:
		case WIRE_DUALOPEND_DEV_MEMLEAK_REPLY:

		/* Messages we send */
		case WIRE_DUALOPEND_INIT:
		case WIRE_DUALOPEND_OPENER_INIT:
		case WIRE_DUALOPEND_GOT_OFFER_REPLY:
		case WIRE_DUALOPEND_FAIL:
		case WIRE_DUALOPEND_PSBT_UPDATED:
		case WIRE_DUALOPEND_SEND_TX_SIGS:
		case WIRE_DUALOPEND_DEV_MEMLEAK:
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

static const struct json_command openchannel_init_command = {
	"openchannel_init",
	"channels",
	json_openchannel_init,
	"Init an open channel to {id} with {initialpsbt} for {amount} satoshis. "
	"Returns updated {psbt} with (partial) contributions from peer"
};

static const struct json_command openchannel_update_command = {
	"openchannel_update",
	"channels",
	json_openchannel_update,
	"Update {channel_id} with {psbt}. "
	"Returns updated {psbt} with (partial) contributions from peer. "
	"If {commitments_secured} is true, next call should be to openchannel_signed"
};

static const struct json_command openchannel_signed_command = {
	"openchannel_signed",
	"channels",
	json_openchannel_signed,
	"Send our {signed_psbt}'s tx sigs for {channel_id}."
};

#if EXPERIMENTAL_FEATURES
AUTODATA(json_command, &openchannel_init_command);
AUTODATA(json_command, &openchannel_update_command);
AUTODATA(json_command, &openchannel_signed_command);
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

	msg = towire_dualopend_init(NULL,
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
