/* This is the lightningd handler for messages to/from various
 * dualopend subdaemons. It manages the callbacks and database
 * saves and funding tx watching for a channel open */

#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/ccan/mem/mem.h>
#include <ccan/ccan/take/take.h>
#include <ccan/ccan/tal/tal.h>
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
#include <common/shutdown_scriptpubkey.h>
#include <common/type_to_string.h>
#include <connectd/connectd_wiregen.h>
#include <hsmd/capabilities.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>
#include <openingd/dualopend_wiregen.h>
#include <wire/common_wiregen.h>
#include <wire/peer_wire.h>

struct commit_rcvd {
	struct channel *channel;
	struct channel_id cid;
	struct uncommitted_channel *uc;
};

static void channel_disconnect(struct channel *channel,
			       enum log_level level,
			       bool reconnect,
			       const char *desc)
{
	log_(channel->log, level, NULL, false, "%s", desc);
	channel_cleanup_commands(channel, desc);

	notify_disconnect(channel->peer->ld, &channel->peer->id);

	if (!reconnect)
		channel_set_owner(channel, NULL);
	else
		channel_fail_reconnect(channel, "%s: %s",
				       channel->owner ?
						channel->owner->name :
						"dualopend-dead",
				       desc);
}

void channel_unsaved_close_conn(struct channel *channel, const char *why)
{
	/* Gotta be unsaved */
	assert(channel_unsaved(channel));
	log_info(channel->log, "Unsaved peer failed."
		 " Disconnecting and deleting channel. Reason: %s",
		 why);

	notify_disconnect(channel->peer->ld, &channel->peer->id);
	channel_cleanup_commands(channel, why);

	channel_set_owner(channel, NULL);
	delete_channel(channel);
}

static void channel_saved_err_broken_reconn(struct channel *channel,
					    const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;

	/* We only reconnect to 'saved' channel peers */
	assert(!channel_unsaved(channel));

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	log_broken(channel->log, "%s", errmsg);
	channel_disconnect(channel, LOG_INFORM, true, errmsg);
}

static void channel_err_broken(struct channel *channel,
			       const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	if (channel_unsaved(channel)) {
		log_broken(channel->log, "%s", errmsg);
		channel_unsaved_close_conn(channel, errmsg);
	} else
		channel_disconnect(channel, LOG_BROKEN, false, errmsg);
}

void json_add_unsaved_channel(struct json_stream *response,
			      const struct channel *channel)
{
	struct amount_msat total;
	struct open_attempt *oa;

	if (!channel)
		return;

	/* If we're chatting but no channel, that's shown by connected: True */
	if (!channel->open_attempt)
		return;

	oa = channel->open_attempt;

	json_object_start(response, NULL);
	json_add_string(response, "state", channel_state_name(channel));
	json_add_string(response, "owner", channel->owner->name);
	json_add_string(response, "opener", channel->opener == LOCAL ?
					    "local" : "remote");
	json_array_start(response, "status");
	for (size_t i = 0; i < ARRAY_SIZE(channel->billboard.permanent); i++) {
		if (!channel->billboard.permanent[i])
			continue;
		json_add_string(response, NULL,
				channel->billboard.permanent[i]);
	}
	if (channel->billboard.transient)
		json_add_string(response, NULL, channel->billboard.transient);
	json_array_end(response);

	/* funding + our_upfront_shutdown only available if we're initiator */
	if (oa->role == TX_INITIATOR) {
		if (amount_sat_to_msat(&total, oa->funding)) {
			json_add_amount_msat_compat(response, total,
						    "msatoshi_to_us",
						    "to_us_msat");
			/* This will change if peer adds funds */
			json_add_amount_msat_compat(response, total,
						    "msatoshi_total",
						    "total_msat");
		}
	}

	json_array_start(response, "features");
	/* v2 channels assumed to have both static_remotekey + anchor_outputs */
	json_add_string(response, NULL, "option_static_remotekey");
	json_add_string(response, NULL, "option_anchor_outputs");
	json_array_end(response);
	json_object_end(response);
}

struct rbf_channel_payload {
	struct subd *dualopend;
	struct channel *channel;
	struct node_id peer_id;

	/* Info specific to this RBF */
	struct channel_id channel_id;
	struct amount_sat their_funding;
	u32 funding_feerate_per_kw;
	u32 locktime;

	/* General info */
	u32 feerate_our_max;
	u32 feerate_our_min;
	/* What's the maximum amount of funding
	 * this channel can hold */
	struct amount_sat channel_max;

	/* Returned from hook */
	struct amount_sat our_funding;
	struct wally_psbt *psbt;
	char *err_msg;
};

static void rbf_channel_hook_serialize(struct rbf_channel_payload *payload,
				       struct json_stream *stream,
				       struct plugin *plugin)
{
	json_object_start(stream, "rbf_channel");
	json_add_node_id(stream, "id", &payload->peer_id);
	json_add_channel_id(stream, "channel_id", &payload->channel_id);
	json_add_amount_sat_only(stream, "their_funding",
				 payload->their_funding);
	json_add_num(stream, "locktime", payload->locktime);
	json_add_num(stream, "feerate_our_max",
		     payload->feerate_our_max);
	json_add_num(stream, "feerate_our_min",
		     payload->feerate_our_min);
	json_add_num(stream, "funding_feerate_per_kw",
		     payload->funding_feerate_per_kw);
	json_add_amount_sat_only(stream, "channel_max_msat",
				 payload->channel_max);
	json_object_end(stream);
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
	struct channel *channel;
	struct node_id peer_id;
	struct channel_id channel_id;
	struct amount_sat their_funding;
	struct amount_sat dust_limit_satoshis;
	struct amount_msat max_htlc_value_in_flight_msat;
	struct amount_msat htlc_minimum_msat;
	u32 funding_feerate_per_kw;
	u32 feerate_our_max;
	u32 feerate_our_min;
	u32 commitment_feerate_per_kw;
	u16 to_self_delay;
	u16 max_accepted_htlcs;
	u8 channel_flags;
	u32 locktime;
	u8 *shutdown_scriptpubkey;
	/* What's the maximum amount of funding
	 * this channel can hold */
	struct amount_sat channel_max;

	struct amount_sat accepter_funding;
	struct wally_psbt *psbt;
	const u8 *our_shutdown_scriptpubkey;
	char *err_msg;
};

static void openchannel2_hook_serialize(struct openchannel2_payload *payload,
					struct json_stream *stream,
					struct plugin *plugin)
{
	json_object_start(stream, "openchannel2");
	json_add_node_id(stream, "id", &payload->peer_id);
	json_add_channel_id(stream, "channel_id", &payload->channel_id);
	json_add_amount_sat_only(stream, "their_funding",
				 payload->their_funding);
	json_add_amount_sat_only(stream, "dust_limit_satoshis",
				 payload->dust_limit_satoshis);
	json_add_amount_msat_only(stream, "max_htlc_value_in_flight_msat",
				  payload->max_htlc_value_in_flight_msat);
	json_add_amount_msat_only(stream, "htlc_minimum_msat",
				  payload->htlc_minimum_msat);
	json_add_num(stream, "funding_feerate_per_kw",
		     payload->funding_feerate_per_kw);
	json_add_num(stream, "commitment_feerate_per_kw",
		     payload->commitment_feerate_per_kw);
	json_add_num(stream, "feerate_our_max",
		     payload->feerate_our_max);
	json_add_num(stream, "feerate_our_min",
		     payload->feerate_our_min);
	json_add_num(stream, "to_self_delay", payload->to_self_delay);
	json_add_num(stream, "max_accepted_htlcs", payload->max_accepted_htlcs);
	json_add_num(stream, "channel_flags", payload->channel_flags);
	json_add_num(stream, "locktime", payload->locktime);
	if (tal_bytelen(payload->shutdown_scriptpubkey) != 0)
		json_add_hex_talarr(stream, "shutdown_scriptpubkey",
				    payload->shutdown_scriptpubkey);
	json_add_amount_sat_only(stream, "channel_max_msat",
				 payload->channel_max);
	json_object_end(stream);
}

struct openchannel2_psbt_payload {
	struct subd *dualopend;
	struct wally_psbt *psbt;
	struct channel *channel;
	struct lightningd *ld;
};

static void
openchannel2_changed_hook_serialize(struct openchannel2_psbt_payload *payload,
				    struct json_stream *stream,
				    struct plugin *plugin)
{
	json_object_start(stream, "openchannel2_changed");
	json_add_psbt(stream, "psbt", payload->psbt);
	json_add_string(stream, "channel_id",
			type_to_string(tmpctx, struct channel_id,
				       &payload->channel->cid));
	json_object_end(stream);
}

static void
openchannel2_sign_hook_serialize(struct openchannel2_psbt_payload *payload,
				 struct json_stream *stream,
				 struct plugin *plugin)
{
	json_object_start(stream, "openchannel2_sign");
	json_add_psbt(stream, "psbt", payload->psbt);
	json_add_string(stream, "channel_id",
			type_to_string(tmpctx, struct channel_id,
				       &payload->channel->cid));
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

static void rbf_channel_remove_dualopend(struct subd *dualopend,
					 struct rbf_channel_payload *payload)
{
	assert(payload->dualopend == dualopend);
	payload->dualopend = NULL;
}

static void rbf_channel_hook_cb(struct rbf_channel_payload *payload STEALS)
{
	struct subd *dualopend = payload->dualopend;
	struct channel *channel = payload->channel;
	u8 *msg;

	tal_steal(tmpctx, payload);

	if (!dualopend)
		return;

	tal_del_destructor2(dualopend, rbf_channel_remove_dualopend, payload);

	if (channel->state != DUALOPEND_AWAITING_LOCKIN) {
		log_debug(channel->log,
			  "rbf_channel hook returned, but channel in state"
			  " %s", channel_state_name(channel));
		msg = towire_dualopend_fail(NULL, "Peer error. Channel"
					    " not ready for RBF attempt.");
		return subd_send_msg(dualopend, take(msg));
	}

	if (payload->err_msg) {
		log_debug(channel->log,
			  "rbf_channel hook rejects and says '%s'",
			  payload->err_msg);
		msg = towire_dualopend_fail(NULL, payload->err_msg);
		return subd_send_msg(dualopend, take(msg));
	}

	/* Update channel with new open attempt. */
	channel->open_attempt = new_channel_open_attempt(channel);
	msg = towire_dualopend_got_rbf_offer_reply(NULL,
						   payload->our_funding,
						   payload->psbt);
	subd_send_msg(dualopend, take(msg));
}



static bool
rbf_channel_hook_deserialize(struct rbf_channel_payload *payload,
			     const char *buffer,
			     const jsmntok_t *toks)
{
	struct subd *dualopend = payload->dualopend;
	struct channel *channel = payload->channel;

	if (!dualopend) {
		rbf_channel_hook_cb(payload);
		return false;
	}

	/* FIXME: move to new json extraction */
	const jsmntok_t *t_result = json_get_member(buffer, toks, "result");
	if (!t_result)
		fatal("Plugin returned an invalid response to the"
		      " rbf_channel hook: %.*s",
		      json_tok_full_len(toks),
		      json_tok_full(buffer, toks));

	if (json_tok_streq(buffer, t_result, "reject")) {
		if (json_get_member(buffer, toks, "psbt"))
			fatal("Plugin rejected rbf_channel but"
			      " also set `psbt`");
		if (json_get_member(buffer, toks, "our_funding_msat"))
			fatal("Plugin rejected rbf_channel but"
			      " also set `our_funding_msat`");

		const jsmntok_t *t_errmsg = json_get_member(buffer, toks,
							    "error_message");
		if (t_errmsg)
			payload->err_msg = json_strdup(payload, buffer,
						       t_errmsg);
		else
			payload->err_msg = "";

		rbf_channel_hook_cb(payload);
		return false;
	} else if (!json_tok_streq(buffer, t_result, "continue"))
		fatal("Plugin returned invalid response to rbf_channel hook:"
		      " %.*s", json_tok_full_len(toks),
		      json_tok_full(buffer, toks));

	if (!hook_extract_psbt(payload, dualopend, buffer, toks,
			       "rbf_channel", true, &payload->psbt))
		return false;

	if (payload->psbt) {
		enum tx_role our_role = channel->opener == LOCAL ?
					TX_INITIATOR : TX_ACCEPTER;
		psbt_add_serials(payload->psbt, our_role);
	}

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
	if (payload->psbt && !psbt_has_required_fields(payload->psbt))
		fatal("Plugin supplied PSBT that's missing"
		      " required fields: %s",
		      type_to_string(tmpctx, struct wally_psbt,
				     payload->psbt));
	if (!hook_extract_amount(dualopend, buffer, toks,
				 "our_funding_msat", &payload->our_funding))
		fatal("Plugin failed to supply our_funding_msat field");

	if (payload->psbt
	    && amount_sat_eq(payload->our_funding, AMOUNT_SAT(0)))
		fatal("Plugin failed to supply our_funding_msat field");

	if (!payload->psbt &&
		!amount_sat_eq(payload->our_funding, AMOUNT_SAT(0))) {

		log_broken(channel->log, "`our_funding_msat` returned"
			   " but no `psbt` present. %.*s",
			   json_tok_full_len(toks),
			   json_tok_full(buffer, toks));

		payload->err_msg = "Client error. Unable to continue";
		rbf_channel_hook_cb(payload);
		return false;
	}

	return true;
}

/* dualopend dies?  Remove dualopend ptr from payload */
static void openchannel2_remove_dualopend(struct subd *dualopend,
					  struct openchannel2_payload *payload)
{
	assert(payload->dualopend == dualopend);
	payload->dualopend = NULL;
}

static void
openchannel2_hook_cb(struct openchannel2_payload *payload STEALS)
{
	struct subd *dualopend = payload->dualopend;
	struct channel *channel = payload->channel;
	u8 *msg;

	/* Our daemon died! */
	if (!dualopend)
		return;

	/* Free payload regardless of what happens next */
	tal_steal(tmpctx, payload);

	channel = dualopend->channel;

	/* Channel open is currently in progress elsewhere! */
	if (channel->open_attempt) {
		msg = towire_dualopend_fail(NULL, "Already initiated channel"
					    " open");
		log_debug(dualopend->ld->log,
			  "Our open in progress, denying their offer");
		return subd_send_msg(dualopend, take(msg));
	}

	tal_del_destructor2(dualopend, openchannel2_remove_dualopend, payload);

	if (payload->err_msg) {
		log_debug(dualopend->ld->log,
			  "openchannel2 hook rejects and says '%s'",
			  payload->err_msg);
		msg = towire_dualopend_fail(NULL, payload->err_msg);
		return subd_send_msg(dualopend, take(msg));
	}

	channel->cid = payload->channel_id;
	channel->opener = REMOTE;
	channel->open_attempt = new_channel_open_attempt(channel);
	msg = towire_dualopend_got_offer_reply(NULL,
					       payload->accepter_funding,
					       payload->psbt,
					       payload->our_shutdown_scriptpubkey);

	subd_send_msg(dualopend, take(msg));
}


static bool
openchannel2_hook_deserialize(struct openchannel2_payload *payload,
			      const char *buffer,
			      const jsmntok_t *toks)
{
	const u8 *shutdown_script;
	struct subd *dualopend = payload->dualopend;

	/* If our daemon died, we're done */
	if (!dualopend) {
		openchannel2_hook_cb(payload);
		return false;
	}

	const jsmntok_t *t_result = json_get_member(buffer, toks, "result");
	if (!t_result)
		fatal("Plugin returned an invalid response to the"
		      " openchannel2 hook: %.*s",
		      json_tok_full_len(toks),
		      json_tok_full(buffer, toks));

	if (json_tok_streq(buffer, t_result, "reject")) {
		/* Should not have set any other fields if 'reject'ing */
		if (json_get_member(buffer, toks, "close_to"))
			fatal("Plugin rejected openchannel2 but"
			      " also set close_to");
		if (json_get_member(buffer, toks, "psbt"))
			fatal("Plugin rejected openchannel2 but"
			      " also set `psbt`");
		if (json_get_member(buffer, toks, "our_funding_msat"))
			fatal("Plugin rejected openchannel2 but"
			      " also set `our_funding_psbt`");

		const jsmntok_t *t_errmsg = json_get_member(buffer, toks,
							    "error_message");

		if (t_errmsg)
			payload->err_msg = json_strdup(payload,
						       buffer, t_errmsg);
		else
			payload->err_msg = "";

		openchannel2_hook_cb(payload);
		return false;
	} else if (!json_tok_streq(buffer, t_result, "continue"))
		fatal("Plugin returned an invalid response to the"
		      " openchannel2 hook: %.*s",
		      json_tok_full_len(toks),
		      json_tok_full(buffer, toks));

	if (!hook_extract_psbt(payload, dualopend, buffer, toks,
			       "openchannel2", true, &payload->psbt))
		return false;

	shutdown_script =
		hook_extract_shutdown_script(dualopend, buffer, toks);
	if (shutdown_script && payload->our_shutdown_scriptpubkey)
		log_broken(dualopend->ld->log,
			   "openchannel2 hook close_to address was"
			   " already set by other plugin. Ignoring!");
	else
		payload->our_shutdown_scriptpubkey = shutdown_script;

	/* Add a serial_id to everything that doesn't have one yet */
	if (payload->psbt)
		psbt_add_serials(payload->psbt, TX_ACCEPTER);

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
	if (payload->psbt && !psbt_has_required_fields(payload->psbt))
		fatal("Plugin supplied PSBT that's missing required fields. %s",
		      type_to_string(tmpctx, struct wally_psbt, payload->psbt));

	if (!hook_extract_amount(dualopend, buffer, toks,
				 "our_funding_msat",
				 &payload->accepter_funding))
		fatal("Plugin failed to supply our_funding_msat field");

	if (payload->psbt
	    && amount_sat_eq(payload->accepter_funding, AMOUNT_SAT(0)))
		fatal("Plugin failed to supply our_funding_msat field");

	if (!payload->psbt
	    && !amount_sat_eq(payload->accepter_funding, AMOUNT_SAT(0))) {
		/* Gotta give a PSBT if you set the accepter_funding amount */
		/* Let dualopend know we've failed */
		payload->err_msg = "Client error. Unable to continue";
		openchannel2_hook_cb(payload);
		return false;
	}

	return true;
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
			       toks, "openchannel2_changed",
			       false, &psbt))
		return false;

	/* Add serials to PSBT, before checking for required fields */
	psbt_add_serials(psbt, TX_ACCEPTER);

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
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

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
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
	struct channel *channel = payload->channel;
	struct channel_inflight *inflight;
	struct bitcoin_txid txid;
	u8 *msg;

	/* Whatever happens, we free the payload */
	tal_steal(tmpctx, payload);

	/* Finalize it, if not already. It shouldn't work entirely */
	psbt_finalize(payload->psbt);

	if (!psbt_side_finalized(payload->psbt, TX_ACCEPTER)) {
		log_broken(channel->log,
			   "Plugin must return a 'psbt' with signatures "
			   "for their inputs %s",
			   type_to_string(tmpctx,
					  struct wally_psbt,
					  payload->psbt));
		msg = towire_dualopend_fail(NULL, "Peer error with PSBT"
					    " signatures.");
		goto send_msg;
	}

	inflight = channel_current_inflight(channel);
	if (!inflight) {
		log_broken(channel->log,
			   "No current channel inflight");
		msg = towire_dualopend_fail(NULL, "No current channel inflight");
		goto send_msg;
	}

	/* Check that we've got the same / correct PSBT */
	psbt_txid(NULL, payload->psbt, &txid, NULL);
	if (!bitcoin_txid_eq(&inflight->funding->txid, &txid)) {
		log_broken(channel->log,
			   "PSBT's txid does not match. %s != %s",
			   type_to_string(tmpctx, struct bitcoin_txid,
					  &txid),
			   type_to_string(tmpctx, struct bitcoin_txid,
					  &inflight->funding->txid));
		msg = towire_dualopend_fail(NULL, "Peer error with PSBT"
					    " signatures.");
		goto send_msg;
	}

	/* Now that we've got the signed PSBT, save it */
	tal_free(inflight->funding_psbt);
	inflight->funding_psbt = tal_steal(inflight,
					   cast_const(struct wally_psbt *,
						      payload->psbt));
	wallet_inflight_save(payload->ld->wallet, inflight);
	channel_watch_funding(payload->ld, channel);
	msg = towire_dualopend_send_tx_sigs(NULL, inflight->funding_psbt);

send_msg:
	/* Peer's gone away, let's try reconnecting */
	if (!payload->dualopend) {
		channel_saved_err_broken_reconn(channel,
						"dualopend daemon died"
						" before signed PSBT returned");
		return;
	}
	tal_del_destructor2(payload->dualopend,
			    openchannel2_psbt_remove_dualopend,
			    payload);

	/* Send peer our signatures */
	subd_send_msg(payload->dualopend, take(msg));
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

REGISTER_PLUGIN_HOOK(rbf_channel,
		     rbf_channel_hook_deserialize,
		     rbf_channel_hook_cb,
		     rbf_channel_hook_serialize,
		     struct rbf_channel_payload *);

static bool feerate_satisfied(struct wally_psbt *psbt,
			      u32 funding_feerate)
{
	struct wally_tx *wtx;
	size_t tx_weight;
	struct amount_sat fee_paid, expected_fee;

	wtx = psbt_final_tx(NULL, psbt);
	tx_weight = wally_tx_weight(wtx);
	tal_free(wtx);

	fee_paid = psbt_compute_fee(psbt);
	expected_fee = amount_tx_fee(funding_feerate, tx_weight);

	return amount_sat_greater_eq(fee_paid, expected_fee);
}

static struct amount_sat calculate_reserve(struct channel_config *their_config,
					   struct amount_sat funding_total,
					   enum side opener)
{
	struct amount_sat reserve, dust_limit;

	/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2
	 *
	 * The channel reserve is fixed at 1% of the total channel balance
	 * rounded down (sum of `funding_satoshis` from `open_channel2`
	 * and `accept_channel2`) or the `dust_limit_satoshis` from
	 * `open_channel2`, whichever is greater.
	 */
	reserve = amount_sat_div(funding_total, 100);
	dust_limit = opener == LOCAL ?
		chainparams->dust_limit :
		their_config->dust_limit;

	if (amount_sat_greater(dust_limit, reserve))
		return dust_limit;

	return reserve;
}

void channel_update_reserve(struct channel *channel,
			    struct channel_config *their_config,
			    struct amount_sat funding_total)
{
	struct amount_sat reserve;

	reserve = calculate_reserve(their_config,
				    funding_total,
				    channel->opener);

	/* Depending on path, these are disjoint */
	their_config->channel_reserve = reserve;
	channel->channel_info.their_config.channel_reserve = reserve;
	channel->our_config.channel_reserve = reserve;
}

/* Steals fields from uncommitted_channel: returns NULL if can't generate a
 * key for this channel (shouldn't happen!). */
static struct channel_inflight *
wallet_update_channel(struct lightningd *ld,
		      struct channel *channel,
		      struct bitcoin_tx *remote_commit STEALS,
		      struct bitcoin_signature *remote_commit_sig,
		      const struct bitcoin_txid *funding_txid,
		      u16 funding_outnum,
		      struct amount_sat total_funding,
		      struct amount_sat our_funding,
		      u32 funding_feerate,
		      struct wally_psbt *psbt STEALS)
{
	struct amount_msat our_msat;
	struct channel_inflight *inflight;

	if (!amount_sat_to_msat(&our_msat, our_funding)) {
		log_broken(channel->log, "Unable to convert funds");
		return NULL;
	}

	assert(channel->unsaved_dbid == 0);
	assert(channel->dbid != 0);

	channel->funding_txid = *funding_txid;
	channel->funding_outnum = funding_outnum;
	channel->funding = total_funding;
	channel->our_funds = our_funding;
	channel->our_msat = our_msat;
	channel->msat_to_us_min = our_msat;
	channel->msat_to_us_max = our_msat;

	channel_set_last_tx(channel,
			    tal_steal(channel, remote_commit),
			    remote_commit_sig,
			    TX_CHANNEL_UNILATERAL);

	/* Update in database */
	wallet_channel_save(ld->wallet, channel);

	/* Add open attempt to channel's inflights */
	inflight = new_inflight(channel,
				channel->funding_txid,
				channel->funding_outnum,
				funding_feerate,
				channel->funding,
				channel->our_funds,
				psbt,
				channel->last_tx,
				channel->last_sig);
	wallet_inflight_add(ld->wallet, inflight);

	return inflight;
}

/* Returns NULL if can't generate a key for this channel (Shouldn't happen) */
static struct channel_inflight *
wallet_commit_channel(struct lightningd *ld,
		      struct channel *channel,
		      struct bitcoin_tx *remote_commit,
		      struct bitcoin_signature *remote_commit_sig,
		      const struct bitcoin_txid *funding_txid,
		      u16 funding_outnum,
		      struct amount_sat total_funding,
		      struct amount_sat our_funding,
		      struct channel_info *channel_info,
		      u32 funding_feerate,
		      u32 commitment_feerate,
		      const u8 *our_upfront_shutdown_script,
		      const u8 *remote_upfront_shutdown_script,
		      struct wally_psbt *psbt STEALS)
{
	struct amount_msat our_msat;
	struct channel_inflight *inflight;

	if (!amount_sat_to_msat(&our_msat, our_funding)) {
		log_broken(channel->log, "Unable to convert funds");
		return NULL;
	}

	/* Get a key to use for closing outputs from this tx */
	channel->final_key_idx = wallet_get_newindex(ld);
	if (channel->final_key_idx == -1) {
		log_broken(channel->log, "Can't get final key index");
		return NULL;
	}

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info->their_config.id = 0;
	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* Promote the unsaved_dbid to the dbid */
	assert(channel->unsaved_dbid != 0);
	channel->dbid = channel->unsaved_dbid;
	channel->unsaved_dbid = 0;

	channel->funding_txid = *funding_txid;
	channel->funding_outnum = funding_outnum;
	channel->funding = total_funding;
	channel->our_funds = our_funding;
	channel->our_msat = our_msat;
	channel->msat_to_us_min = our_msat;
	channel->msat_to_us_max = our_msat;

	channel->last_tx = tal_steal(channel, remote_commit);
	channel->last_sig = *remote_commit_sig;
	channel->last_tx_type = TX_CHANNEL_UNILATERAL;

	channel->channel_info = *channel_info;
	channel->fee_states = new_fee_states(channel,
					     channel->opener,
					     &commitment_feerate);
	channel->min_possible_feerate = commitment_feerate;
	channel->max_possible_feerate = commitment_feerate;

	/* We are connected */
	channel->connected = true;

	if (our_upfront_shutdown_script)
		channel->shutdown_scriptpubkey[LOCAL]
			= tal_steal(channel, our_upfront_shutdown_script);
	else
		channel->shutdown_scriptpubkey[LOCAL]
			= p2wpkh_for_keyidx(channel, channel->peer->ld,
					    channel->final_key_idx);

	channel->remote_upfront_shutdown_script
		= tal_steal(channel, remote_upfront_shutdown_script);

	channel->state_change_cause = (channel->opener == LOCAL) ?
					REASON_USER : REASON_REMOTE;

	/* If we're fundee, could be a little before this
	 * in theory, but it's only used for timing out. */
	channel->first_blocknum = get_block_height(ld->topology);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	/* Open attempt to channel's inflights */
	inflight = new_inflight(channel,
				channel->funding_txid,
				channel->funding_outnum,
				funding_feerate,
				channel->funding,
				channel->our_funds,
				psbt,
				channel->last_tx,
				channel->last_sig);
	wallet_inflight_add(ld->wallet, inflight);

	return inflight;
}

static void handle_peer_wants_to_close(struct subd *dualopend,
				       const u8 *msg)
{
	u8 *scriptpubkey;
	struct lightningd *ld = dualopend->ld;
	struct channel *channel = dualopend->channel;
	char *errmsg;
	bool anysegwit = feature_negotiated(ld->our_features,
					    channel->peer->their_features,
					    OPT_SHUTDOWN_ANYSEGWIT);

	/* We shouldn't get this message while we're waiting to finish */
	if (channel_unsaved(channel)) {
		log_broken(dualopend->ld->log, "Channel in wrong state for"
		           " shutdown, still has uncommitted"
		           " channel pending.");

		errmsg = "Channel not established yet, shutdown invalid";
		subd_send_msg(dualopend,
			      take(towire_dualopend_fail(NULL, errmsg)));
		return;
	}

	if (!fromwire_dualopend_got_shutdown(channel, msg, &scriptpubkey)) {
		channel_internal_error(channel,
				       "Bad DUALOPEND_GOT_SHUTDOWN: %s",
				       tal_hex(msg, msg));
		return;
	}


	tal_free(channel->shutdown_scriptpubkey[REMOTE]);
	channel->shutdown_scriptpubkey[REMOTE] = scriptpubkey;

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *  - if the `scriptpubkey` is not in one of the above forms:
	 *    - SHOULD fail the connection.
	 */
	if (!valid_shutdown_scriptpubkey(scriptpubkey, anysegwit)) {
		channel_fail_permanent(channel,
				       REASON_PROTOCOL,
				       "Bad shutdown scriptpubkey %s",
				       tal_hex(channel, scriptpubkey));
		return;
	}

	/* If we weren't already shutting down, we are now */
	if (channel->state != CHANNELD_SHUTTING_DOWN)
		channel_set_state(channel,
				  channel->state,
				  CHANNELD_SHUTTING_DOWN,
				  REASON_REMOTE,
				  "Peer closes channel");

	/* TODO(cdecker) Selectively save updated fields to DB */
	wallet_channel_save(ld->wallet, channel);

	/* Now we send back our scriptpubkey to close with */
	subd_send_msg(dualopend, take(towire_dualopend_send_shutdown(NULL,
				      channel->shutdown_scriptpubkey[LOCAL])));

}

static void handle_channel_closed(struct subd *dualopend,
				  const int *fds,
				  const u8 *msg)
{
	struct per_peer_state *pps;
	struct channel *channel = dualopend->channel;

	if (!fromwire_dualopend_shutdown_complete(tmpctx, msg, &pps)) {
		channel_internal_error(dualopend->channel,
				       "Bad DUALOPEND_SHUTDOWN_COMPLETE: %s",
				       tal_hex(msg, msg));
		close(fds[0]);
		close(fds[1]);
		close(fds[2]);
		return;
	}

	per_peer_state_set_fds_arr(pps, fds);

	peer_start_closingd(channel, pps, false, NULL);
	channel_set_state(channel,
			  CHANNELD_SHUTTING_DOWN,
			  CLOSINGD_SIGEXCHANGE,
			  REASON_UNKNOWN,
			  "Start closingd");
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
		log_unusual(channel->log,
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
		json_add_channel_id(response, "channel_id", &channel->cid);
		was_pending(command_success(cmd, response));
	}

	tal_free(cs);
}


static void send_funding_tx(struct channel *channel,
			    const struct wally_tx *wtx TAKES)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_send *cs;
	struct bitcoin_txid txid;

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

	wally_txid(wtx, &txid);
	log_debug(channel->log,
		  "Broadcasting funding tx %s for channel %s. %s",
		  type_to_string(tmpctx, struct bitcoin_txid, &txid),
		  type_to_string(tmpctx, struct channel_id, &channel->cid),
		  type_to_string(tmpctx, struct wally_tx, cs->wtx));

	bitcoind_sendrawtx(ld->topology->bitcoind,
			   tal_hex(tmpctx, linearize_wtx(tmpctx, cs->wtx)),
			   sendfunding_done, cs);
}

static void handle_peer_tx_sigs_sent(struct subd *dualopend,
				     const int *fds,
				     const u8 *msg)
{
	struct channel *channel = dualopend->channel;
	struct channel_inflight *inflight;
	const struct wally_tx *wtx;

	if (!fromwire_dualopend_tx_sigs_sent(msg)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_TX_SIGS_SENT: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	inflight = channel_current_inflight(channel);
	if (!inflight) {
		channel_internal_error(channel,
				       "No inflight found for channel %s",
				       type_to_string(tmpctx, struct channel,
						      channel));
		return;
	}

	/* Once we've sent our sigs to the peer, we're fine
	 * to broadcast the transaction, even if they haven't
	 * sent us their tx-sigs yet. They're not allowed to
	 * send us funding-locked until their tx-sigs has been
	 * received, but that's no reason not to broadcast.
	 * Note this only happens if we're the only input-er */
	if (psbt_finalize(inflight->funding_psbt) &&
	    !inflight->tx_broadcast) {
		inflight->tx_broadcast = true;

		wtx = psbt_final_tx(NULL, inflight->funding_psbt);
		if (!wtx) {
			channel_internal_error(channel,
					       "Unable to extract final tx"
					       " from PSBT %s",
					       type_to_string(tmpctx,
							      struct wally_psbt,
							      inflight->funding_psbt));
			return;
		}

		/* Saves the now finalized version of the psbt */
		wallet_inflight_save(dualopend->ld->wallet, inflight);
		send_funding_tx(channel, take(wtx));

		/* Must be in an "init" state */
		assert(channel->state == DUALOPEND_OPEN_INIT
		       || channel->state == DUALOPEND_AWAITING_LOCKIN);

		channel_set_state(channel, channel->state,
				  DUALOPEND_AWAITING_LOCKIN,
				  REASON_UNKNOWN,
				  "Sigs exchanged, waiting for lock-in");

		/* Mimic the old behavior, notify a channel has been opened,
		 * for the accepter side */
		if (channel->opener == REMOTE)
			/* Tell plugins about the success */
			notify_channel_opened(dualopend->ld,
					      &channel->peer->id,
					      &channel->funding,
					      &channel->funding_txid,
					      &channel->remote_funding_locked);

		/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2
		 * The receiving node:  ...
		 * - MUST fail the channel if:
		 *   - the `witness_stack` weight lowers the
		 *   effective `feerate` below the agreed upon
		 *   transaction `feerate`
		 */
		if (!feerate_satisfied(inflight->funding_psbt,
				       inflight->funding->feerate)) {
			char *errmsg = tal_fmt(tmpctx,
					       "Witnesses lower effective"
					       " feerate below agreed upon rate"
					       " of %dperkw. Failing channel."
					       " Offending PSBT: %s",
					       inflight->funding->feerate,
					       type_to_string(tmpctx,
						      struct wally_psbt,
						      inflight->funding_psbt));

			/* Notify the peer we're failing */
			subd_send_msg(dualopend,
				      take(towire_dualopend_fail(NULL, errmsg)));
		}
	}
}

static void handle_peer_locked(struct subd *dualopend, const u8 *msg)
{
	struct pubkey remote_per_commit;
	struct channel *channel = dualopend->channel;

	if (!fromwire_dualopend_peer_locked(msg, &remote_per_commit)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_PEER_LOCKED: %s",
				       tal_hex(msg, msg));
		return;
	}

	/* Updates channel with the next per-commit point etc, calls
	 * channel_internal_error on failure */
	if (!channel_on_funding_locked(channel, &remote_per_commit))
		return;

	/* Remember that we got the lock-in */
	wallet_channel_save(dualopend->ld->wallet, channel);
}

static void handle_channel_locked(struct subd *dualopend,
				  const int *fds,
				  const u8 *msg)
{
	struct channel *channel = dualopend->channel;
	struct per_peer_state *pps;

	if (!fromwire_dualopend_channel_locked(tmpctx, msg, &pps)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_CHANNEL_LOCKED: %s",
				       tal_hex(msg, msg));
		return;
	}
	per_peer_state_set_fds_arr(pps, fds);

	assert(channel->scid);
	assert(channel->remote_funding_locked);

	/* This can happen if we missed their sigs, for some reason */
	if (channel->state != DUALOPEND_AWAITING_LOCKIN)
		log_debug(channel->log, "Lockin complete, but state %s",
			  channel_state_name(channel));

	channel_set_state(channel,
			  channel->state,
			  CHANNELD_NORMAL,
			  REASON_UNKNOWN,
			  "Lockin complete");
	channel_record_open(channel);

	/* Empty out the inflights */
	wallet_channel_clear_inflights(dualopend->ld->wallet, channel);

	/* FIXME: LND sigs/update_fee msgs? */
	peer_start_channeld(channel, pps, NULL, false);
	return;
}

void dualopen_tell_depth(struct subd *dualopend,
			 struct channel *channel,
			 const struct bitcoin_txid *txid,
			 u32 depth)
{
	const u8 *msg;
	u32 to_go;

	if (depth < channel->minimum_depth) {
		to_go = channel->minimum_depth - depth;
	} else
		to_go = 0;

	/* Are we there yet? */
	if (to_go == 0) {
		assert(channel->scid);
		assert(bitcoin_txid_eq(&channel->funding_txid, txid));

		channel_set_billboard(channel, false,
				      tal_fmt(tmpctx, "Funding depth reached"
					      " %d confirmations, alerting peer"
					      " we're locked-in.",
					      to_go));

		msg = towire_dualopend_depth_reached(NULL, depth);
		subd_send_msg(dualopend, take(msg));
	} else
		channel_set_billboard(channel, false,
				      tal_fmt(tmpctx, "Funding needs %d more"
					      " confirmations for lockin.",
					      to_go));
}

static void rbf_got_offer(struct subd *dualopend, const u8 *msg)
{
	/* We expect the channel to still exist?! */
	struct channel *channel;
	struct rbf_channel_payload *payload;

	channel = dualopend->channel;

	payload = tal(dualopend, struct rbf_channel_payload);
	payload->dualopend = dualopend;
	payload->channel = channel;

	if (!fromwire_dualopend_got_rbf_offer(msg,
					      &payload->channel_id,
					      &payload->their_funding,
					      &payload->funding_feerate_per_kw,
					      &payload->locktime)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_GOT_RBF_OFFER: %s",
				       tal_hex(msg, msg));
		return;
	}

	/* There's currently another attempt in progress? */
	if (channel->open_attempt) {
		log_debug(channel->log,
			  "RBF attempted while previous attempt"
			  " is still in progress");

		subd_send_msg(dualopend,
			      take(towire_dualopend_fail(NULL,
					"Error. Already negotiation"
					" in progress")));
		return;
	}

	assert(channel_id_eq(&channel->cid, &payload->channel_id));
	/* Fill in general channel info from channel */
	payload->peer_id = channel->peer->id;
	payload->feerate_our_max = feerate_max(dualopend->ld, NULL);
	payload->feerate_our_min = feerate_min(dualopend->ld, NULL);

	/* Set our contributions to empty, in case there is no plugin */
	payload->our_funding = AMOUNT_SAT(0);
	payload->psbt = NULL;

	/* No error message known (yet) */
	payload->err_msg = NULL;

	payload->channel_max = chainparams->max_funding;
	if (feature_negotiated(dualopend->ld->our_features,
			       channel->peer->their_features,
			       OPT_LARGE_CHANNELS))
		payload->channel_max = AMOUNT_SAT(UINT_MAX);

	tal_add_destructor2(dualopend, rbf_channel_remove_dualopend, payload);
	plugin_hook_call_rbf_channel(dualopend->ld, payload);
}

static void accepter_got_offer(struct subd *dualopend,
			       struct channel *channel,
			       const u8 *msg)
{
	struct openchannel2_payload *payload;

	if (peer_active_channel(channel->peer)) {
		subd_send_msg(dualopend,
				take(towire_dualopend_fail(NULL,
					"Already have active channel")));
		return;
	}

	if (channel->open_attempt) {
		subd_send_msg(dualopend,
				take(towire_dualopend_fail(NULL,
					"Already initiated channel open")));
		return;
	}

	payload = tal(dualopend, struct openchannel2_payload);
	payload->dualopend = dualopend;
	payload->channel = channel;
	payload->psbt = NULL;
	payload->accepter_funding = AMOUNT_SAT(0);
	payload->our_shutdown_scriptpubkey = NULL;
	payload->peer_id = channel->peer->id;
	payload->err_msg = NULL;

	if (!fromwire_dualopend_got_offer(payload, msg,
					  &payload->channel_id,
					  &payload->their_funding,
					  &payload->dust_limit_satoshis,
					  &payload->max_htlc_value_in_flight_msat,
					  &payload->htlc_minimum_msat,
					  &payload->funding_feerate_per_kw,
					  &payload->commitment_feerate_per_kw,
					  &payload->to_self_delay,
					  &payload->max_accepted_htlcs,
					  &payload->channel_flags,
					  &payload->locktime,
					  &payload->shutdown_scriptpubkey)) {
		channel_internal_error(channel, "Bad DUALOPEND_GOT_OFFER: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* As a convenience to the plugin, we provide our current known
	 * min + max feerates. Ideally, the plugin will fail to
	 * contribute funds if the peer's feerate range is outside of
	 * this acceptable range, but we delegate that decision to
	 * the plugin */
	payload->feerate_our_min = feerate_min(dualopend->ld, NULL);
	payload->feerate_our_max = feerate_max(dualopend->ld, NULL);

	payload->channel_max = chainparams->max_funding;
	if (feature_negotiated(dualopend->ld->our_features,
			       channel->peer->their_features,
			       OPT_LARGE_CHANNELS))
		payload->channel_max = AMOUNT_SAT(UINT64_MAX);

	tal_add_destructor2(dualopend, openchannel2_remove_dualopend, payload);
	plugin_hook_call_openchannel2(dualopend->ld, payload);
}

static void handle_peer_tx_sigs_msg(struct subd *dualopend,
				    const u8 *msg)
{
	struct wally_psbt *psbt;
	const struct wally_tx *wtx;
	struct lightningd *ld = dualopend->ld;
	struct channel *channel = dualopend->channel;
	struct channel_inflight *inflight;

	if (!fromwire_dualopend_funding_sigs(tmpctx, msg, &psbt)) {
		channel_internal_error(channel,
				       "Bad DUALOPEND_FUNDING_SIGS: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	inflight = channel_current_inflight(channel);
	if (!inflight) {
		channel_internal_error(channel,
				       "No inflight found for channel %s",
				       type_to_string(tmpctx, struct channel,
						      channel));
		return;
	}

	/* Save that we've gotten their sigs. Sometimes
	 * the peer doesn't send any sigs (no inputs), otherwise
	 * we could just check the PSBT was finalized */
	inflight->remote_tx_sigs = true;
	tal_wally_start();
	if (wally_psbt_combine(inflight->funding_psbt, psbt) != WALLY_OK) {
		channel_internal_error(channel,
				       "Unable to combine PSBTs: %s, %s",
				       type_to_string(tmpctx,
						      struct wally_psbt,
						      inflight->funding_psbt),
				       type_to_string(tmpctx,
						      struct wally_psbt,
						      psbt));
		tal_wally_end(inflight->funding_psbt);
		return;
	}
	tal_wally_end(inflight->funding_psbt);
	wallet_inflight_save(ld->wallet, inflight);

	/* It's possible we haven't sent them our (empty) tx-sigs yet,
	 * but we should be sending it soon... */
	if (psbt_finalize(cast_const(struct wally_psbt *,
			  inflight->funding_psbt))
	    && !inflight->tx_broadcast) {
		inflight->tx_broadcast = true;

		/* Saves the now finalized version of the psbt */
		wallet_inflight_save(ld->wallet, inflight);
		wtx = psbt_final_tx(NULL, inflight->funding_psbt);
		if (!wtx) {
			channel_internal_error(channel,
					       "Unable to extract final tx"
					       " from PSBT %s",
					       type_to_string(tmpctx,
							      struct wally_psbt,
							      inflight->funding_psbt));
			return;
		}

		send_funding_tx(channel, take(wtx));

		assert(channel->state == DUALOPEND_OPEN_INIT
		       /* We might be reconnecting */
		       || channel->state == DUALOPEND_AWAITING_LOCKIN);
		channel_set_state(channel, channel->state,
				  DUALOPEND_AWAITING_LOCKIN,
				  REASON_UNKNOWN,
				  "Sigs exchanged, waiting for lock-in");

		/* Mimic the old behavior, notify a channel has been opened,
		 * for the accepter side */
		if (channel->opener == REMOTE)
			/* Tell plugins about the success */
			notify_channel_opened(dualopend->ld,
					      &channel->peer->id,
					      &channel->funding,
					      &channel->funding_txid,
					      &channel->remote_funding_locked);

		/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2
		 * The receiving node:  ...
		 * - MUST fail the channel if:
		 *   - the `witness_stack` weight lowers the
		 *   effective `feerate` below the agreed upon
		 *   transaction `feerate`
		 */
		if (!feerate_satisfied(inflight->funding_psbt,
				       inflight->funding->feerate)) {
			char *errmsg = tal_fmt(tmpctx,
					       "Witnesses lower effective"
					       " feerate below agreed upon rate"
					       " of %dperkw. Failing channel."
					       " Offending PSBT: %s",
					       inflight->funding->feerate,
					       type_to_string(tmpctx,
						      struct wally_psbt,
						      inflight->funding_psbt));

			/* Notify the peer we're failing */
			subd_send_msg(dualopend,
				      take(towire_dualopend_fail(NULL, errmsg)));
		}
	}

	/* Send notification with peer's signed PSBT */
	notify_openchannel_peer_sigs(ld, &channel->cid,
				     inflight->funding_psbt);
}

static void handle_validate_rbf(struct subd *dualopend,
				const u8 *msg)
{
	struct wally_psbt *candidate_psbt;
	struct channel_inflight *inflight;
	struct channel *channel = dualopend->channel;
	bool *inputs_present;
	struct amount_sat candidate_fee, last_fee;

	if (!fromwire_dualopend_rbf_validate(tmpctx, msg,
					     &candidate_psbt)) {
		channel_internal_error(channel,
				       "Bad DUALOPEND_RBF_VALIDATE: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	inputs_present = tal_arr(tmpctx, bool, candidate_psbt->num_inputs);
	memset(inputs_present, true, tal_bytelen(inputs_present));

	/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
	 * The receiving node: ...
	 *    - MUST fail the negotiation if: ...
	 *    - the transaction does not share a common input with
	 *    all previous funding transactions
	 */
	list_for_each(&channel->inflights, inflight, list) {
		/* Remove every non-matching input from set */
		for (size_t i = 0; i < candidate_psbt->num_inputs; i++) {
			struct wally_tx_input *input =
				&candidate_psbt->tx->inputs[i];
			struct bitcoin_txid in_txid;

			wally_tx_input_get_txid(input, &in_txid);

			if (!psbt_has_input(inflight->funding_psbt,
					    &in_txid, input->index))
				inputs_present[i] = false;
		}
	}

	/* Are there any inputs that were present on all txs? */
	if (memeqzero(inputs_present, tal_bytelen(inputs_present))) {
		char *errmsg;

		inflight = list_tail(&channel->inflights,
				     struct channel_inflight,
				     list);
		assert(inflight);

		errmsg = tal_fmt(tmpctx, "No overlapping input"
				 " present. New: %s, last: %s",
				 type_to_string(tmpctx,
						struct wally_psbt,
						candidate_psbt),
				 type_to_string(tmpctx,
						struct wally_psbt,
						inflight->funding_psbt));
		msg = towire_dualopend_fail(NULL, errmsg);
		goto send_msg;
	}

	candidate_fee = psbt_compute_fee(candidate_psbt);

	inflight = list_tail(&channel->inflights,
			     struct channel_inflight,
			     list);
	assert(inflight);
	last_fee = psbt_compute_fee(inflight->funding_psbt);

	/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
	 * The receiving node: ...
	 * - if is an RBF attempt:
	 *   - MUST fail the negotiation if:
	 *   - the transaction's total fees is less than the last
	 *   successfully negotiated transaction's fees
	 */
	if (!amount_sat_greater(candidate_fee, last_fee)) {
		char *errmsg = tal_fmt(tmpctx, "Proposed funding tx fee (%s)"
				       " less than/equal to last (%s)",
				       type_to_string(tmpctx,
						      struct amount_sat,
						      &candidate_fee),
				       type_to_string(tmpctx,
						      struct amount_sat,
						      &last_fee));
		msg = towire_dualopend_fail(NULL, errmsg);
		goto send_msg;
	}

	msg = towire_dualopend_rbf_valid(NULL);

send_msg:
	subd_send_msg(channel->owner, take(msg));
}

static struct command_result *
json_openchannel_abort(struct command *cmd,
		       const char *buffer,
		       const jsmntok_t *obj UNNEEDED,
		       const jsmntok_t *params)
{
	struct channel_id *cid;
	struct channel *channel;
	u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("channel_id", param_channel_id, &cid),
		   NULL))
		return command_param_failed();

	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    type_to_string(tmpctx, struct channel_id,
						   cid));

	if (!channel->owner)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");

	if (!channel->open_attempt) {
		if (list_empty(&channel->inflights))
			return command_fail(cmd, FUNDING_STATE_INVALID,
					    "Channel open not in progress");
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Sigs already exchanged, can't cancel");
	}

	if (channel->open_attempt->cmd)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Another openchannel command"
				    " is in progress");

	if (channel->openchannel_signed_cmd)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Already sent sigs, waiting for peer's");

	/* Mark it as aborted so when we clean-up, we send the
	 * correct response */
	channel->open_attempt->aborted = true;
	channel->open_attempt->cmd = cmd;

	/* Tell dualopend to fail this channel */
	msg = towire_dualopend_fail(NULL, "Abort requested");
	subd_send_msg(channel->owner, take(msg));

	return command_still_pending(cmd);
}

static struct command_result *
json_openchannel_bump(struct command *cmd,
		      const char *buffer,
		      const jsmntok_t *obj UNNEEDED,
		      const jsmntok_t *params)
{
	struct channel_id *cid;
	struct channel *channel;
	struct amount_sat *amount, psbt_val;
	struct wally_psbt *psbt;
	struct open_attempt *oa;

	if (!param(cmd, buffer, params,
		   p_req("channel_id", param_channel_id, &cid),
		   p_req("amount", param_sat, &amount),
		   p_req("initialpsbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	psbt_val = AMOUNT_SAT(0);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct amount_sat in_amt = psbt_input_get_amount(psbt, i);
		if (!amount_sat_add(&psbt_val, psbt_val, in_amt))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Overflow in adding PSBT input"
					    " values. %s",
					    type_to_string(tmpctx,
							   struct wally_psbt,
							   psbt));
	}

	/* If they don't pass in at least enough in the PSBT to cover
	 * their amount, nope */
	if (!amount_sat_greater(psbt_val, *amount))
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Provided PSBT cannot afford funding of "
				    "amount %s. %s",
				    type_to_string(tmpctx,
						   struct amount_sat,
						   amount),
				    type_to_string(tmpctx,
						   struct wally_psbt,
						   psbt));

	if (!topology_synced(cmd->ld->topology)) {
		return command_fail(cmd, FUNDING_STILL_SYNCING_BITCOIN,
				    "Still syncing with bitcoin network");
	}

	/* Are we in a state where we can attempt an RBF? */
	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    type_to_string(tmpctx, struct channel_id,
						   cid));

	/* BOLT #2:
	 *  - if both nodes advertised `option_support_large_channel`:
	 *    - MAY set `funding_satoshis` greater than or equal to 2^24 satoshi.
	 *  - otherwise:
	 *    - MUST set `funding_satoshis` to less than 2^24 satoshi.
	 */
	if (!feature_negotiated(cmd->ld->our_features,
				channel->peer->their_features,
				OPT_LARGE_CHANNELS)
	    && amount_sat_greater(*amount, chainparams->max_funding))
		return command_fail(cmd, FUND_MAX_EXCEEDED,
				    "Amount exceeded %s",
				    type_to_string(tmpctx, struct amount_sat,
						   &chainparams->max_funding));

	if (!channel->owner)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				      "Peer not connected.");

	if (channel->open_attempt)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Commitments for this channel not "
				    "secured, see `openchannel_update`");

	if (channel->state != DUALOPEND_AWAITING_LOCKIN)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Channel not eligible to init RBF."
				    " Current state %s, expected state %s",
				    channel_state_name(channel),
				    channel_state_str(DUALOPEND_AWAITING_LOCKIN));
	if (channel->opener != LOCAL)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Only the channel opener can initiate an"
				    " RBF attempt");

	/* Ok, we're kosher to start */
	channel->open_attempt = oa = new_channel_open_attempt(channel);
	oa->funding = *amount;
	oa->cmd = cmd;
	oa->our_upfront_shutdown_script
		= channel->shutdown_scriptpubkey[LOCAL];

	/* Add serials to any input that's missing them */
	psbt_add_serials(psbt, TX_INITIATOR);

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
	if (!psbt_has_required_fields(psbt))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "PSBT is missing required fields %s",
				    type_to_string(tmpctx, struct wally_psbt,
						   psbt));

	subd_send_msg(channel->owner,
		      take(towire_dualopend_rbf_init(NULL, *amount, psbt)));
	return command_still_pending(cmd);
}

static struct command_result *
json_openchannel_signed(struct command *cmd,
			 const char *buffer,
			 const jsmntok_t *obj UNNEEDED,
			 const jsmntok_t *params)
{
	struct wally_psbt *psbt;
	struct channel_id *cid;
	struct channel *channel;
	struct bitcoin_txid txid;
	struct channel_inflight *inflight;

	if (!param(cmd, buffer, params,
		   p_req("channel_id", param_channel_id, &cid),
		   p_req("signed_psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel");
	if (!channel->owner)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");

	if (channel->open_attempt)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Commitments for this channel not "
				    "yet secured, see `openchannel_update`");

	if (list_empty(&channel->inflights))
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Channel open not initialized yet.");

	if (channel->openchannel_signed_cmd)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Already sent sigs, waiting for peer's");

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

	inflight = list_tail(&channel->inflights,
			     struct channel_inflight,
			     list);
	if (!inflight)
		return command_fail(cmd, LIGHTNINGD,
				    "Open attempt for channel not found");

	if (!bitcoin_txid_eq(&txid, &inflight->funding->txid))
		return command_fail(cmd, LIGHTNINGD,
				    "Current inflight transaction is %s,"
				    " not %s",
				    type_to_string(tmpctx, struct bitcoin_txid,
						   &txid),
				    type_to_string(tmpctx, struct bitcoin_txid,
						   &inflight->funding->txid));

	if (inflight->funding_psbt && psbt_is_finalized(inflight->funding_psbt))
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Already have a finalized PSBT for "
				    "this channel");

	/* Go ahead and try to finalize things, or what we can */
	psbt_finalize(psbt);

	/* Check that all of *our* outputs are finalized */
	if (!psbt_side_finalized(psbt, channel->opener == LOCAL ?
					TX_INITIATOR : TX_ACCEPTER))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Local PSBT input(s) not finalized");

	/* Now that we've got the signed PSBT, save it */
	tal_wally_start();
	if (wally_psbt_combine(cast_const(struct wally_psbt *,
					  inflight->funding_psbt),
			       psbt) != WALLY_OK) {
		tal_wally_end(tal_free(inflight->funding_psbt));
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Failed adding sigs");
	}

	/* Make memleak happy, (otherwise cleaned up with `cmd`) */
	tal_free(psbt);
	tal_wally_end(tal_steal(inflight, inflight->funding_psbt));

	/* Update the PSBT on disk */
	wallet_inflight_save(cmd->ld->wallet, inflight);
	/* Uses the channel->funding_txid, which we verified above */
	channel_watch_funding(cmd->ld, channel);

	/* Send our tx_sigs to the peer */
	subd_send_msg(channel->owner,
		      take(towire_dualopend_send_tx_sigs(NULL,
							 inflight->funding_psbt)));

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
	u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("channel_id", param_channel_id, &cid),
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    type_to_string(tmpctx, struct channel_id,
						   cid));
	if (!channel->owner)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");

	if (!channel->open_attempt)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Channel open not in progress");

	if (channel->open_attempt->cmd)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Another openchannel command"
				    " is in progress");

	/* Add serials to PSBT */
	psbt_add_serials(psbt, TX_INITIATOR);

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
	if (!psbt_has_required_fields(psbt))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "PSBT is missing required fields %s",
				    type_to_string(tmpctx, struct wally_psbt,
						   psbt));

	channel->open_attempt->cmd = cmd;

	msg = towire_dualopend_psbt_updated(NULL, psbt);
	subd_send_msg(channel->owner, take(msg));
	return command_still_pending(cmd);
}

static struct command_result *json_openchannel_init(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	bool *announce_channel;
	u32 *feerate_per_kw_funding;
	u32 *feerate_per_kw;
	struct amount_sat *amount, psbt_val;
	struct wally_psbt *psbt;
	const u8 *our_upfront_shutdown_script;
	struct open_attempt *oa;
	u8 *msg;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &id),
		   p_req("amount", param_sat, &amount),
		   p_req("initialpsbt", param_psbt, &psbt),
		   p_opt("commitment_feerate", param_feerate, &feerate_per_kw),
		   p_opt("funding_feerate", param_feerate, &feerate_per_kw_funding),
		   p_opt_def("announce", param_bool, &announce_channel, true),
		   p_opt("close_to", param_bitcoin_address, &our_upfront_shutdown_script),
		   NULL))
		return command_param_failed();

	psbt_val = AMOUNT_SAT(0);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct amount_sat in_amt = psbt_input_get_amount(psbt, i);
		if (!amount_sat_add(&psbt_val, psbt_val, in_amt))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Overflow in adding PSBT input"
					    " values. %s",
					    type_to_string(tmpctx,
							   struct wally_psbt,
							   psbt));
	}

	/* If they don't pass in at least enough in the PSBT to cover
	 * their amount, nope */
	if (!amount_sat_greater(psbt_val, *amount))
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Provided PSBT cannot afford funding of "
				    "amount %s. %s",
				    type_to_string(tmpctx,
						   struct amount_sat,
						   amount),
				    type_to_string(tmpctx,
						   struct wally_psbt,
						   psbt));

	if (!feerate_per_kw_funding) {
		feerate_per_kw_funding = tal(cmd, u32);
		*feerate_per_kw_funding = opening_feerate(cmd->ld->topology);
		if (!*feerate_per_kw_funding)
			return command_fail(cmd, LIGHTNINGD,
					    "`funding_feerate` not specified and fee "
					    "estimation failed");
	}
	if (!feerate_per_kw) {
		feerate_per_kw = tal(cmd, u32);
		/* FIXME: Anchors are on by default, we should use the lowest
		 * possible feerate */
		*feerate_per_kw = *feerate_per_kw_funding;
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

	channel = peer_unsaved_channel(peer);
	if (!channel || !channel->owner)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");
	if (channel->open_attempt
	     || !list_empty(&channel->inflights))
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Channel funding in-progress. %s",
				    channel_state_name(channel));

	if (!feature_negotiated(cmd->ld->our_features,
			        peer->their_features,
				OPT_DUAL_FUND)) {
		return command_fail(cmd, FUNDING_V2_NOT_SUPPORTED,
				    "v2 openchannel not supported "
				    "by peer");
	}

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

	/* Add serials to any input that's missing them */
	psbt_add_serials(psbt, TX_INITIATOR);

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
	if (!psbt_has_required_fields(psbt))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "PSBT is missing required fields %s",
				    type_to_string(tmpctx, struct wally_psbt,
						   psbt));

	/* Get a new open_attempt going */
	channel->opener = LOCAL;
	channel->open_attempt = oa = new_channel_open_attempt(channel);
	channel->channel_flags = OUR_CHANNEL_FLAGS;
	oa->funding = *amount;
	oa->cmd = cmd;

	if (!*announce_channel) {
		channel->channel_flags &= ~CHANNEL_FLAGS_ANNOUNCE_CHANNEL;
		log_info(peer->ld->log,
			 "Will open private channel with node %s",
			 type_to_string(tmpctx, struct node_id, id));
	}

	/* Needs to be stolen away from cmd */
	if (our_upfront_shutdown_script)
		oa->our_upfront_shutdown_script
			= tal_steal(oa, our_upfront_shutdown_script);

	msg = towire_dualopend_opener_init(NULL,
					   psbt, *amount,
					   oa->our_upfront_shutdown_script,
					   *feerate_per_kw,
					   *feerate_per_kw_funding,
					   channel->channel_flags);

	subd_send_msg(channel->owner, take(msg));
	return command_still_pending(cmd);
}

static void
channel_fail_fallen_behind(struct subd* dualopend, const u8 *msg)
{
	struct channel *channel = dualopend->channel;

	if (!fromwire_dualopend_fail_fallen_behind(msg)) {
		channel_internal_error(channel,
				       "Bad DUALOPEND_FAIL_FALLEN_BEHIND: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

        channel_fallen_behind(channel, msg);
}

static void handle_psbt_changed(struct subd *dualopend,
				struct channel *channel,
				const u8 *msg)
{
	struct channel_id cid;
	u64 funding_serial;
	struct wally_psbt *psbt;
	struct json_stream *response;
	struct openchannel2_psbt_payload *payload;
	struct open_attempt *oa;
	struct command *cmd;

	assert(channel->open_attempt);
	oa = channel->open_attempt;
	cmd = oa->cmd;

	if (!fromwire_dualopend_psbt_changed(tmpctx, msg,
					     &cid,
					     &funding_serial,
					     &psbt)) {
		channel_internal_error(channel,
				       "Bad DUALOPEND_PSBT_CHANGED: %s",
				       tal_hex(tmpctx, msg));
		return;
	}


	switch (oa->role) {
	case TX_INITIATOR:
		if (!cmd) {
			channel_err_broken(channel,
					   tal_fmt(tmpctx, "Unexpected"
						   " PSBT_CHANGED %s",
						   tal_hex(tmpctx, msg)));
			return;
		}
		/* This might be the first time we learn the channel_id */
		channel->cid = cid;
		response = json_stream_success(cmd);
		json_add_string(response, "channel_id",
				type_to_string(tmpctx, struct channel_id,
					       &channel->cid));
		json_add_psbt(response, "psbt", psbt);
		json_add_bool(response, "commitments_secured", false);
		json_add_u64(response, "funding_serial", funding_serial);

		oa->cmd = NULL;
		was_pending(command_success(cmd, response));
		return;
	case TX_ACCEPTER:
		payload = tal(dualopend, struct openchannel2_psbt_payload);
		payload->dualopend = dualopend;
		tal_add_destructor2(dualopend,
				    openchannel2_psbt_remove_dualopend,
				    payload);
		payload->psbt = tal_steal(payload, psbt);
		payload->channel = channel;
		plugin_hook_call_openchannel2_changed(dualopend->ld, payload);
		return;
	}
	abort();
}

static void handle_commit_received(struct subd *dualopend,
				   struct channel *channel,
				   const u8 *msg)
{
	struct lightningd *ld = dualopend->ld;
	struct open_attempt *oa = channel->open_attempt;
	struct channel_info channel_info;
	struct bitcoin_tx *remote_commit;
	struct bitcoin_signature remote_commit_sig;
	struct bitcoin_txid funding_txid;
	u16 funding_outnum;
	u32 feerate_funding, feerate_commitment;
	struct amount_sat total_funding, funding_ours;
	u8 *remote_upfront_shutdown_script,
	   *local_upfront_shutdown_script;
	struct penalty_base *pbase;
	struct wally_psbt *psbt;
	struct json_stream *response;
	struct openchannel2_psbt_payload *payload;
	struct channel_inflight *inflight;
	struct command *cmd = oa->cmd;

	if (!fromwire_dualopend_commit_rcvd(tmpctx, msg,
					    &channel_info.their_config,
					    &remote_commit,
					    &pbase,
					    &remote_commit_sig,
					    &psbt,
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
					    &channel->channel_flags,
					    &feerate_funding,
					    &feerate_commitment,
					    &local_upfront_shutdown_script,
					    &remote_upfront_shutdown_script)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_COMMIT_RCVD: %s",
				       tal_hex(msg, msg));
		channel->open_attempt = tal_free(channel->open_attempt);
		notify_channel_open_failed(channel->peer->ld, &channel->cid);
		return;
	}

	/* We need to update the channel reserve on the config */
	channel_update_reserve(channel,
			       &channel_info.their_config,
			       total_funding);

	if (channel->state == DUALOPEND_OPEN_INIT) {
		if (peer_active_channel(channel->peer)) {
			channel_saved_err_broken_reconn(channel,
						  "Already have active"
						  " channel with %s",
						  type_to_string(tmpctx,
							 struct node_id,
							 &channel->peer->id));
			channel->open_attempt
				= tal_free(channel->open_attempt);
			return;
		}

		if (!(inflight = wallet_commit_channel(ld, channel,
						       remote_commit,
						       &remote_commit_sig,
						       &funding_txid,
						       funding_outnum,
						       total_funding,
						       funding_ours,
						       &channel_info,
						       feerate_funding,
						       feerate_commitment,
						       oa->role == TX_INITIATOR ?
								oa->our_upfront_shutdown_script :
								local_upfront_shutdown_script,
						       remote_upfront_shutdown_script,
						       psbt))) {
			channel_internal_error(channel,
					       "wallet_commit_channel failed"
					       " (chan %s)",
					       type_to_string(tmpctx,
							      struct channel_id,
							      &channel->cid));
			channel->open_attempt
				= tal_free(channel->open_attempt);
			return;
		}

		/* FIXME: handle RBF pbases */
		if (pbase)
			wallet_penalty_base_add(ld->wallet,
						channel->dbid,
						pbase);

	} else {
		assert(channel->state == DUALOPEND_AWAITING_LOCKIN);

		if (!(inflight = wallet_update_channel(ld, channel,
						       remote_commit,
						       &remote_commit_sig,
						       &funding_txid,
						       funding_outnum,
						       total_funding,
						       funding_ours,
						       feerate_funding,
						       psbt))) {
			channel_internal_error(channel,
					       "wallet_update_channel failed"
					       " (chan %s)",
					       type_to_string(tmpctx,
							      struct channel_id,
							      &channel->cid));
			channel->open_attempt
				= tal_free(channel->open_attempt);
			return;
		}

	}

	switch (oa->role) {
	case TX_INITIATOR:
		if (!oa->cmd) {
			channel_err_broken(channel,
					   "Unexpected COMMIT_RCVD %s",
					   tal_hex(msg, msg));
			channel->open_attempt
				= tal_free(channel->open_attempt);
			return;
		}
		response = json_stream_success(oa->cmd);
		json_add_string(response, "channel_id",
				type_to_string(tmpctx,
					       struct channel_id,
					       &channel->cid));
		json_add_psbt(response, "psbt", psbt);
		json_add_bool(response, "commitments_secured", true);
		/* For convenience sake, we include the funding outnum */
		json_add_num(response, "funding_outnum", funding_outnum);
		if (oa->our_upfront_shutdown_script) {
			json_add_hex_talarr(response, "close_to",
					    oa->our_upfront_shutdown_script);
			/* FIXME: also include the output as address */
		}

		channel->open_attempt
			= tal_free(channel->open_attempt);
		was_pending(command_success(cmd, response));
		return;
	case TX_ACCEPTER:
		payload = tal(dualopend, struct openchannel2_psbt_payload);
		payload->ld = ld;
		payload->dualopend = dualopend;
		tal_add_destructor2(dualopend,
				    openchannel2_psbt_remove_dualopend,
				    payload);
		payload->channel = channel;
		payload->psbt = clone_psbt(payload, inflight->funding_psbt);

		channel->open_attempt
			= tal_free(channel->open_attempt);

		/* We don't have a command, so set to NULL here */
		payload->channel->openchannel_signed_cmd = NULL;
		/* We call out to hook who will
		 * provide signatures for us! */
		plugin_hook_call_openchannel2_sign(ld, payload);
		return;
	}

	abort();
}

static unsigned int dual_opend_msg(struct subd *dualopend,
				   const u8 *msg, const int *fds)
{
	enum dualopend_wire t = fromwire_peektype(msg);
	struct channel *channel = dualopend->channel;

	switch (t) {
		case WIRE_DUALOPEND_GOT_OFFER:
			accepter_got_offer(dualopend, dualopend->channel, msg);
			return 0;
		case WIRE_DUALOPEND_GOT_RBF_OFFER:
			rbf_got_offer(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_PSBT_CHANGED:
			handle_psbt_changed(dualopend, channel, msg);
			return 0;
		case WIRE_DUALOPEND_COMMIT_RCVD:
			handle_commit_received(dualopend, channel, msg);
			return 0;
		case WIRE_DUALOPEND_RBF_VALIDATE:
			handle_validate_rbf(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_FUNDING_SIGS:
			handle_peer_tx_sigs_msg(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_TX_SIGS_SENT:
			handle_peer_tx_sigs_sent(dualopend, fds, msg);
			return 0;
		case WIRE_DUALOPEND_PEER_LOCKED:
			handle_peer_locked(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_CHANNEL_LOCKED:
			if (tal_count(fds) != 3)
				return 3;
			handle_channel_locked(dualopend, fds, msg);
			return 0;
		case WIRE_DUALOPEND_GOT_SHUTDOWN:
			handle_peer_wants_to_close(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_SHUTDOWN_COMPLETE:
			if (tal_count(fds) != 3)
				return 3;
			handle_channel_closed(dualopend, fds, msg);
			return 0;
		case WIRE_DUALOPEND_FAIL_FALLEN_BEHIND:
			channel_fail_fallen_behind(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_DEV_MEMLEAK_REPLY:

		/* Messages we send */
		case WIRE_DUALOPEND_INIT:
		case WIRE_DUALOPEND_REINIT:
		case WIRE_DUALOPEND_OPENER_INIT:
		case WIRE_DUALOPEND_RBF_INIT:
		case WIRE_DUALOPEND_GOT_OFFER_REPLY:
		case WIRE_DUALOPEND_GOT_RBF_OFFER_REPLY:
		case WIRE_DUALOPEND_RBF_VALID:
		case WIRE_DUALOPEND_FAIL:
		case WIRE_DUALOPEND_PSBT_UPDATED:
		case WIRE_DUALOPEND_SEND_TX_SIGS:
		case WIRE_DUALOPEND_SEND_SHUTDOWN:
		case WIRE_DUALOPEND_DEPTH_REACHED:
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

static const struct json_command openchannel_bump_command = {
	"openchannel_bump",
	"channels",
	json_openchannel_bump,
	"Attempt to bump the fee on {channel_id}'s funding transaction."
};

static const struct json_command openchannel_abort_command = {
	"openchannel_abort",
	"channels",
	json_openchannel_abort,
	"Abort {channel_id}'s open. Usable while `commitment_signed=false`."
};

AUTODATA(json_command, &openchannel_init_command);
AUTODATA(json_command, &openchannel_update_command);
AUTODATA(json_command, &openchannel_signed_command);
AUTODATA(json_command, &openchannel_bump_command);
AUTODATA(json_command, &openchannel_abort_command);

static void start_fresh_dualopend(struct peer *peer,
				  struct per_peer_state *pps,
				  struct channel *channel)
{
	int hsmfd;
	u32 max_to_self_delay;
	struct amount_msat min_effective_htlc_capacity;
	const u8 *msg;

	hsmfd = hsm_get_client_fd(peer->ld, &peer->id, channel->unsaved_dbid,
				  HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	channel->owner = new_channel_subd(peer->ld,
					  "lightning_dualopend",
					  channel,
					  &peer->id,
					  channel->log, true,
					  dualopend_wire_name,
					  dual_opend_msg,
					  channel_errmsg,
					  channel_set_billboard,
					  take(&pps->peer_fd),
					  take(&pps->gossip_fd),
					  take(&pps->gossip_store_fd),
					  take(&hsmfd), NULL);

	if (!channel->owner) {
		channel_internal_error(channel,
				       "Running lightningd_dualopend: %s",
				       strerror(errno));
		return;
	}

	channel_config(peer->ld, &channel->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	/* BOLT #2:
	 *
	 * The sender:
	 *   - SHOULD set `minimum_depth` to a number of blocks it
	 *     considers reasonable to avoid double-spending of the
	 *     funding transaction.
	 */
	channel->minimum_depth = peer->ld->config.anchor_confirms;

	msg = towire_dualopend_init(NULL, chainparams,
				    peer->ld->our_features,
				    peer->their_features,
				    &channel->our_config,
				    max_to_self_delay,
				    min_effective_htlc_capacity,
				    pps, &channel->local_basepoints,
				    &channel->local_funding_pubkey,
				    channel->minimum_depth);
	subd_send_msg(channel->owner, take(msg));

}

void peer_restart_dualopend(struct peer *peer,
			    struct per_peer_state *pps,
			    struct channel *channel)
{
	u32 max_to_self_delay;
	struct amount_msat min_effective_htlc_capacity;
	struct channel_config unused_config;
	struct channel_inflight *inflight, *first_inflight;
        int hsmfd;
	u8 *msg;

	if (channel_unsaved(channel)) {
		start_fresh_dualopend(peer, pps, channel);
		return;
	}
	hsmfd = hsm_get_client_fd(peer->ld, &peer->id, channel->dbid,
				  HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	channel_set_owner(channel,
			  new_channel_subd(peer->ld, "lightning_dualopend",
					   channel,
					   &peer->id,
					   channel->log, true,
					   dualopend_wire_name,
					   dual_opend_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&pps->peer_fd),
					   take(&pps->gossip_fd),
					   take(&pps->gossip_store_fd),
					   take(&hsmfd), NULL));
	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon channel: %s",
			   strerror(errno));
		channel_fail_reconnect_later(channel,
					     "Failed to subdaemon channel");
		return;
	}

	/* Find the max self delay and min htlc capacity */
	channel_config(peer->ld, &unused_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	inflight = channel_current_inflight(channel);
	assert(inflight);

	/* Get the first inflight to figure out the original feerate
	 * for this channel. It's fine if it's the same as the current */
	first_inflight = list_top(&channel->inflights,
				  struct channel_inflight,
				  list);
	assert(first_inflight);
	msg = towire_dualopend_reinit(NULL,
				      chainparams,
				      peer->ld->our_features,
				      peer->their_features,
				      &channel->our_config,
				      &channel->channel_info.their_config,
				      &channel->cid,
				      max_to_self_delay,
				      min_effective_htlc_capacity,
				      pps,
				      &channel->local_basepoints,
				      &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey,
				      channel->minimum_depth,
				      &inflight->funding->txid,
				      inflight->funding->outnum,
				      first_inflight->funding->feerate,
				      inflight->funding->feerate,
				      channel->funding,
				      channel->our_msat,
				      &channel->channel_info.theirbase,
				      &channel->channel_info.remote_per_commit,
				      inflight->funding_psbt,
				      channel->opener,
				      channel->scid != NULL,
				      channel->remote_funding_locked,
				      channel->state == CHANNELD_SHUTTING_DOWN,
				      channel->shutdown_scriptpubkey[REMOTE] != NULL,
				      channel->shutdown_scriptpubkey[LOCAL],
				      channel->remote_upfront_shutdown_script,
				      inflight->remote_tx_sigs,
                                      channel->fee_states,
				      channel->channel_flags);


	subd_send_msg(channel->owner, take(msg));
}

void peer_start_dualopend(struct peer *peer, struct per_peer_state *pps)
{
	struct channel *channel;

	/* And we never touch this. */
	assert(!peer_unsaved_channel(peer));
	channel = new_unsaved_channel(peer,
				      peer->ld->config.fee_base,
				      peer->ld->config.fee_per_satoshi);

	start_fresh_dualopend(peer, pps, channel);
}
