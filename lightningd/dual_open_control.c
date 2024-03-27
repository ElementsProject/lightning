/* This is the lightningd handler for messages to/from various
 * dualopend subdaemons. It manages the callbacks and database
 * saves and funding tx watching for a channel open */

#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/blockheight_states.h>
#include <common/json_channel_type.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/psbt_open.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <errno.h>
#include <hsmd/permissions.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/channel_gossip.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/gossip_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/notification.h>
#include <lightningd/opening_common.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_fd.h>
#include <lightningd/plugin_hook.h>
#include <openingd/dualopend_wiregen.h>

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

	channel_fail_transient(channel, true, "%s: %s",
			       channel->owner ?
			       channel->owner->name :
			       "dualopend-dead",
			       desc);
}

void channel_unsaved_close_conn(struct channel *channel, const char *why)
{
	/* Gotta be unsaved */
	assert(channel_state_uncommitted(channel->state));
	log_info(channel->log, "Unsaved peer failed."
		 " Disconnecting and deleting channel. Reason: %s",
		 why);

	channel_cleanup_commands(channel, why);

	assert(channel->owner);
	channel_set_owner(channel, NULL);
	delete_channel(channel);
}

static void channel_saved_err_broken_reconn(struct channel *channel,
					    const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;

	/* We only reconnect to 'saved' channel peers */
	assert(!channel_state_uncommitted(channel->state));

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

	if (channel_state_uncommitted(channel->state)) {
		log_broken(channel->log, "%s", errmsg);
		channel_unsaved_close_conn(channel, errmsg);
	} else
		channel_disconnect(channel, LOG_BROKEN, false, errmsg);
}

void json_add_unsaved_channel(struct json_stream *response,
			      const struct channel *channel,
			      const struct peer *peer)
{
	struct amount_msat total;
	struct open_attempt *oa;

	/* If we're chatting but no channel, that's shown by connected: True */
	if (!channel->open_attempt)
		return;

	/* If we're calling out to connectd to activate peer to start the
	 * process, this will be NULL */
	if (!channel->owner)
		return;

	oa = channel->open_attempt;

	json_object_start(response, NULL);
	json_add_node_id(response, "peer_id", &peer->id);
	json_add_bool(response, "peer_connected", peer->connected == PEER_CONNECTED);
	json_add_channel_type(response, "channel_type", channel->type);
	json_add_string(response, "state", channel_state_name(channel));
	json_add_string(response, "owner", channel->owner->name);
	json_add_string(response, "opener", channel->opener == LOCAL ?
					    "local" : "remote");
	json_add_bool(response, "lost_state", channel->future_per_commitment_point ? true : false);
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
			json_add_amount_msat(response, "to_us_msat", total);
			/* This will change if peer adds funds */
			json_add_amount_msat(response, "total_msat", total);
		}
	}

	json_array_start(response, "features");
	/* v2 channels assume static_remotekey */
	json_add_string(response, NULL, "option_static_remotekey");

	if (feature_negotiated(channel->peer->ld->our_features,
			       channel->peer->their_features,
			       OPT_ANCHOR_OUTPUTS))
		json_add_string(response, NULL, "option_anchor_outputs");

	if (feature_negotiated(channel->peer->ld->our_features,
			       channel->peer->their_features,
			       OPT_ANCHORS_ZERO_FEE_HTLC_TX))
		json_add_string(response, NULL, "option_anchors_zero_fee_htlc_tx");

	json_array_end(response);
	json_object_end(response);
}

struct rbf_channel_payload {
	struct subd *dualopend;
	struct channel *channel;
	struct node_id peer_id;

	/* Info specific to this RBF */
	struct channel_id channel_id;
	struct amount_sat their_last_funding;
	struct amount_sat their_proposed_funding;
	struct amount_sat our_last_funding;
	u32 funding_feerate_per_kw;
	u32 locktime;
	bool req_confirmed_ins_remote;

	/* General info */
	u32 feerate_our_max;
	u32 feerate_our_min;
	/* What's the maximum amount of funding
	 * this channel can hold */
	struct amount_sat channel_max;

	/* If they've requested funds, this is their request */
	struct amount_sat *requested_lease_amt;

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
	json_add_amount_sat_msat(stream, "their_last_funding_msat",
				 payload->their_last_funding);
	json_add_amount_sat_msat(stream, "their_funding_msat",
				 payload->their_proposed_funding);
	json_add_amount_sat_msat(stream, "our_last_funding_msat",
				 payload->our_last_funding);
	json_add_num(stream, "locktime", payload->locktime);
	json_add_num(stream, "feerate_our_max",
		     payload->feerate_our_max);
	json_add_num(stream, "feerate_our_min",
		     payload->feerate_our_min);
	json_add_num(stream, "funding_feerate_per_kw",
		     payload->funding_feerate_per_kw);
	json_add_amount_sat_msat(stream, "channel_max_msat",
				 payload->channel_max);

	if (payload->requested_lease_amt)
		json_add_amount_sat_msat(stream, "requested_lease_msat",
					 *payload->requested_lease_amt);
	json_add_bool(stream, "require_confirmed_inputs",
		      payload->req_confirmed_ins_remote);
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
	/* If they've requested funds, this is their request */
	struct amount_sat *requested_lease_amt;
	u32 lease_blockheight_start;
	u32 node_blockheight;
	bool req_confirmed_ins_remote;

	struct amount_sat accepter_funding;
	struct wally_psbt *psbt;
	const u8 *our_shutdown_scriptpubkey;
	struct lease_rates *rates;
	char *err_msg;
};

static void openchannel2_hook_serialize(struct openchannel2_payload *payload,
					struct json_stream *stream,
					struct plugin *plugin)
{
	json_object_start(stream, "openchannel2");
	json_add_node_id(stream, "id", &payload->peer_id);
	json_add_channel_id(stream, "channel_id", &payload->channel_id);
	json_add_amount_sat_msat(stream,
				 "their_funding_msat", payload->their_funding);
	json_add_amount_sat_msat(stream,
				 "dust_limit_msat", payload->dust_limit_satoshis);

	json_add_amount_msat(stream, "max_htlc_value_in_flight_msat",
			     payload->max_htlc_value_in_flight_msat);
	json_add_amount_msat(stream, "htlc_minimum_msat",
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
	json_add_amount_sat_msat(stream, "channel_max_msat",
				 payload->channel_max);
	if (payload->requested_lease_amt) {
		json_add_amount_sat_msat(stream, "requested_lease_msat",
					 *payload->requested_lease_amt);
		json_add_num(stream, "lease_blockheight_start",
			     payload->lease_blockheight_start);
		json_add_num(stream, "node_blockheight",
			     payload->node_blockheight);
	}
	json_add_bool(stream, "require_confirmed_inputs",
		      payload->req_confirmed_ins_remote);
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
			fmt_channel_id(tmpctx,
				       &payload->channel->cid));
	json_add_bool(stream, "require_confirmed_inputs",
		      payload->channel->req_confirmed_ins[REMOTE]);
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
			fmt_channel_id(tmpctx,
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

	/* Update the remote's require confirmed preferences */
	if (payload->req_confirmed_ins_remote != channel->req_confirmed_ins[REMOTE]) {
		channel->req_confirmed_ins[REMOTE] =
			payload->req_confirmed_ins_remote;
		wallet_channel_save(dualopend->ld->wallet, channel);
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
		      fmt_wally_psbt(tmpctx, payload->psbt));
	if (!hook_extract_amount(dualopend, buffer, toks,
				 "our_funding_msat", &payload->our_funding))
		fatal("Plugin failed to supply our_funding_msat field");

	if (payload->psbt
	    && amount_sat_zero(payload->our_funding))
		fatal("Plugin failed to supply our_funding_msat field");

	if (!payload->psbt &&
		!amount_sat_zero(payload->our_funding)) {

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
	u32 *our_shutdown_script_wallet_index;
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

	/* Determine the wallet index for our_shutdown_scriptpubkey,
	 * NULL if not found. */
	u32 found_wallet_index;
	if (wallet_can_spend(dualopend->ld->wallet,
			     payload->our_shutdown_scriptpubkey,
			     &found_wallet_index)) {
		our_shutdown_script_wallet_index = tal(tmpctx, u32);
		*our_shutdown_script_wallet_index = found_wallet_index;
	} else
		our_shutdown_script_wallet_index = NULL;

	channel->cid = payload->channel_id;
	channel->opener = REMOTE;
	channel->open_attempt = new_channel_open_attempt(channel);
	channel->req_confirmed_ins[REMOTE] =
		payload->req_confirmed_ins_remote;
	msg = towire_dualopend_got_offer_reply(NULL,
					       payload->accepter_funding,
					       payload->psbt,
					       payload->our_shutdown_scriptpubkey,
					       our_shutdown_script_wallet_index,
					       payload->rates);

	subd_send_msg(dualopend, take(msg));
}


static bool
openchannel2_hook_deserialize(struct openchannel2_payload *payload,
			      const char *buffer,
			      const jsmntok_t *toks)
{
	const u8 *shutdown_script;
	const char *err;
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


	struct amount_msat fee_base, fee_max_base;
	/* deserialized may be called multiple times */
	if (!payload->rates)
		payload->rates = tal(payload, struct lease_rates);
	err = json_scan(payload, buffer, toks,
			"{lease_fee_base_msat:%"
			",lease_fee_basis:%"
			",channel_fee_max_base_msat:%"
			",channel_fee_max_proportional_thousandths:%"
			",funding_weight:%}",
			JSON_SCAN(json_to_msat, &fee_base),
			JSON_SCAN(json_to_u16,
				  &payload->rates->lease_fee_basis),
			JSON_SCAN(json_to_msat, &fee_max_base),
			JSON_SCAN(json_to_u16,
				  &payload->rates->channel_fee_max_proportional_thousandths),
			JSON_SCAN(json_to_u16,
				  &payload->rates->funding_weight));

	/* It's possible they didn't send these back! */
	if (err)
		payload->rates = tal_free(payload->rates);

	/* Convert to u32s */
	if (payload->rates &&
	    !lease_rates_set_lease_fee_msat(payload->rates, fee_base))
		fatal("Plugin sent overflowing/non-sat `lease_fee_base_msat`");

	if (payload->rates &&
	    !lease_rates_set_chan_fee_base_msat(payload->rates, fee_max_base))
		fatal("Plugin sent overflowing `channel_fee_max_base_msat`");

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
		      fmt_wally_psbt(tmpctx, payload->psbt));

	if (!hook_extract_amount(dualopend, buffer, toks,
				 "our_funding_msat",
				 &payload->accepter_funding))
		fatal("Plugin failed to supply our_funding_msat field");

	if (payload->psbt
	    && amount_sat_zero(payload->accepter_funding))
		fatal("Plugin failed to supply our_funding_msat field");

	if (!payload->psbt
	    && !amount_sat_zero(payload->accepter_funding)) {
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
		      fmt_wally_psbt(tmpctx, psbt));

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
		      fmt_wally_psbt(tmpctx, psbt));

	/* NOTE - The psbt_contribs_changed function nulls lots of
	 * fields in place to compare the PSBTs. This removes the
	 * witness stack held in final_witness.  Give it a clone of
	 * the PSBT to hack on instead ... */
	struct wally_psbt *psbt_clone;
	psbt_clone = clone_psbt(tmpctx, psbt);

	/* Verify that inputs/outputs are the same. Note that this is a
	 * 'de minimus' check -- we just look at serial_ids. If you've
	 * totally managled the data here but left the serial_ids intact,
	 * you'll get a failure back from the peer when you send
	 * commitment sigs */
	if (psbt_contribs_changed(payload->psbt, psbt_clone))
		fatal("Plugin must not change psbt input/output set. "
		      "orig: %s. updated: %s",
		      fmt_wally_psbt(tmpctx, payload->psbt),
		      fmt_wally_psbt(tmpctx, psbt));

	if (payload->psbt)
		tal_free(payload->psbt);

	payload->psbt = tal_steal(payload, psbt);
	return true;
}

static void dualopend_tell_depth(struct channel *channel,
				 const struct bitcoin_txid *txid,
				 u32 depth)
{
	const u8 *msg;
	u32 to_go;

	if (!channel->owner) {
		log_debug(channel->log,
			  "Funding tx %s confirmed, but peer disconnected",
			  fmt_bitcoin_txid(tmpctx, txid));
		return;
	}

	log_debug(channel->log,
		  "Funding tx %s confirmed, telling peer",
		  fmt_bitcoin_txid(tmpctx, txid));
	if (depth < channel->minimum_depth) {
		to_go = channel->minimum_depth - depth;
	} else
		to_go = 0;

	/* Are we there yet? */
	if (to_go == 0) {
		assert(channel->scid);
		assert(bitcoin_txid_eq(&channel->funding.txid, txid));

		channel_set_billboard(channel, false,
				      tal_fmt(tmpctx, "Funding depth reached"
					      " %d confirmations, alerting peer"
					      " we're locked-in.",
					      to_go));

		msg = towire_dualopend_depth_reached(NULL, depth);
		subd_send_msg(channel->owner, take(msg));
	} else
		channel_set_billboard(channel, false,
				      tal_fmt(tmpctx, "Funding needs %d more"
					      " confirmations to be ready.",
					      to_go));
}

static enum watch_result opening_depth_cb(struct lightningd *ld,
					  const struct bitcoin_txid *txid,
					  const struct bitcoin_tx *tx,
					  unsigned int depth,
					  struct channel_inflight *inflight)
{
	struct txlocator *loc;
	struct short_channel_id scid;

	/* Usually, we're here because we're awaiting a lockin, but
	 * we could also mutual shutdown */
	if (inflight->channel->state != DUALOPEND_AWAITING_LOCKIN)
		return DELETE_WATCH;

	/* Reorged out?  OK, we're not committed yet. */
	if (depth == 0)
		return KEEP_WATCHING;

	/* FIXME: Don't do this until we're actually locked in! */
	loc = wallet_transaction_locate(tmpctx, ld->wallet, txid);
	if (!mk_short_channel_id(&scid,
				 loc->blkheight, loc->index,
				 inflight->funding->outpoint.n)) {
		channel_fail_permanent(inflight->channel,
				       REASON_LOCAL,
				       "Invalid funding scid %u:%u:%u",
				       loc->blkheight, loc->index,
				       inflight->funding->outpoint.n);
		return DELETE_WATCH;
	}

	if (!inflight->channel->scid) {
		wallet_annotate_txout(ld->wallet, &inflight->funding->outpoint,
				      TX_CHANNEL_FUNDING, inflight->channel->dbid);
		inflight->channel->scid = tal_dup(inflight->channel, struct short_channel_id, &scid);
		wallet_channel_save(ld->wallet, inflight->channel);
	} else if (!short_channel_id_eq(*inflight->channel->scid, scid)) {
		/* We freaked out if required when original was
		 * removed, so just update now */
		log_info(inflight->channel->log, "Short channel id changed from %s->%s",
			 fmt_short_channel_id(tmpctx, *inflight->channel->scid),
			 fmt_short_channel_id(tmpctx, scid));
		*inflight->channel->scid = scid;
		wallet_channel_save(ld->wallet, inflight->channel);
	}

	if (depth >= inflight->channel->minimum_depth)
		update_channel_from_inflight(ld, inflight->channel, inflight);

	dualopend_tell_depth(inflight->channel, txid, depth);

	return KEEP_WATCHING;
}

void watch_opening_inflight(struct lightningd *ld,
			    struct channel_inflight *inflight)
{
	watch_txid(inflight, ld->topology,
		   &inflight->funding->outpoint.txid,
		   opening_depth_cb, inflight);
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
			   fmt_wally_psbt(tmpctx,
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
	if (!bitcoin_txid_eq(&inflight->funding->outpoint.txid, &txid)) {
		log_broken(channel->log,
			   "PSBT's txid does not match. %s != %s",
			   fmt_bitcoin_txid(tmpctx, &txid),
			   fmt_bitcoin_txid(tmpctx,
					    &inflight->funding->outpoint.txid));
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
	watch_opening_inflight(payload->ld, inflight);
	msg = towire_dualopend_send_tx_sigs(NULL, inflight->funding_psbt);

send_msg:
	/* Peer's gone away, let's try reconnecting */
	if (!payload->dualopend) {
		channel_saved_err_broken_reconn(channel,
						"dualopend daemon died"
						" before signed PSBT returned");
		tal_free(msg);
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
		      const struct bitcoin_outpoint *funding,
		      struct amount_sat total_funding,
		      struct amount_sat our_funding,
		      u32 funding_feerate,
		      struct wally_psbt *psbt STEALS,
		      const u32 lease_expiry,
		      struct amount_sat lease_fee,
		      secp256k1_ecdsa_signature *lease_commit_sig STEALS,
		      const u32 lease_chan_max_msat,
		      const u16 lease_chan_max_ppt,
		      const u32 lease_blockheight_start,
		      struct amount_sat lease_amt)
{
	struct amount_msat our_msat, lease_fee_msat;
	struct channel_inflight *inflight;

	if (!amount_sat_to_msat(&our_msat, our_funding)) {
		log_broken(channel->log, "Unable to convert funds");
		return NULL;
	}

	if (!amount_sat_to_msat(&lease_fee_msat, lease_fee)) {
		log_broken(channel->log, "Unable to convert 'lease_fee'");
		return NULL;
	}

	assert(channel->unsaved_dbid == 0);
	assert(channel->dbid != 0);

	channel->funding = *funding;
	channel->funding_sats = total_funding;
	channel->our_funds = our_funding;
	channel->our_msat = our_msat;
	channel->push = lease_fee_msat;
	channel->msat_to_us_min = our_msat;
	channel->msat_to_us_max = our_msat;
	channel->lease_expiry = lease_expiry;
	channel->htlc_minimum_msat = channel->channel_info.their_config.htlc_minimum;
	channel->htlc_maximum_msat = htlc_max_possible_send(channel);

	tal_free(channel->lease_commit_sig);
	channel->lease_commit_sig = tal_steal(channel, lease_commit_sig);
	channel->lease_chan_max_msat = lease_chan_max_msat;
	channel->lease_chan_max_ppt = lease_chan_max_ppt;

	tal_free(channel->blockheight_states);
	channel->blockheight_states = new_height_states(channel,
							channel->opener,
							&lease_blockheight_start);

	/* Update in database */
	wallet_channel_save(ld->wallet, channel);

	/* Add open attempt to channel's inflights */
	inflight = new_inflight(channel,
				&channel->funding,
				funding_feerate,
				channel->funding_sats,
				channel->our_funds,
				psbt,
				channel->lease_expiry,
				channel->lease_commit_sig,
				channel->lease_chan_max_msat,
				channel->lease_chan_max_ppt,
				lease_blockheight_start,
				channel->push,
				lease_amt,
				0,
				false,
				false);
	wallet_inflight_add(ld->wallet, inflight);

	return inflight;
}

static bool
wallet_update_channel_commit(struct lightningd *ld,
			     struct channel *channel,
			     struct channel_inflight *inflight,
			     struct bitcoin_tx *remote_commit,
			     struct bitcoin_signature *remote_commit_sig)
{
	channel_set_last_tx(channel,
			    tal_steal(channel, remote_commit),
			    remote_commit_sig);

	/* We can't call channel_set_state here: channel isn't in db, so
	 * really this is a "channel creation" event. */
	if (channel->state == DUALOPEND_OPEN_COMMIT_READY) {
		log_info(channel->log, "State changed from %s to %s",
			 channel_state_name(channel),
			 channel_state_str(DUALOPEND_OPEN_COMMITTED));
		channel->state = DUALOPEND_OPEN_COMMITTED;
		notify_channel_state_changed(channel->peer->ld,
					     &channel->peer->id,
					     &channel->cid,
					     channel->scid,
					     time_now(),
					     DUALOPEND_OPEN_COMMIT_READY,
					     DUALOPEND_OPEN_COMMITTED,
					     REASON_REMOTE,
					     "Commitment transaction committed");
	}

	/* Update in database */
	wallet_channel_save(ld->wallet, channel);

	/* Set inflight data & update */
	if (inflight->last_tx) {
		struct bitcoin_txid txid, inflight_txid;
		/* confirm they're the same tx! */
		bitcoin_txid(remote_commit, &txid);
		bitcoin_txid(inflight->last_tx, &inflight_txid);
		if (!bitcoin_txid_eq(&txid, &inflight_txid)) {
			channel_fail_permanent(channel,
					       REASON_LOCAL,
					       "Invalid commitment txid."
					       " expected (inflight's) %s, got %s",
					       fmt_bitcoin_txid(tmpctx, &inflight_txid),
					       fmt_bitcoin_txid(tmpctx, &txid));
		}
		return false;
	}


	inflight_set_last_tx(inflight, remote_commit, *remote_commit_sig);
	wallet_inflight_save(ld->wallet, inflight);
	return true;
}


/* Returns NULL if can't generate a key for this channel (Shouldn't happen) */
static struct channel_inflight *
wallet_commit_channel(struct lightningd *ld,
		      struct channel *channel,
		      const struct bitcoin_outpoint *funding,
		      struct amount_sat total_funding,
		      struct amount_sat our_funding,
		      struct channel_info *channel_info,
		      u32 funding_feerate,
		      u32 commitment_feerate,
		      const u8 *our_upfront_shutdown_script,
		      const u8 *remote_upfront_shutdown_script,
		      struct wally_psbt *psbt STEALS,
		      const struct amount_sat lease_amt,
		      const u32 lease_blockheight_start,
		      const u32 lease_expiry,
		      const struct amount_sat lease_fee,
		      secp256k1_ecdsa_signature *lease_commit_sig STEALS,
		      const u32 lease_chan_max_msat,
		      const u16 lease_chan_max_ppt,
		      const struct channel_type *type)
{
	struct amount_msat our_msat, lease_fee_msat;
	struct channel_inflight *inflight;
	bool any_active = peer_any_channel(channel->peer, channel_state_wants_peercomms, NULL);

	if (!amount_sat_to_msat(&our_msat, our_funding)) {
		log_broken(channel->log, "Unable to convert funds");
		return NULL;
	}

	if (!amount_sat_to_msat(&lease_fee_msat, lease_fee)) {
		log_broken(channel->log, "Unable to convert lease fee");
		return NULL;
	}

	/* Get a key to use for closing outputs from this tx */
	channel->final_key_idx = wallet_get_newindex(ld);
	if (channel->final_key_idx == -1) {
		log_broken(channel->log, "Can't get final key index");
		return NULL;
	}

	assert(channel->state == DUALOPEND_OPEN_INIT);
	log_info(channel->log, "State changed from %s to %s",
		 channel_state_name(channel),
		 channel_state_str(DUALOPEND_OPEN_COMMIT_READY));
	channel->state = DUALOPEND_OPEN_COMMIT_READY;
	notify_channel_state_changed(channel->peer->ld,
				     &channel->peer->id,
				     &channel->cid,
				     channel->scid,
				     time_now(),
				     DUALOPEND_OPEN_INIT,
				     DUALOPEND_OPEN_COMMIT_READY,
				     REASON_REMOTE,
				     "Ready to send our commitment sigs");

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info->their_config.id = 0;
	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	/* Promote the unsaved_dbid to the dbid */
	assert(channel->unsaved_dbid != 0);
	channel->dbid = channel->unsaved_dbid;
	channel->unsaved_dbid = 0;
	channel->funding = *funding;
	channel->funding_sats = total_funding;
	channel->our_funds = our_funding;
	channel->our_msat = our_msat;
	channel->push = lease_fee_msat;
	channel->msat_to_us_min = our_msat;
	channel->msat_to_us_max = our_msat;
	channel->req_confirmed_ins[LOCAL] =
		ld->config.require_confirmed_inputs;

	channel->last_tx = NULL;
	channel->channel_info = *channel_info;
	channel->fee_states = new_fee_states(channel,
					     channel->opener,
					     &commitment_feerate);
	channel->min_possible_feerate = commitment_feerate;
	channel->max_possible_feerate = commitment_feerate;
	if (channel->peer->addr.itype == ADDR_INTERNAL_WIREADDR) {
		channel->scb = tal(channel, struct scb_chan);
		channel->scb->id = channel->dbid;
		channel->scb->unused = 0;
		channel->scb->addr = channel->peer->addr.u.wireaddr.wireaddr;
		channel->scb->node_id = channel->peer->id;
		channel->scb->funding = *funding;
		channel->scb->cid = channel->cid;
		channel->scb->funding_sats = total_funding;
	} else
		channel->scb = NULL;

	tal_free(channel->type);
	channel->type = channel_type_dup(channel, type);
	channel->scb->type = channel_type_dup(channel->scb, type);

	if (our_upfront_shutdown_script)
		channel->shutdown_scriptpubkey[LOCAL]
			= tal_steal(channel, our_upfront_shutdown_script);
	else
		channel->shutdown_scriptpubkey[LOCAL]
			= p2tr_for_keyidx(channel, channel->peer->ld,
					    channel->final_key_idx);

	channel->remote_upfront_shutdown_script
		= tal_steal(channel, remote_upfront_shutdown_script);

	channel->state_change_cause = (channel->opener == LOCAL) ?
					REASON_USER : REASON_REMOTE;

	/* If we're fundee, could be a little before this
	 * in theory, but it's only used for timing out. */
	channel->first_blocknum = get_block_height(ld->topology);

	/* Update lease info for channel */
	channel->blockheight_states = new_height_states(channel,
							channel->opener,
							&lease_blockheight_start);
	channel->lease_expiry = lease_expiry;

	tal_free(channel->lease_commit_sig);
	channel->lease_commit_sig = tal_steal(channel, lease_commit_sig);

	channel->lease_chan_max_msat = lease_chan_max_msat;
	channel->lease_chan_max_ppt = lease_chan_max_ppt;
	channel->htlc_minimum_msat = channel_info->their_config.htlc_minimum;
	channel->htlc_maximum_msat = htlc_max_possible_send(channel);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	/* Open attempt to channel's inflights */
	inflight = new_inflight(channel,
				&channel->funding,
				funding_feerate,
				channel->funding_sats,
				channel->our_funds,
				psbt,
				channel->lease_expiry,
				channel->lease_commit_sig,
				channel->lease_chan_max_msat,
				channel->lease_chan_max_ppt,
				lease_blockheight_start,
				channel->push,
				lease_amt,
				0,
				false,
				false);
	wallet_inflight_add(ld->wallet, inflight);

	/* We might have disconnected and decided we didn't need to
	 * reconnect because no channels are active.  But the subd
	 * just made it active! */
	if (!any_active && channel->peer->connected == PEER_DISCONNECTED) {
		try_reconnect(channel->peer, channel->peer,
			      &channel->peer->addr);
	}

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
	bool anchors = feature_negotiated(ld->our_features,
					  channel->peer->their_features,
					  OPT_ANCHOR_OUTPUTS)
		|| feature_negotiated(ld->our_features,
				      channel->peer->their_features,
				      OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	/* We shouldn't get this message while we're waiting to finish */
	if (channel_state_uncommitted(channel->state)) {
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
	 *    - SHOULD send a `warning`
	 */
	if (!valid_shutdown_scriptpubkey(scriptpubkey, anysegwit, !anchors)) {
		u8 *warning = towire_warningfmt(NULL,
						&channel->cid,
						"Bad shutdown scriptpubkey %s",
						tal_hex(tmpctx, scriptpubkey));

		/* Get connectd to send warning, and kill subd. */
		subd_send_msg(ld->connectd,
			      take(towire_connectd_peer_send_msg(NULL,
								 &channel->peer->id,
								 channel->peer->connectd_counter,
								 warning)));
		subd_send_msg(ld->connectd,
			      take(towire_connectd_discard_peer(NULL,
								&channel->peer->id,
								channel->peer->connectd_counter)));
		channel_fail_transient(channel, true, "Bad shutdown scriptpubkey %s",
				       tal_hex(tmpctx, scriptpubkey));
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
	struct peer_fd *peer_fd;
	struct channel *channel = dualopend->channel;

	if (!fromwire_dualopend_shutdown_complete(msg)) {
		channel_internal_error(dualopend->channel,
				       "Bad DUALOPEND_SHUTDOWN_COMPLETE: %s",
				       tal_hex(msg, msg));
		close(fds[0]);
		close(fds[1]);
		return;
	}

	peer_fd = new_peer_fd_arr(tmpctx, fds);

	peer_start_closingd(channel, peer_fd);
	channel_set_state(channel,
			  CHANNELD_SHUTTING_DOWN,
			  CLOSINGD_SIGEXCHANGE,
			  REASON_UNKNOWN,
			  "Start closingd");
}

struct channel_send {
	const struct wally_tx *wtx;
	struct channel *channel;
	const char *err_msg;
};

static void handle_tx_broadcast(struct channel_send *cs)
{
	struct lightningd *ld = cs->channel->peer->ld;
	const struct wally_tx *wtx = cs->wtx;
	struct channel *channel = cs->channel;
	struct command *cmd = channel->openchannel_signed_cmd;
	struct json_stream *response;
	struct bitcoin_txid txid;
	struct amount_sat unused;
	int num_utxos;

	/* This might have spent UTXOs from our wallet */
	num_utxos = wallet_extract_owned_outputs(ld->wallet,
						 /* FIXME: what txindex? */
						 wtx, false, NULL,
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

		cs->channel->openchannel_signed_cmd = NULL;
	}
}

static void check_utxo_block(struct bitcoind *bitcoind UNUSED,
			     const struct bitcoin_tx_output *txout,
			     void *arg)
{
	struct channel_send *cs = arg;
	struct command *cmd = cs->channel->openchannel_signed_cmd;
	const struct wally_tx *wtx = cs->wtx;

	/* note: if this tx has been included in a block *and spent*
	 * then this will also fail... */
	if (!txout) {
		if (cmd) {
			was_pending(command_fail(cmd,
						 FUNDING_BROADCAST_FAIL,
						 "Error broadcasting funding "
						 "tx: %s. Unsent tx discarded "
						 "%s.",
						 cs->err_msg,
						 fmt_wally_tx(tmpctx, wtx)));
			cs->channel->openchannel_signed_cmd = NULL;
		}

		log_unusual(cs->channel->log,
			    "Error broadcasting funding "
			    "tx: %s. Unsent tx discarded "
			    "%s.",
			    cs->err_msg,
			    fmt_wally_tx(tmpctx, wtx));
	} else
		handle_tx_broadcast(cs);

	tal_free(cs);
}

static void sendfunding_done(struct bitcoind *bitcoind UNUSED,
			     bool success, const char *msg,
			     struct channel_send *cs)
{
	struct lightningd *ld = cs->channel->peer->ld;
	struct channel *channel = cs->channel;
	struct command *cmd = channel->openchannel_signed_cmd;

	if (!cmd && channel->opener == LOCAL)
		log_unusual(channel->log,
			    "No outstanding command for channel %s,"
			    " funding sent was success? %d",
			    fmt_channel_id(tmpctx, &channel->cid),
			    success);

	if (success) {
		handle_tx_broadcast(cs);
		tal_free(cs);
	} else {
		/* If the tx was mined into a block, it's possible
		 * that the broadcast would fail. Verify that's not
		 * the case here. */
		cs->err_msg = tal_strdup(cs, msg);
		bitcoind_getutxout(ld->topology->bitcoind,
				   &channel->funding,
				   check_utxo_block,
				   cs);
	}
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
		tal_wally_end_onto(cs,
				   cast_const(struct wally_tx *,
					      cs->wtx), struct wally_tx);
	}

	wally_txid(wtx, &txid);
	log_debug(channel->log,
		  "Broadcasting funding tx %s for channel %s. %s",
		  fmt_bitcoin_txid(tmpctx, &txid),
		  fmt_channel_id(tmpctx, &channel->cid),
		  fmt_wally_tx(tmpctx, cs->wtx));

	bitcoind_sendrawtx(ld->topology->bitcoind,
			   ld->topology->bitcoind,
			   channel->open_attempt
			   ? (channel->open_attempt->cmd
			      ? channel->open_attempt->cmd->id
			      : NULL)
			   : NULL,
			   tal_hex(tmpctx, linearize_wtx(tmpctx, cs->wtx)),
			   false,
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
				       "No inflight found for channel");
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
					       fmt_wally_psbt(tmpctx,
							      inflight->funding_psbt));
			return;
		}

		/* Saves the now finalized version of the psbt */
		wallet_inflight_save(dualopend->ld->wallet, inflight);
		send_funding_tx(channel, take(wtx));

		/* Must be in an "init" state */
		assert(channel->state == DUALOPEND_OPEN_COMMITTED
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
					      &channel->funding_sats,
					      &channel->funding.txid,
					      channel->remote_channel_ready);

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
					       fmt_wally_psbt(tmpctx,
							      inflight->funding_psbt));

			/* Notify the peer we're failing */
			subd_send_msg(dualopend,
				      take(towire_dualopend_fail(NULL, errmsg)));
		}
	}
}

static void handle_dry_run_finished(struct subd *dualopend, const u8 *msg)
{
	struct json_stream *response;
	struct channel_id c_id;
	struct channel *channel = dualopend->channel;
	struct command *cmd;
	struct lease_rates *rates;
	struct amount_sat their_funding, our_funding;
	bool requires_confirms;

	assert(channel->open_attempt);
	cmd = channel->open_attempt->cmd;
	channel->open_attempt->cmd = NULL;

	if (!fromwire_dualopend_dry_run(msg, msg, &c_id,
					&our_funding,
					&their_funding,
					&requires_confirms,
					&rates)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_DRY_RUN_FINISHED: %s",
				       tal_hex(msg, msg));

		return;
	}

	/* Free up this open attempt */
	channel->open_attempt = tal_free(channel->open_attempt);

	response = json_stream_success(cmd);
	json_add_amount_sat_msat(response, "our_funding_msat", our_funding);
	json_add_amount_sat_msat(response, "their_funding_msat", their_funding);
	json_add_bool(response, "requires_confirmed_inputs", requires_confirms);

	if (rates) {
		json_add_lease_rates(response, rates);
		/* As a convenience, add a hexstring version of this data */
		json_add_string(response, "compact_lease",
				lease_rates_tohex(tmpctx, rates));
	}

	was_pending(command_success(cmd, response));
}

static void handle_peer_locked(struct subd *dualopend, const u8 *msg)
{
	struct pubkey remote_per_commit;
	struct channel *channel = dualopend->channel;
	struct short_channel_id *remote_alias;

	if (!fromwire_dualopend_peer_locked(msg, msg,
					    &remote_per_commit,
					    &remote_alias)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_PEER_LOCKED: %s",
				       tal_hex(msg, msg));
		return;
	}

	/* Updates channel with the next per-commit point etc, calls
	 * channel_internal_error on failure */
	if (!channel_on_channel_ready(channel, &remote_per_commit, remote_alias))
		return;

	/* Remember that we got the lock-in */
	wallet_channel_save(dualopend->ld->wallet, channel);
}

static void handle_channel_locked(struct subd *dualopend,
				  const int *fds,
				  const u8 *msg)
{
	struct channel *channel = dualopend->channel;
	struct peer_fd *peer_fd;

	if (!fromwire_dualopend_channel_locked(msg)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_CHANNEL_LOCKED: %s",
				       tal_hex(msg, msg));
		return;
	}
	peer_fd = new_peer_fd_arr(tmpctx, fds);

	assert(channel->scid);
	assert(channel->remote_channel_ready);

	/* This can happen if we missed their sigs, for some reason */
	if (channel->state != DUALOPEND_AWAITING_LOCKIN)
		log_debug(channel->log, "Lockin complete, but state %s",
			  channel_state_name(channel));

	channel_set_state(channel,
			  channel->state,
			  CHANNELD_NORMAL,
			  REASON_UNKNOWN,
			  "Lockin complete");
	channel_record_open(channel,
			    short_channel_id_blocknum(*channel->scid),
			    true);

	/* Empty out the inflights */
	wallet_channel_clear_inflights(dualopend->ld->wallet, channel);

	/* That freed watchers in inflights: now watch funding tx */
	channel_watch_funding(dualopend->ld, channel);

	/* FIXME: LND sigs/update_fee msgs? */
	peer_start_channeld(channel, peer_fd, NULL, false, NULL);
	return;
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

	if (!fromwire_dualopend_got_rbf_offer(payload, msg,
					      &payload->channel_id,
					      &payload->their_last_funding,
					      &payload->their_proposed_funding,
					      &payload->our_last_funding,
					      &payload->funding_feerate_per_kw,
					      &payload->locktime,
					      &payload->requested_lease_amt,
					      &payload->req_confirmed_ins_remote)) {
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

	payload->psbt = NULL;

	/* No error message known (yet) */
	payload->err_msg = NULL;

	if (feature_negotiated(dualopend->ld->our_features,
			       channel->peer->their_features,
			       OPT_LARGE_CHANNELS))
		payload->channel_max = chainparams->max_supply;
	else
		payload->channel_max = chainparams->max_funding;

	tal_add_destructor2(dualopend, rbf_channel_remove_dualopend, payload);
	plugin_hook_call_rbf_channel(dualopend->ld, NULL, payload);
}

static void accepter_got_offer(struct subd *dualopend,
			       struct channel *channel,
			       const u8 *msg)
{
	struct openchannel2_payload *payload;

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
	payload->rates = NULL;
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
					  &payload->shutdown_scriptpubkey,
					  &payload->requested_lease_amt,
					  &payload->lease_blockheight_start,
					  &payload->req_confirmed_ins_remote)) {
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
	payload->node_blockheight = get_block_height(dualopend->ld->topology);

	if (feature_negotiated(dualopend->ld->our_features,
			       channel->peer->their_features,
			       OPT_LARGE_CHANNELS))
		payload->channel_max = chainparams->max_supply;
	else
		payload->channel_max = chainparams->max_funding;

	tal_add_destructor2(dualopend, openchannel2_remove_dualopend, payload);
	plugin_hook_call_openchannel2(dualopend->ld, NULL, payload);
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
				       "No inflight found for channel");
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
				       fmt_wally_psbt(tmpctx,
						      inflight->funding_psbt),
				       fmt_wally_psbt(tmpctx,
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
					       fmt_wally_psbt(tmpctx,
							      inflight->funding_psbt));
			return;
		}

		send_funding_tx(channel, take(wtx));

		assert(channel->state == DUALOPEND_OPEN_COMMITTED
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
					      &channel->funding_sats,
					      &channel->funding.txid,
					      channel->remote_channel_ready);

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
					       fmt_wally_psbt(tmpctx,
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

static bool verify_option_will_fund_signature(struct peer *peer,
					      struct pubkey *funding_pubkey,
					      u32 lease_expiry,
					      u32 chan_fee_msat,
					      u16 chan_fee_ppt,
					      const secp256k1_ecdsa_signature *sig)

{
	struct pubkey their_pubkey;
	struct sha256 sha;
	int ret;

	lease_rates_get_commitment(funding_pubkey, lease_expiry,
				   chan_fee_msat, chan_fee_ppt,
				   &sha);

	if (!pubkey_from_node_id(&their_pubkey, &peer->id)) {
		log_broken(peer->ld->log,
			   "Unable to extract pubkey from peer's node id %s",
			   fmt_node_id(tmpctx, &peer->id));
		return false;
	}

	ret = secp256k1_ecdsa_verify(secp256k1_ctx, sig, sha.u.u8,
				     &their_pubkey.pubkey);
	return ret == 1;
}

static void handle_validate_lease(struct subd *dualopend,
				  const u8 *msg)
{
	const secp256k1_ecdsa_signature sig;
	u16 chan_fee_max_ppt;
	u32 chan_fee_max_base_msat, lease_expiry;
	struct pubkey their_pubkey;
	struct channel *chan;
	char *err_msg;

	if (!fromwire_dualopend_validate_lease(msg,
					       cast_const(secp256k1_ecdsa_signature *, &sig),
					       &lease_expiry,
					       &chan_fee_max_base_msat,
					       &chan_fee_max_ppt,
					       &their_pubkey)) {
		channel_internal_error(dualopend->channel,
				       "Bad DUALOPEND_VALIDATE_LEASE: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	assert(dualopend->channel);
	chan = dualopend->channel;

	if (!verify_option_will_fund_signature(chan->peer, &their_pubkey,
					       lease_expiry,
					       chan_fee_max_base_msat,
					       chan_fee_max_ppt,
					       &sig))
		err_msg = "Unable to verify sig";
	else
		err_msg = NULL;

	subd_send_msg(dualopend,
		      take(towire_dualopend_validate_lease_reply(NULL, err_msg)));
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
			const struct wally_psbt_input *input =
				&candidate_psbt->inputs[i];
			struct bitcoin_outpoint outpoint;

			wally_psbt_input_get_outpoint(input, &outpoint);

			if (!psbt_has_input(inflight->funding_psbt,
					    &outpoint))
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
				 fmt_wally_psbt(tmpctx,
						candidate_psbt),
				 fmt_wally_psbt(tmpctx,
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
				       fmt_amount_sat(tmpctx, candidate_fee),
				       fmt_amount_sat(tmpctx, last_fee));
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

	if (!param_check(cmd, buffer, params,
			 p_req("channel_id", param_channel_id, &cid),
			 NULL))
		return command_param_failed();

	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    fmt_channel_id(tmpctx, cid));

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

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Mark it as aborted so when we clean-up, we send the
	 * correct response */
	channel->open_attempt->aborted = true;
	channel->open_attempt->cmd = cmd;

	/* Tell dualopend to fail this channel */
	msg = towire_dualopend_fail(NULL, "Abort requested");
	subd_send_msg(channel->owner, take(msg));

	return command_still_pending(cmd);
}

static char *restart_dualopend(const tal_t *ctx, const struct lightningd *ld,
			       struct channel *channel, bool from_abort)
{
	int fds[2];
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		log_broken(channel->log,
			   "Failed to create socketpair: %s",
			   strerror(errno));
		return tal_fmt(ctx, "Unable to create socket: %s",
			       strerror(errno));
	}

	if (!peer_restart_dualopend(channel->peer,
				    new_peer_fd(tmpctx, fds[0]),
				    channel, from_abort)) {
		close(fds[1]);
		return tal_fmt(ctx, "Peer not connected");
	}
	subd_send_msg(ld->connectd,
		      take(towire_connectd_peer_connect_subd(NULL,
							     &channel->peer->id,
							     channel->peer->connectd_counter,
							     &channel->cid)));
	subd_send_fd(ld->connectd, fds[1]);
	return NULL;
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
	u32 last_feerate_perkw, next_feerate_min, *feerate_per_kw_funding;
	struct open_attempt *oa;
	struct channel_inflight *inflight;

	if (!param_check(cmd, buffer, params,
			 p_req("channel_id", param_channel_id, &cid),
			 p_req("amount", param_sat, &amount),
			 p_req("initialpsbt", param_psbt, &psbt),
			 p_opt("funding_feerate", param_feerate,
			       &feerate_per_kw_funding),
			 NULL))
		return command_param_failed();

	psbt_val = AMOUNT_SAT(0);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct amount_sat in_amt = psbt_input_get_amount(psbt, i);
		if (!amount_sat_add(&psbt_val, psbt_val, in_amt))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Overflow in adding PSBT input"
					    " values. %s",
					    fmt_wally_psbt(tmpctx, psbt));
	}

	/* If they don't pass in at least enough in the PSBT to cover
	 * their amount, nope */
	if (!amount_sat_greater(psbt_val, *amount))
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Provided PSBT cannot afford funding of "
				    "amount %s. %s",
				    fmt_amount_sat(tmpctx, *amount),
				    fmt_wally_psbt(tmpctx, psbt));

	if (!topology_synced(cmd->ld->topology)) {
		return command_fail(cmd, FUNDING_STILL_SYNCING_BITCOIN,
				    "Still syncing with bitcoin network");
	}

	/* Are we in a state where we can attempt an RBF? */
	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    fmt_channel_id(tmpctx, cid));

	last_feerate_perkw = channel_last_funding_feerate(channel);
	next_feerate_min = last_feerate_perkw * 65 / 64;
	assert(next_feerate_min > last_feerate_perkw);
	if (!feerate_per_kw_funding) {
		feerate_per_kw_funding = tal(cmd, u32);
		*feerate_per_kw_funding = next_feerate_min;
	} else if (*feerate_per_kw_funding < next_feerate_min)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Next feerate must be at least 1/64th"
				    " greater than the last. Min req %u,"
				    " you proposed %u",
				    next_feerate_min,
				    *feerate_per_kw_funding);

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
				    fmt_amount_sat(tmpctx,
						   chainparams->max_funding));

	/* It's possible that the last open failed/was aborted.
	 * So now we restart the attempt! */
	if (!channel->owner) {
		char *err = restart_dualopend(cmd, cmd->ld, channel, false);
		if (err)
			return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
					    "%s", err);
	}

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

	inflight = channel_current_inflight(channel);
	if (!inflight) {
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "No inflight for this channel exists.");
	}

	if (!inflight->remote_tx_sigs) {
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Funding sigs for this channel not "
				    "secured, see `openchannel_signed`");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);


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
				    fmt_wally_psbt(tmpctx, psbt));

	subd_send_msg(channel->owner,
		      take(towire_dualopend_rbf_init(NULL, *amount,
						     *feerate_per_kw_funding,
						     psbt)));
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

	if (!param_check(cmd, buffer, params,
			 p_req("channel_id", param_channel_id, &cid),
			 p_req("signed_psbt", param_psbt, &psbt),
			 NULL))
		return command_param_failed();

	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel");
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
	if (!bitcoin_txid_eq(&txid, &channel->funding.txid))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "Txid for passed in PSBT does not match"
				    " funding txid for channel. Expected %s, "
				    "received %s",
				    fmt_bitcoin_txid(tmpctx,
						     &channel->funding.txid),
				    fmt_bitcoin_txid(tmpctx,
						     &txid));

	inflight = list_tail(&channel->inflights,
			     struct channel_inflight,
			     list);
	if (!inflight)
		return command_fail(cmd, LIGHTNINGD,
				    "Open attempt for channel not found");

	if (!bitcoin_txid_eq(&txid, &inflight->funding->outpoint.txid))
		return command_fail(cmd, LIGHTNINGD,
				    "Current inflight transaction is %s,"
				    " not %s",
				    fmt_bitcoin_txid(tmpctx,
						     &txid),
				    fmt_bitcoin_txid(tmpctx,
						     &inflight->funding
						     ->outpoint.txid));

	if (!inflight->last_tx)
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Commitments for this channel not "
				    "yet secured, see `openchannel_update`");

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

	if (command_check_only(cmd))
		return command_check_done(cmd);

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
	tal_wally_end_onto(inflight, inflight->funding_psbt, struct wally_psbt);

	/* Update the PSBT on disk */
	wallet_inflight_save(cmd->ld->wallet, inflight);
	watch_opening_inflight(cmd->ld, inflight);

	/* Only after we've updated/saved our psbt do we check
	 * for peer connected */
	if (!channel->owner)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");

	/* Send our tx_sigs to the peer */
	subd_send_msg(channel->owner,
		      take(towire_dualopend_send_tx_sigs(NULL,
							 inflight->funding_psbt)));

	channel->openchannel_signed_cmd = tal_steal(channel, cmd);
	return command_still_pending(cmd);
}

struct psbt_validator {
	struct command *cmd;
	struct channel *channel;
	struct wally_psbt *psbt;
	enum tx_role role_to_validate;
	size_t next_index;

	/* on success */
	void (*success)(struct psbt_validator *pv);

	/* on invalid psbt input */
	void (*invalid_input)(struct psbt_validator *pv, const char *err_msg);
};

static void validate_input_unspent(struct bitcoind *bitcoind,
				   const struct bitcoin_tx_output *txout,
				   void *arg)
{
	struct psbt_validator *pv = arg;
	char *err;

	/* First time thru bitcoind will be NULL, otherwise is response */
	if (bitcoind && !txout) {
		struct bitcoin_outpoint outpoint;

		assert(pv->next_index > 0);
		wally_psbt_input_get_outpoint(&pv->psbt->inputs[pv->next_index - 1],
					    &outpoint);

		err = tal_fmt(pv, "Requested only confirmed"
			      " inputs for this open."
			      " Input %s is not confirmed.",
			      fmt_bitcoin_outpoint(tmpctx, &outpoint));
		pv->invalid_input(pv, err);
		return;
	}

	for (size_t i = pv->next_index; i < pv->psbt->num_inputs; i++) {
		struct bitcoin_outpoint outpoint;
		u64 serial;

		if (!psbt_get_serial_id(&pv->psbt->inputs[i].unknowns, &serial)) {
			err = tal_fmt(pv, "PSBT input at index %zu"
				      " missing serial id", i);
			pv->invalid_input(pv, err);
			return;
		}
		/* Ignore any input that's not what we're looking for  */
		if (serial % 2 != pv->role_to_validate)
			continue;

		wally_psbt_input_get_outpoint(&pv->psbt->inputs[i],
					      &outpoint);
		pv->next_index = i + 1;

		/* Confirm input is in a block */
		bitcoind_getutxout(pv->channel->owner->ld->topology->bitcoind,
				   &outpoint,
				   validate_input_unspent,
				   pv);
		return;
	}

	pv->success(pv);
}

static void openchannel_update_valid_psbt(struct psbt_validator *pv)
{
	u8 *msg;
	assert(pv->cmd);
	pv->channel->open_attempt->cmd = pv->cmd;

	msg = towire_dualopend_psbt_updated(NULL, pv->psbt);
	subd_send_msg(pv->channel->owner, take(msg));
}

static void openchannel_invalid_psbt(struct psbt_validator *pv, const char *err_msg)
{
	assert(pv->cmd);
	was_pending(command_fail(pv->cmd,
				 FUNDING_PSBT_INVALID,
				 "%s", err_msg));
}

static struct channel_inflight *find_inprogress_inflight(struct channel *channel,
							 struct wally_psbt *psbt)
{
	struct channel_inflight *inflight;
	struct bitcoin_txid txid;

	inflight = channel_current_inflight(channel);
	if (!inflight)
		return NULL;

	/* check if psbt txid matches? */
	psbt_txid(NULL, psbt, &txid, NULL);
	if (!bitcoin_txid_eq(&inflight->funding->outpoint.txid, &txid))
		return NULL;

	return inflight;
}

static struct json_stream *build_commit_response(struct command *cmd,
						 struct channel *channel,
						 struct channel_inflight *inflight)
{
	struct json_stream *response;

	response = json_stream_success(cmd);
	json_add_string(response, "channel_id",
			fmt_channel_id(tmpctx, &channel->cid));
	json_add_psbt(response, "psbt", inflight->funding_psbt);
	json_add_channel_type(response, "channel_type", channel->type);
	json_add_bool(response, "commitments_secured", inflight->last_tx != NULL);
	/* For convenience sake, we include the funding outnum */
	assert(inflight->funding);
	json_add_num(response, "funding_outnum", inflight->funding->outpoint.n);
	/* This is *sort of* dicey, since there's a small chance the channel
	 * might disconnect/reconnect and we lose the open-attempt data */
	if (channel->open_attempt && channel->open_attempt->our_upfront_shutdown_script) {
		/* FIXME: also include the output as address */
		json_add_hex_talarr(response, "close_to",
				    channel->open_attempt->our_upfront_shutdown_script);
	/* Worse case is that we accidentally report what we're 'closing-to' even if you
	 * didn't request it? We *could* just announce it every time... */
	} else if (!channel->open_attempt && channel->shutdown_scriptpubkey[LOCAL]) {
		json_add_hex_talarr(response, "close_to",
				    channel->shutdown_scriptpubkey[LOCAL]);
		/* FIXME: also include the output as address */
	}
	return response;
}

static struct command_result *json_openchannel_update(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	struct wally_psbt *psbt;
	struct channel_id *cid;
	struct channel *channel;
	struct psbt_validator *pv;
	struct command_result *ret;
	struct channel_inflight *inflight;

	if (!param_check(cmd, buffer, params,
			 p_req("channel_id", param_channel_id, &cid),
			 p_req("psbt", param_psbt, &psbt),
			 NULL))
		return command_param_failed();

	channel = channel_by_cid(cmd->ld, cid);
	if (!channel)
		return command_fail(cmd, FUNDING_UNKNOWN_CHANNEL,
				    "Unknown channel %s",
				    fmt_channel_id(tmpctx, cid));
	if (!channel->owner)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer not connected");


	if (!channel->open_attempt) {
		/* Check if the last inflight for this matches? */
		inflight = find_inprogress_inflight(channel, psbt);
		if (inflight) {
			return command_success(cmd,
				       build_commit_response(cmd, channel, inflight));
		}
		return command_fail(cmd, FUNDING_STATE_INVALID,
				    "Channel open not in progress");
	}

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
				    fmt_wally_psbt(tmpctx, psbt));

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Set up the psbt-validator, we only validate in the
	 * case of requiring confirmations */
	pv = tal(cmd, struct psbt_validator);
	pv->cmd = cmd;
	pv->channel = channel;
	pv->next_index = 0;
	pv->psbt = psbt;
	pv->role_to_validate = TX_INITIATOR;
	pv->success = openchannel_update_valid_psbt;
	pv->invalid_input = openchannel_invalid_psbt;

	if (channel->req_confirmed_ins[REMOTE]) {
		/* We might fail/terminate in validate's first call,
		 * which expects us to be at "command still pending" */
		ret = command_still_pending(cmd);
		validate_input_unspent(NULL, NULL, pv);
		return ret;
	}

	/* Jump straight to the end here! */
	openchannel_update_valid_psbt(pv);
	return command_still_pending(cmd);
}

static struct command_result *init_set_feerate(struct command *cmd,
					       u32 **feerate_per_kw,
					       u32 **feerate_per_kw_funding)

{
	if (!*feerate_per_kw_funding) {
		*feerate_per_kw_funding = tal(cmd, u32);
		**feerate_per_kw_funding = opening_feerate(cmd->ld->topology);
		if (!**feerate_per_kw_funding)
			return command_fail(cmd, LIGHTNINGD,
					    "`funding_feerate` not specified and fee "
					    "estimation failed");
	}
	if (!*feerate_per_kw) {
		*feerate_per_kw = tal(cmd, u32);
		**feerate_per_kw = **feerate_per_kw_funding;
	}

	return NULL;
}

static struct command_result *openchannel_init(struct command *cmd,
					       struct peer *peer,
					       struct amount_sat amount,
					       struct amount_sat request_amt,
					       const struct wally_psbt *psbt,
					       u32 feerate_per_kw_funding,
					       u32 feerate_per_kw,
					       const u8 *our_upfront_shutdown_script,
					       bool announce_channel,
					       const struct lease_rates *rates,
					       const struct channel_type *ctype)
{
	u32 *our_upfront_shutdown_script_wallet_index;
	u32 found_wallet_index;
	struct channel *channel;
	struct open_attempt *oa;
	int fds[2];

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		return command_fail(cmd, FUND_MAX_EXCEEDED,
				    "Failed to create socketpair: %s",
				    strerror(errno));
	}

	/* Now we can't fail, create channel */
	channel = new_unsaved_channel(peer,
				      peer->ld->config.fee_base,
				      peer->ld->config.fee_per_satoshi);
	/* We derive initial channel_id *now*, so we can tell it to connectd. */
	derive_tmp_channel_id(&channel->cid,
			      &channel->local_basepoints.revocation);

	/* Get a new open_attempt going */
	channel->opener = LOCAL;
	channel->open_attempt = oa = new_channel_open_attempt(channel);
	channel->channel_flags = OUR_CHANNEL_FLAGS;
	oa->funding = amount;
	oa->cmd = cmd;

	if (!announce_channel) {
		channel->channel_flags &= ~CHANNEL_FLAGS_ANNOUNCE_CHANNEL;
		log_info(peer->ld->log,
			 "Will open private channel with node %s",
			 fmt_node_id(tmpctx, &peer->id));
	}

	/* Needs to be stolen away from cmd */
	if (our_upfront_shutdown_script)
		oa->our_upfront_shutdown_script
			= tal_steal(oa, our_upfront_shutdown_script);

	/* Determine the wallet index for our_upfront_shutdown_script,
	 * NULL if not found. */
	if (wallet_can_spend(cmd->ld->wallet,
			     oa->our_upfront_shutdown_script,
			     &found_wallet_index)) {
		our_upfront_shutdown_script_wallet_index = &found_wallet_index;
	} else
		our_upfront_shutdown_script_wallet_index = NULL;

	oa->open_msg = towire_dualopend_opener_init(oa,
					   psbt, amount,
					   oa->our_upfront_shutdown_script,
					   our_upfront_shutdown_script_wallet_index,
					   feerate_per_kw,
					   unilateral_feerate(cmd->ld->topology, true),
					   feerate_per_kw_funding,
					   channel->channel_flags,
					   amount_sat_zero(request_amt) ?
						NULL : &request_amt,
					   get_block_height(cmd->ld->topology),
					   false,
					   ctype,
					   rates);

	/* Start dualopend! */
	if (!peer_start_dualopend(peer, new_peer_fd(cmd, fds[0]), channel)) {
		close(fds[1]);
		/* FIXME: gets completed by failure path above! */
		return command_its_complicated("completed by peer_start_dualopend");
	}

	/* Go! */
	subd_send_msg(channel->owner, channel->open_attempt->open_msg);

	/* Tell connectd connect this to this channel id. */
	subd_send_msg(peer->ld->connectd,
		      take(towire_connectd_peer_connect_subd(NULL,
							     &peer->id,
							     peer->connectd_counter,
							     &channel->cid)));
	subd_send_fd(peer->ld->connectd, fds[1]);
	return command_still_pending(cmd);
}

struct openchannel_init_info {
	struct command *cmd;
	struct node_id *id;
	struct amount_sat *amount, *request_amt;
	struct wally_psbt *psbt;
	u32 *feerate_per_kw_funding, *feerate_per_kw;
	const u8 *our_upfront_shutdown_script;
	bool *announce_channel;
	struct lease_rates *rates;
	struct channel_type *ctype;
};

static void openchannel_init_after_sync(struct chain_topology *topo,
					struct openchannel_init_info *info)
{
	struct peer *peer;

	/* Look up peer again in case it's gone! */
	peer = peer_by_id(info->cmd->ld, info->id);
	if (!peer) {
		was_pending(command_fail(info->cmd, FUNDING_UNKNOWN_PEER, "Unknown peer"));
		return;
	}

	if (!feature_negotiated(info->cmd->ld->our_features,
			        peer->their_features,
				OPT_DUAL_FUND)) {
		was_pending(command_fail(info->cmd, FUNDING_V2_NOT_SUPPORTED,
					 "v2 openchannel not supported "
					 "by peer"));
		return;
	}

	openchannel_init(info->cmd, peer,
			 *info->amount,
			 *info->request_amt,
			 info->psbt,
			 *info->feerate_per_kw_funding, *info->feerate_per_kw,
			 info->our_upfront_shutdown_script,
			 *info->announce_channel,
			 info->rates, info->ctype);
}

static struct command_result *json_openchannel_init(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *obj UNNEEDED,
						    const jsmntok_t *params)
{
	struct openchannel_init_info *info = tal(cmd, struct openchannel_init_info);
	struct peer *peer;
	struct amount_sat psbt_val;
	struct command_result *res;

	info->cmd = cmd;
	if (!param_check(cmd, buffer, params,
			 p_req("id", param_node_id, &info->id),
			 p_req("amount", param_sat, &info->amount),
			 p_req("initialpsbt", param_psbt, &info->psbt),
			 p_opt("commitment_feerate", param_feerate, &info->feerate_per_kw),
			 p_opt("funding_feerate", param_feerate, &info->feerate_per_kw_funding),
			 p_opt_def("announce", param_bool, &info->announce_channel, true),
			 p_opt("close_to", param_bitcoin_address, &info->our_upfront_shutdown_script),
			 p_opt_def("request_amt", param_sat, &info->request_amt, AMOUNT_SAT(0)),
			 p_opt("compact_lease", param_lease_hex, &info->rates),
			 p_opt("channel_type", param_channel_type, &info->ctype),
			 NULL))
		return command_param_failed();

	/* We only deal in v2 */
	if (!psbt_set_version(info->psbt, 2)) {
		return command_fail(cmd, LIGHTNINGD, "Could not set PSBT version.");
	}

	/* Gotta expect some rates ! */
	if (!amount_sat_zero(*info->request_amt) && !info->rates)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must pass in 'compact_lease' if requesting"
				    " funds from peer");
	psbt_val = AMOUNT_SAT(0);
	for (size_t i = 0; i < info->psbt->num_inputs; i++) {
		struct amount_sat in_amt = psbt_input_get_amount(info->psbt, i);
		if (!amount_sat_add(&psbt_val, psbt_val, in_amt))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Overflow in adding PSBT input"
					    " values. %s",
					    fmt_wally_psbt(tmpctx, info->psbt));
	}

	/* If they don't pass in at least enough in the PSBT to cover
	 * their amount, nope */
	if (!amount_sat_greater(psbt_val, *info->amount))
		return command_fail(cmd, FUND_CANNOT_AFFORD,
				    "Provided PSBT cannot afford funding of "
				    "amount %s. %s",
				    fmt_amount_sat(tmpctx, *info->amount),
				    fmt_wally_psbt(tmpctx, info->psbt));

	res = init_set_feerate(cmd, &info->feerate_per_kw, &info->feerate_per_kw_funding);
	if (res)
		return res;

	peer = peer_by_id(cmd->ld, info->id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	if (!feature_negotiated(cmd->ld->our_features,
			        peer->their_features,
				OPT_DUAL_FUND)) {
		return command_fail(cmd, FUNDING_V2_NOT_SUPPORTED,
				    "v2 openchannel not supported "
				    "by peer");
	}

	if (info->ctype &&
	    !cmd->ld->dev_any_channel_type &&
	    !channel_type_accept(tmpctx,
				 info->ctype->features,
				 cmd->ld->our_features)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "channel_type not supported");
	}

	/* BOLT #2:
	 *  - if both nodes advertised `option_support_large_channel`:
	 *    - MAY set `funding_satoshis` greater than or equal to 2^24 satoshi.
	 *  - otherwise:
	 *    - MUST set `funding_satoshis` to less than 2^24 satoshi.
	 */
	if (!feature_negotiated(cmd->ld->our_features,
				peer->their_features, OPT_LARGE_CHANNELS)
	    && amount_sat_greater(*info->amount, chainparams->max_funding))
		return command_fail(cmd, FUND_MAX_EXCEEDED,
				    "Amount exceeded %s",
				    fmt_amount_sat(tmpctx, chainparams->max_funding));

	/* Add serials to any input that's missing them */
	psbt_add_serials(info->psbt, TX_INITIATOR);

	/* We require the PSBT to meet certain criteria such as
	 * extra, proprietary fields (`serial_id`s) or
	 * to have a `redeemscripts` iff the inputs are P2SH.
	 *
	 * Since this is externally provided, we confirm that
	 * they've done the right thing / haven't lost any required info.
	 */
	if (!psbt_has_required_fields(info->psbt))
		return command_fail(cmd, FUNDING_PSBT_INVALID,
				    "PSBT is missing required fields %s",
				    fmt_wally_psbt(tmpctx, info->psbt));

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!topology_synced(cmd->ld->topology)) {
		json_notify_fmt(cmd, LOG_UNUSUAL,
				"Waiting to sync with bitcoind network (block %u of %u)",
				get_block_height(cmd->ld->topology),
				get_network_blockheight(cmd->ld->topology));

		topology_add_sync_waiter(cmd, cmd->ld->topology,
					 openchannel_init_after_sync,
					 info);
		return command_still_pending(cmd);
	}

	return openchannel_init(cmd, peer,
				*info->amount,
				*info->request_amt,
				info->psbt,
				*info->feerate_per_kw_funding, *info->feerate_per_kw,
				info->our_upfront_shutdown_script,
				*info->announce_channel,
				info->rates, info->ctype);
}

static void psbt_request_valid(struct psbt_validator *pv)
{
	struct subd *dualopend = pv->channel->owner;

	if (!dualopend)
		goto done;

	assert(!pv->cmd);
	subd_send_msg(dualopend,
		      take(towire_dualopend_validate_inputs_reply(NULL)));
done:
	tal_free(pv);
}

static void psbt_request_invalid(struct psbt_validator *pv, const char *err_msg)
{
	struct subd *dualopend = pv->channel->owner;

	if (!dualopend)
		goto done;

	assert(!pv->cmd);
	subd_send_msg(dualopend,
		      take(towire_dualopend_fail(NULL, err_msg)));

done:
	tal_free(pv);
}

static void handle_update_require_confirmed(struct subd *dualopend,
					    const u8 *msg)
{
	bool require_confirmed;
	struct channel *channel = dualopend->channel;

	if (!fromwire_dualopend_update_require_confirmed(msg, &require_confirmed)) {
		channel_internal_error(dualopend->channel,
				       "Bad DUALOPEND_UPDATE_REQUIRE_CONFIRMED: %s",
				       tal_hex(msg, msg));
		return;
	}

	if (channel->req_confirmed_ins[REMOTE] != require_confirmed) {
		channel->req_confirmed_ins[REMOTE] = require_confirmed;
		wallet_channel_save(dualopend->ld->wallet, channel);
	}
}

static void handle_validate_inputs(struct subd *dualopend,
				   const u8 *msg)
{
	struct psbt_validator *pv;
	pv = tal(NULL, struct psbt_validator);

	if (!fromwire_dualopend_validate_inputs(pv, msg,
						&pv->psbt,
						&pv->role_to_validate)) {
		channel_internal_error(dualopend->channel,
				       "Bad DUALOPEND_VALIDATE_INPUTS: %s",
				       tal_hex(msg, msg));
		return;
	}

	log_debug(dualopend->ld->log,
		  "validating psbt for role: %s",
		  pv->role_to_validate == TX_INITIATOR ?
			"initiator" : "accepter");

	pv->cmd = NULL;
	pv->channel = dualopend->channel;
	pv->next_index = 0;
	pv->success = psbt_request_valid;
	pv->invalid_input = psbt_request_invalid;
	validate_input_unspent(NULL, NULL, pv);
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
	struct channel_type *channel_type;

	assert(channel->open_attempt);
	oa = channel->open_attempt;
	cmd = oa->cmd;

	if (!fromwire_dualopend_psbt_changed(tmpctx, msg,
					     &cid,
					     &channel->req_confirmed_ins[REMOTE],
					     &funding_serial,
					     &psbt,
					     &channel_type)) {
		channel_internal_error(channel,
				       "Bad DUALOPEND_PSBT_CHANGED: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* This is often the first time we hear about channel details */
	tal_free(channel->type);
	channel->type = tal_steal(channel, channel_type);

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
				fmt_channel_id(tmpctx, &channel->cid));
		json_add_psbt(response, "psbt", psbt);
		json_add_channel_type(response, "channel_type", channel->type);
		json_add_bool(response, "commitments_secured", false);
		json_add_u64(response, "funding_serial", funding_serial);
		json_add_bool(response, "requires_confirmed_inputs",
			      channel->req_confirmed_ins[REMOTE]);

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
		plugin_hook_call_openchannel2_changed(dualopend->ld, NULL, payload);
		return;
	}
	abort();
}

static void handle_commit_ready(struct subd *dualopend,
				struct channel *channel,
				const u8 *msg)
{
	struct lightningd *ld = dualopend->ld;
	struct channel_info channel_info;
	struct bitcoin_outpoint funding;
	u16 lease_chan_max_ppt;
	u32 feerate_funding, feerate_commitment, lease_expiry,
	    lease_chan_max_msat, lease_blockheight_start;
	struct amount_sat total_funding, funding_ours, lease_fee, lease_amt;
	u8 *remote_upfront_shutdown_script,
	   *local_upfront_shutdown_script;
	struct wally_psbt *psbt;
	struct channel_inflight *inflight;
	struct channel_type *channel_type;
	secp256k1_ecdsa_signature *lease_commit_sig;

	if (!fromwire_dualopend_commit_ready(tmpctx, msg,
					     &channel_info.their_config,
					     &psbt,
					     &channel_info.theirbase.revocation,
					     &channel_info.theirbase.payment,
					     &channel_info.theirbase.htlc,
					     &channel_info.theirbase.delayed_payment,
					     &channel_info.remote_per_commit,
					     &channel_info.remote_fundingkey,
					     &funding,
					     &total_funding,
					     &funding_ours,
					     &channel->channel_flags,
					     &feerate_funding,
					     &feerate_commitment,
					     &local_upfront_shutdown_script,
					     &remote_upfront_shutdown_script,
					     &lease_amt,
					     &lease_blockheight_start,
					     &lease_expiry,
					     &lease_fee,
					     &lease_commit_sig,
					     &lease_chan_max_msat,
					     &lease_chan_max_ppt,
					     &channel_type)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_COMMIT_READY: %s",
				       tal_hex(msg, msg));
		channel->open_attempt = tal_free(channel->open_attempt);
		notify_channel_open_failed(channel->peer->ld, &channel->cid);
		return;
	}

	/* We need to update the channel reserve on the config */
	channel_update_reserve(channel,
			       &channel_info.their_config,
			       total_funding);

	/* First time (not an RBF) */
	if (channel->state == DUALOPEND_OPEN_INIT) {
		/* Now we know if it's public or not, we can init channel_gossip */
		assert(channel->channel_gossip == NULL);
		channel_gossip_init(channel, NULL);
		if (!(inflight = wallet_commit_channel(ld, channel,
						       &funding,
						       total_funding,
						       funding_ours,
						       &channel_info,
						       feerate_funding,
						       feerate_commitment,
						       local_upfront_shutdown_script,
						       remote_upfront_shutdown_script,
						       psbt,
						       lease_amt,
						       lease_blockheight_start,
						       lease_expiry,
						       lease_fee,
						       lease_commit_sig,
						       lease_chan_max_msat,
						       lease_chan_max_ppt,
						       channel_type))) {
			channel_internal_error(channel,
					       "wallet_commit_channel failed"
					       " (chan %s)",
					       fmt_channel_id(tmpctx,
							      &channel->cid));
			channel->open_attempt
				= tal_free(channel->open_attempt);
			return;
		}

	} else {
		/* We're doing an RBF */
		assert(channel->state == DUALOPEND_AWAITING_LOCKIN);

		if (!(inflight = wallet_update_channel(ld, channel,
						       &funding,
						       total_funding,
						       funding_ours,
						       feerate_funding,
						       psbt,
						       lease_expiry,
						       lease_fee,
						       lease_commit_sig,
						       lease_chan_max_msat,
						       lease_chan_max_ppt,
						       lease_blockheight_start,
						       lease_amt))) {
			channel_internal_error(channel,
					       "wallet_update_channel failed"
					       " (chan %s)",
					       fmt_channel_id(tmpctx,
							      &channel->cid));
			channel->open_attempt
				= tal_free(channel->open_attempt);
			return;
		}

	}

	/* Send back ack! */
	subd_send_msg(dualopend,
		      take(towire_dualopend_commit_send_ack(NULL)));

}

static void handle_commit_received(struct subd *dualopend,
				   struct channel *channel,
				   const u8 *msg)
{
	struct lightningd *ld = dualopend->ld;
	struct bitcoin_tx *remote_commit;
	struct bitcoin_signature remote_commit_sig;
	struct penalty_base *pbase;
	struct json_stream *response;
	struct openchannel2_psbt_payload *payload;
	struct channel_inflight *inflight;
	struct command *cmd;
	bool updated;

	if (!fromwire_dualopend_commit_rcvd(tmpctx, msg,
					    &remote_commit,
					    &remote_commit_sig,
					    &pbase)) {
		channel_internal_error(channel,
				       "Bad WIRE_DUALOPEND_COMMIT_RCVD: %s",
				       tal_hex(msg, msg));
		channel->open_attempt = tal_free(channel->open_attempt);
		notify_channel_open_failed(channel->peer->ld, &channel->cid);
		return;
	}

	inflight = channel_current_inflight(channel);
	if (!inflight) {
		channel_internal_error(channel,
				       "No inflight found for channel");
		return;
	}

	updated = wallet_update_channel_commit(ld, channel, inflight,
					       remote_commit,
					       &remote_commit_sig);

	/* FIXME: handle RBF pbases */
	if (pbase && channel->state != DUALOPEND_AWAITING_LOCKIN) {
		wallet_penalty_base_add(ld->wallet,
					channel->dbid,
					pbase);
	}

	switch (channel->opener) {
	case LOCAL:
		if (!channel->open_attempt || !channel->open_attempt->cmd) {
			log_info(channel->log, "No channel open attempt/command!");
			channel->open_attempt
				= tal_free(channel->open_attempt);
			return;
		}
		cmd = channel->open_attempt->cmd;
		response = build_commit_response(cmd, channel, inflight);
		channel->open_attempt
			= tal_free(channel->open_attempt);
		was_pending(command_success(cmd, response));
		return;
	case REMOTE:
		if (!updated) {
			log_info(channel->log, "Already had sigs, skipping notif");
			return;
		}
		payload = tal(dualopend, struct openchannel2_psbt_payload);
		payload->ld = ld;
		payload->dualopend = dualopend;
		tal_add_destructor2(dualopend,
				    openchannel2_psbt_remove_dualopend,
				    payload);
		payload->channel = channel;
		payload->psbt = clone_psbt(payload, inflight->funding_psbt);

		if (channel->open_attempt)
			channel->open_attempt
				= tal_free(channel->open_attempt);

		/* We don't have a command, so set to NULL here */
		payload->channel->openchannel_signed_cmd = NULL;
		/* We call out to hook who will
		 * provide signatures for us! */
		plugin_hook_call_openchannel2_sign(ld, NULL, payload);
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
		case WIRE_DUALOPEND_COMMIT_READY:
			handle_commit_ready(dualopend, channel, msg);
			return 0;
		case WIRE_DUALOPEND_COMMIT_RCVD:
			handle_commit_received(dualopend, channel, msg);
			return 0;
		case WIRE_DUALOPEND_RBF_VALIDATE:
			handle_validate_rbf(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_VALIDATE_LEASE:
			handle_validate_lease(dualopend, msg);
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
		case WIRE_DUALOPEND_DRY_RUN:
			handle_dry_run_finished(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_CHANNEL_LOCKED:
			if (tal_count(fds) != 1)
				return 1;
			handle_channel_locked(dualopend, fds, msg);
			return 0;
		case WIRE_DUALOPEND_GOT_SHUTDOWN:
			handle_peer_wants_to_close(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_SHUTDOWN_COMPLETE:
			if (tal_count(fds) != 1)
				return 1;
			handle_channel_closed(dualopend, fds, msg);
			return 0;
		case WIRE_DUALOPEND_FAIL_FALLEN_BEHIND:
			channel_fail_fallen_behind(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_VALIDATE_INPUTS:
			handle_validate_inputs(dualopend, msg);
			return 0;
		case WIRE_DUALOPEND_UPDATE_REQUIRE_CONFIRMED:
			handle_update_require_confirmed(dualopend, msg);
			return 0;
		/* Messages we send */
		case WIRE_DUALOPEND_INIT:
		case WIRE_DUALOPEND_REINIT:
		case WIRE_DUALOPEND_OPENER_INIT:
		case WIRE_DUALOPEND_COMMIT_SEND_ACK:
		case WIRE_DUALOPEND_RBF_INIT:
		case WIRE_DUALOPEND_GOT_OFFER_REPLY:
		case WIRE_DUALOPEND_GOT_RBF_OFFER_REPLY:
		case WIRE_DUALOPEND_VALIDATE_INPUTS_REPLY:
		case WIRE_DUALOPEND_RBF_VALID:
		case WIRE_DUALOPEND_VALIDATE_LEASE_REPLY:
		case WIRE_DUALOPEND_FAIL:
		case WIRE_DUALOPEND_PSBT_UPDATED:
		case WIRE_DUALOPEND_SEND_TX_SIGS:
		case WIRE_DUALOPEND_SEND_SHUTDOWN:
		case WIRE_DUALOPEND_DEPTH_REACHED:
		case WIRE_DUALOPEND_DEV_MEMLEAK:
		case WIRE_DUALOPEND_DEV_MEMLEAK_REPLY:
			break;
	}

	log_broken(dualopend->log, "Unexpected msg %s: %s",
		   dualopend_wire_name(t), tal_hex(tmpctx, msg));
	tal_free(dualopend);
	return 0;
}

static struct command_result *json_queryrates(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct node_id *id;
	struct peer *peer;
	struct channel *channel;
	u32 *feerate_per_kw_funding;
	u32 *feerate_per_kw;
	struct amount_sat *amount, *request_amt;
	struct wally_psbt *psbt;
	struct open_attempt *oa;
	u32 *our_upfront_shutdown_script_wallet_index;
	struct command_result *res;
	int fds[2];

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_node_id, &id),
			 p_req("amount", param_sat, &amount),
			 p_req("request_amt", param_sat, &request_amt),
			 p_opt("commitment_feerate", param_feerate, &feerate_per_kw),
			 p_opt("funding_feerate", param_feerate, &feerate_per_kw_funding),
			 NULL))
		return command_param_failed();

	res = init_set_feerate(cmd, &feerate_per_kw, &feerate_per_kw_funding);
	if (res)
		return res;

	peer = peer_by_id(cmd->ld, id);
	if (!peer) {
		return command_fail(cmd, FUNDING_UNKNOWN_PEER, "Unknown peer");
	}

	if (peer->connected != PEER_CONNECTED)
		return command_fail(cmd, FUNDING_PEER_NOT_CONNECTED,
				    "Peer %s",
				    peer->connected == PEER_DISCONNECTED
				    ? "not connected" : "still connecting");

	if (!feature_negotiated(cmd->ld->our_features,
			        peer->their_features,
				OPT_DUAL_FUND)) {
		return command_fail(cmd, FUNDING_V2_NOT_SUPPORTED,
				    "v2 openchannel not supported "
				    "by peer, can't query rates");
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
				    fmt_amount_sat(tmpctx,
						   chainparams->max_funding));

	if (command_check_only(cmd))
		return command_check_done(cmd);

	channel = new_unsaved_channel(peer,
				      peer->ld->config.fee_base,
				      peer->ld->config.fee_per_satoshi);

	/* We derive initial channel_id *now*, so we can tell it to
	 * connectd. */
	derive_tmp_channel_id(&channel->cid,
			      &channel->local_basepoints.revocation);

	/* Get a new open_attempt going, keeps us from re-initing
	 * while looking */
	channel->opener = LOCAL;
	channel->open_attempt = oa = new_channel_open_attempt(channel);
	channel->channel_flags = OUR_CHANNEL_FLAGS;
	oa->funding = *amount;
	oa->cmd = cmd;
	/* empty psbt to start */
	psbt = create_psbt(tmpctx, 0, 0, 0);

	/* Determine the wallet index for our_upfront_shutdown_script,
	 * NULL if not found. */
	u32 found_wallet_index;
	if (wallet_can_spend(cmd->ld->wallet,
			     oa->our_upfront_shutdown_script,
			     &found_wallet_index)) {
		our_upfront_shutdown_script_wallet_index = tal(tmpctx, u32);
		*our_upfront_shutdown_script_wallet_index = found_wallet_index;
	} else
		our_upfront_shutdown_script_wallet_index = NULL;

	oa->open_msg = towire_dualopend_opener_init(oa,
					   psbt, *amount,
					   oa->our_upfront_shutdown_script,
					   our_upfront_shutdown_script_wallet_index,
					   *feerate_per_kw,
					   unilateral_feerate(cmd->ld->topology, true),
					   *feerate_per_kw_funding,
					   channel->channel_flags,
					   amount_sat_zero(*request_amt) ?
						NULL : request_amt,
					   get_block_height(cmd->ld->topology),
					   true,
					   NULL, NULL);

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0) {
		return command_fail(cmd, FUND_MAX_EXCEEDED,
				    "Failed to create socketpair: %s",
				    strerror(errno));
	}

	/* Start dualopend! */
	if (!peer_start_dualopend(peer, new_peer_fd(cmd, fds[0]), channel)) {
		close(fds[1]);
		/* FIXME: gets completed by failure path above! */
		return command_its_complicated("completed by peer_start_dualopend");
	}

	/* Go! */
	subd_send_msg(channel->owner, channel->open_attempt->open_msg);

	/* Tell connectd connect this to this channel id. */
	subd_send_msg(peer->ld->connectd,
		      take(towire_connectd_peer_connect_subd(NULL,
							     &peer->id,
							     peer->connectd_counter,
							     &channel->cid)));
	subd_send_fd(peer->ld->connectd, fds[1]);
 	return command_still_pending(cmd);
 }

static const struct json_command queryrates_command = {
	"dev-queryrates",
	"channels",
	json_queryrates,
	"Ask a peer what their contribution and liquidity rates are"
	" for the given {amount} and {requested_amt}",
	.dev_only = true,
};

AUTODATA(json_command, &queryrates_command);

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

static void dualopen_errmsg(struct channel *channel,
			    struct peer_fd *peer_fd,
			    const char *desc,
			    const u8 *err_for_them,
			    bool disconnect,
			    bool warning)
{
	/* Clean up any in-progress open attempts */
	channel_cleanup_commands(channel, desc);

	if (channel_state_uncommitted(channel->state)) {
		log_info(channel->log, "%s", "Unsaved peer failed."
			 " Deleting channel.");
		delete_channel(channel);
		return;
	}
	if ((warning || disconnect) && channel_state_open_uncommitted(channel->state)) {
		log_info(channel->log, "%s", "Commit ready peer failed."
			 " Deleting channel.");
		delete_channel(channel);
		return;
	}

	/* Do we have an error to send? */
	if (err_for_them && !channel->error && !warning)
		channel->error = tal_dup_talarr(channel, u8, err_for_them);

	/* No peer_fd means a subd crash or disconnection. */
	if (!peer_fd) {
		if (!warning && disconnect)
			channel_fail_permanent(channel,
					       err_for_them ? REASON_LOCAL : REASON_PROTOCOL,
					       "%s: %s ERROR %s",
					       channel->owner->name,
					       err_for_them ? "sent" : "received", desc);
		else
			/* If the channel is unsaved, we forget it */
			channel_fail_transient(channel, disconnect, "%s: %s",
					       channel->owner->name, desc);
		return;
	}

	/* Other implementations chose to ignore errors early on.  Not
	 * surprisingly, they now spew out spurious errors frequently,
	 * and we would close the channel on them.  We now support warnings
	 * for this case. */
	if (warning || !disconnect) {
		/* We *don't* hang up if they aborted: that's fine! */
		channel_fail_transient(channel, disconnect, "%s %s: %s",
				       channel->owner->name,
				       warning ? "WARNING" : "ABORTED",
				       desc);

		/* If it was an abort AND the last infight has no last_tx,
		 * clean up the inflight. only hits for RBF cases */
		if (maybe_cleanup_last_inflight(channel))
			log_debug(channel->log, "Cleaned up incomplete inflight");


		if (!disconnect) {
			if (channel_state_open_uncommitted(channel->state)) {
				log_info(channel->log, "%s", "Commit ready peer can't reconnect."
					 " Deleting channel.");
				delete_channel(channel);
				return;
			}
			char *err = restart_dualopend(tmpctx,
						      channel->peer->ld,
						      channel, true);
			if (err)
				log_broken(channel->log,
					   "Unable to restart dualopend"
					   " after abort: %s", err);
		}

		return;
	}

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *   - when sending `error`:
	 *     - MUST fail the channel(s) referred to by the error message.
	 *     - MAY set `channel_id` to all zero to indicate all channels.
	 */
	/* FIXME: Close if it's an all-channels error sent or rcvd */

	/* BOLT #1:
	 *
	 * A sending node:
	 *...
	 *  - when sending `error`:
	 *    - MUST fail the channel(s) referred to by the error message.
	 *    - MAY set `channel_id` to all zero to indicate all channels.
	 *...
	 * The receiving node:
	 *  - upon receiving `error`:
	 *    - if `channel_id` is all zero:
	 *       - MUST fail all channels with the sending node.
	 *    - otherwise:
	 *      - MUST fail the channel referred to by `channel_id`, if that channel is with the
	 *        sending node.
	 */

	/* FIXME: We don't close all channels */
	/* We should immediately forget the channel if we receive error during
	 * CHANNELD_AWAITING_LOCKIN if we are fundee. */
	if (!err_for_them && channel_state_open_uncommitted(channel->state))
		channel_fail_forget(channel, "%s: %s ERROR %s",
				    channel->owner->name,
				    err_for_them ? "sent" : "received", desc);
	else
		channel_fail_permanent(channel,
				       err_for_them ? REASON_LOCAL : REASON_PROTOCOL,
				       "%s: %s ERROR %s",
				       channel->owner->name,
				       err_for_them ? "sent" : "received", desc);
}


bool peer_start_dualopend(struct peer *peer,
			  struct peer_fd *peer_fd,
			  struct channel *channel)
{
	int hsmfd;
	u32 max_to_self_delay;
	struct amount_msat min_effective_htlc_capacity;
	const u8 *msg;

	hsmfd = hsm_get_client_fd(peer->ld, &peer->id, channel->unsaved_dbid,
				  HSM_PERM_COMMITMENT_POINT
				  | HSM_PERM_SIGN_REMOTE_TX
				  | HSM_PERM_SIGN_WILL_FUND_OFFER
				  | HSM_PERM_LOCK_OUTPOINT);

	channel->owner = new_channel_subd(channel,
					  peer->ld,
					  "lightning_dualopend",
					  channel,
					  &peer->id,
					  channel->log, true,
					  dualopend_wire_name,
					  dual_opend_msg,
					  dualopen_errmsg,
					  channel_set_billboard,
					  take(&peer_fd->fd),
					  take(&hsmfd), NULL);

	if (!channel->owner) {
		channel_internal_error(channel,
				       "Running lightningd_dualopend: %s",
				       strerror(errno));
		return false;
	}

	channel_config(peer->ld, &channel->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	/* BOLT #2:
	 *
	 * The sender:
	 *   - if `channel_type` includes `option_zeroconf`:
	 *      - MUST set `minimum_depth` to zero.
	 *   - otherwise:
	 *     - SHOULD set `minimum_depth` to a number of blocks it
	 *       considers reasonable to avoid double-spending of the
	 *       funding transaction.
	 */
	/* FIXME: We should override this to 0 in the openchannel2 hook of we want zeroconf*/
	channel->minimum_depth = peer->ld->config.anchor_confirms;

	msg = towire_dualopend_init(NULL, chainparams,
				    peer->ld->our_features,
				    peer->their_features,
				    &channel->our_config,
				    max_to_self_delay,
				    min_effective_htlc_capacity,
				    &channel->local_basepoints,
				    &channel->local_funding_pubkey,
				    channel->minimum_depth,
				    peer->ld->config.require_confirmed_inputs,
				    *channel->alias[LOCAL],
				    peer->ld->dev_any_channel_type);
	subd_send_msg(channel->owner, take(msg));
	return true;
}

bool peer_restart_dualopend(struct peer *peer,
			    struct peer_fd *peer_fd,
			    struct channel *channel,
			    bool from_abort)
{
	u32 max_to_self_delay, blockheight;
	struct amount_msat min_effective_htlc_capacity;
	struct channel_config unused_config;
	struct channel_inflight *inflight;
        int hsmfd;
	u32 *local_shutdown_script_wallet_index;
	u8 *msg;

	if (channel_state_uncommitted(channel->state))
		return peer_start_dualopend(peer, peer_fd, channel);

	hsmfd = hsm_get_client_fd(peer->ld, &peer->id, channel->dbid,
				  HSM_PERM_COMMITMENT_POINT
				  | HSM_PERM_SIGN_REMOTE_TX
				  | HSM_PERM_SIGN_WILL_FUND_OFFER
				  | HSM_PERM_LOCK_OUTPOINT);

	channel_set_owner(channel,
			  new_channel_subd(channel, peer->ld,
					   "lightning_dualopend",
					   channel,
					   &peer->id,
					   channel->log, true,
					   dualopend_wire_name,
					   dual_opend_msg,
					   dualopen_errmsg,
					   channel_set_billboard,
					   take(&peer_fd->fd),
					   take(&hsmfd), NULL));
	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon channel: %s",
			   strerror(errno));
		/* Disconnect it. */
		force_peer_disconnect(peer->ld, peer,
				      "Failed to create dualopend");
		return false;
	}

	/* Find the max self delay and min htlc capacity */
	channel_config(peer->ld, &unused_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity);

	inflight = channel_current_inflight(channel);
	assert(inflight);
	blockheight = get_blockheight(channel->blockheight_states,
				      channel->opener, LOCAL);

	/* Determine the wallet index for the LOCAL shutdown_scriptpubkey,
	 * NULL if not found. */
	u32 found_wallet_index;
	if (wallet_can_spend(peer->ld->wallet,
			     channel->shutdown_scriptpubkey[LOCAL],
			     &found_wallet_index)) {
		local_shutdown_script_wallet_index = tal(tmpctx, u32);
		*local_shutdown_script_wallet_index = found_wallet_index;
	} else
		local_shutdown_script_wallet_index = NULL;

	msg = towire_dualopend_reinit(NULL,
				      chainparams,
				      from_abort,
				      peer->ld->our_features,
				      peer->their_features,
				      &channel->our_config,
				      &channel->channel_info.their_config,
				      &channel->cid,
				      max_to_self_delay,
				      min_effective_htlc_capacity,
				      &channel->local_basepoints,
				      &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey,
				      channel->minimum_depth,
				      &inflight->funding->outpoint,
				      inflight->funding->feerate,
				      channel->funding_sats,
				      channel->our_msat,
				      &channel->channel_info.theirbase,
				      &channel->channel_info.remote_per_commit,
				      inflight->funding_psbt,
				      channel->opener,
				      channel->scid != NULL,
				      channel->remote_channel_ready,
				      channel->state == CHANNELD_SHUTTING_DOWN,
				      channel->shutdown_scriptpubkey[REMOTE] != NULL,
				      channel->shutdown_scriptpubkey[LOCAL],
				      channel->remote_upfront_shutdown_script,
				      local_shutdown_script_wallet_index,
				      inflight->remote_tx_sigs,
				      inflight->last_tx != NULL,
                                      channel->fee_states,
				      channel->channel_flags,
				      blockheight,
				      inflight->lease_expiry,
				      inflight->lease_commit_sig,
				      inflight->lease_chan_max_msat,
				      inflight->lease_chan_max_ppt,
				      amount_sat_zero(inflight->lease_amt) ?
					      NULL : &inflight->lease_amt,
				      channel->type,
				      channel->req_confirmed_ins[LOCAL],
				      channel->req_confirmed_ins[REMOTE],
				      *channel->alias[LOCAL]);

	subd_send_msg(channel->owner, take(msg));
	return true;
}
