/* This plugin covers both sending and receiving offers */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/rune/rune.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/bolt11.h>
#include <common/bolt11_json.h>
#include <common/bolt12_id.h>
#include <common/bolt12_merkle.h>
#include <common/gossmap.h>
#include <common/iso4217.h>
#include <common/json_blinded_path.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/onion_message.h>
#include <errno.h>
#include <plugins/establish_onion_path.h>
#include <plugins/fetchinvoice.h>
#include <plugins/offers.h>
#include <plugins/offers_inv_hook.h>
#include <plugins/offers_invreq_hook.h>
#include <plugins/offers_offer.h>
#include <sodium.h>

#define HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define ABYTES crypto_secretstream_xchacha20poly1305_ABYTES

struct pubkey id;
u32 blockheight;
u16 cltv_final;
bool disable_connect;
bool dev_invoice_bpath_scid;
struct short_channel_id *dev_invoice_internal_scid;
struct secret invoicesecret_base;
struct secret offerblinding_base;
struct secret nodealias_base;
static struct gossmap *global_gossmap;

static void init_gossmap(struct plugin *plugin)
{
	global_gossmap
		= notleak_with_children(gossmap_load(plugin,
						     GOSSIP_STORE_FILENAME,
						     plugin_gossmap_logcb,
						     plugin));
	if (!global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
}

struct gossmap *get_gossmap(struct plugin *plugin)
{
	if (!global_gossmap)
		init_gossmap(plugin);
	else
		gossmap_refresh(global_gossmap);
	return global_gossmap;
}

static struct command_result *finished(struct command *cmd,
				       const char *method,
				       const char *buf,
				       const jsmntok_t *result,
				       void *unused)
{
	return command_hook_success(cmd);
}

static struct command_result *injectonionmessage_error(struct command *cmd,
						       const char *method,
						       const char *buf,
						       const jsmntok_t *err,
						       void *unused)
{
	/* This can happen if the peer goes offline or wasn't directly
	 * connected: "Unknown first peer" */
	plugin_log(cmd->plugin, LOG_DBG,
		   "injectonionmessage gave JSON error: %.*s",
		   json_tok_full_len(err),
		   json_tok_full(buf, err));
	return command_hook_success(cmd);
}

struct command_result *
inject_onionmessage_(struct command *cmd,
		     const struct onion_message *omsg,
		     struct command_result *(*cb)(struct command *command,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *result,
						  void *arg),
		     struct command_result *(*errcb)(struct command *command,
						     const char *method,
						     const char *buf,
						     const jsmntok_t *result,
						     void *arg),
		     void *arg)
{
	struct out_req *req;
	struct sphinx_path *sphinx_path;
	struct onionpacket *op;
	struct secret *path_secrets;
	size_t onion_size;

	/* Create an onion which encodes this. */
	sphinx_path = sphinx_path_new(tmpctx, NULL, 0);
	for (size_t i = 0; i < tal_count(omsg->hops); i++)
		sphinx_add_hop(sphinx_path,
			       &omsg->hops[i]->pubkey, omsg->hops[i]->raw_payload);

	/* BOLT #4:
	 * - SHOULD set `onion_message_packet` `len` to 1366 or 32834.
	 */
	if (sphinx_path_payloads_size(sphinx_path) <= ROUTING_INFO_SIZE)
		onion_size = ROUTING_INFO_SIZE;
	else
		onion_size = 32768; /* VERSION_SIZE + HMAC_SIZE + PUBKEY_SIZE == 66 */

	op = create_onionpacket(tmpctx, sphinx_path, onion_size, &path_secrets);
	if (!op) {
		/* errcb expects a JSON message. */
		const char *err;
		jsmntok_t *toks;

		err = tal_fmt(tmpctx, "{\"code\":%d,\"message\":\"Creating onion failed (tlvs too long?)\"}",
			      JSONRPC2_INVALID_PARAMS);
		toks = json_parse_simple(tmpctx, err, strlen(err));
		assert(toks);
		/* Not really an error from injectpaymentonion, but near enough */
		return errcb(cmd, "injectpaymentonion", err, toks, arg);
	}

	req = jsonrpc_request_start(cmd, "injectonionmessage", cb, errcb, arg);
	json_add_pubkey(req->js, "path_key", &omsg->first_path_key);
	json_add_hex_talarr(req->js, "message", serialize_onionpacket(tmpctx, op));
	return send_outreq(req);
}

/* Holds the details while we wait for establish_onion_path to connect */
struct onion_reply {
	struct blinded_path *reply_path;
	struct tlv_onionmsg_tlv *payload;
};

static struct command_result *send_onion_reply_after_established(struct command *cmd,
								 const struct pubkey *path,
								 struct onion_reply *onion_reply)
{
	struct onion_message *omsg;

	omsg = outgoing_onion_message(tmpctx, path, NULL, onion_reply->reply_path, onion_reply->payload);
	return inject_onionmessage(cmd, omsg, finished, injectonionmessage_error, onion_reply);
}

static struct command_result *send_onion_reply_not_established(struct command *cmd,
							       const char *why,
							       struct onion_reply *onion_reply)
{
	plugin_log(cmd->plugin, LOG_DBG,
		   "Failed to connect for reply via %s: %s",
		   fmt_sciddir_or_pubkey(tmpctx, &onion_reply->reply_path->first_node_id),
		   why);
	return command_hook_success(cmd);
}

static struct blinded_path *blinded_path_dup(const tal_t *ctx,
					     const struct blinded_path *old)
{
	struct blinded_path *bp = tal(ctx, struct blinded_path);
	*bp = *old;
	bp->path = tal_arr(bp, struct blinded_path_hop *, tal_count(old->path));
	for (size_t i = 0; i < tal_count(bp->path); i++) {
		bp->path[i] = tal(bp->path, struct blinded_path_hop);
		bp->path[i]->blinded_node_id = old->path[i]->blinded_node_id;
		bp->path[i]->encrypted_recipient_data = tal_dup_talarr(bp->path[i], u8,
								       old->path[i]->encrypted_recipient_data);
	}
	return bp;
}

struct command_result *
send_onion_reply(struct command *cmd,
		 struct blinded_path *reply_path,
		 struct tlv_onionmsg_tlv *payload)
{
	struct onion_reply *onion_reply;

	onion_reply = tal(cmd, struct onion_reply);
	onion_reply->reply_path = blinded_path_dup(onion_reply, reply_path);
	onion_reply->payload = tal_steal(onion_reply, payload);

	if (!gossmap_scidd_pubkey(get_gossmap(cmd->plugin),
				  &onion_reply->reply_path->first_node_id)) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Cannot resolve initial reply scidd %s",
			   fmt_short_channel_id_dir(tmpctx,
						    &onion_reply->reply_path->first_node_id.scidd));
		return command_hook_success(cmd);
	}

	return establish_onion_path(cmd, get_gossmap(cmd->plugin),
				    &id, &onion_reply->reply_path->first_node_id.pubkey,
				    disable_connect,
				    send_onion_reply_after_established,
				    send_onion_reply_not_established,
				    onion_reply);
}

static struct command_result *onion_message_recv(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *om, *secrettok, *replytok, *invreqtok, *invtok;
	struct blinded_path *reply_path = NULL;
 	struct secret *secret;

	om = json_get_member(buf, params, "onion_message");
	secrettok = json_get_member(buf, om, "pathsecret");
	if (secrettok) {
		secret = tal(tmpctx, struct secret);
		json_to_secret(buf, secrettok, secret);
	} else
		secret = NULL;

	/* Might be reply for fetchinvoice (which always has a secret,
	 * so we can tell it's a response). */
	if (secret) {
		struct command_result *res;
		res = handle_invoice_onion_message(cmd, buf, om, secret);
		if (res)
			return res;
	}

	replytok = json_get_member(buf, om, "reply_blindedpath");
	if (replytok) {
		reply_path = json_to_blinded_path(cmd, buf, replytok);
		if (!reply_path)
			plugin_err(cmd->plugin, "Invalid reply path %.*s?",
				   json_tok_full_len(replytok),
				   json_tok_full(buf, replytok));
	}

	invreqtok = json_get_member(buf, om, "invoice_request");
	if (invreqtok) {
		const u8 *invreqbin = json_tok_bin_from_hex(tmpctx, buf, invreqtok);
		if (reply_path)
			return handle_invoice_request(cmd,
						      invreqbin,
						      reply_path, secret);
		else
			plugin_log(cmd->plugin, LOG_DBG,
				   "invoice_request without reply_path");
	}

	invtok = json_get_member(buf, om, "invoice");
	if (invtok) {
		const u8 *invbin = json_tok_bin_from_hex(tmpctx, buf, invtok);
		if (invbin)
			return handle_invoice(cmd, invbin, reply_path, secret);
	}

	return command_hook_success(cmd);
}

struct find_best_peer_data {
	struct command_result *(*cb)(struct command *,
				     const struct chaninfo *,
				     void *);
	int needed_feature;
	void *arg;
};

static struct command_result *listincoming_done(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						struct find_best_peer_data *data)
{
	const jsmntok_t *arr, *t;
	size_t i;
	struct chaninfo *best = NULL;

  	arr = json_get_member(buf, result, "incoming");
	json_for_each_arr(i, t, arr) {
		struct chaninfo ci;
		const jsmntok_t *pftok;
		u8 *features;
		const char *err;
		struct amount_msat feebase;

		err = json_scan(tmpctx, buf, t,
				"{id:%,"
				"incoming_capacity_msat:%,"
				"htlc_min_msat:%,"
				"htlc_max_msat:%,"
				"fee_base_msat:%,"
				"fee_proportional_millionths:%,"
				"cltv_expiry_delta:%}",
				JSON_SCAN(json_to_pubkey, &ci.id),
				JSON_SCAN(json_to_msat, &ci.capacity),
				JSON_SCAN(json_to_msat, &ci.htlc_min),
				JSON_SCAN(json_to_msat, &ci.htlc_max),
				JSON_SCAN(json_to_msat, &feebase),
				JSON_SCAN(json_to_u32, &ci.feeppm),
				JSON_SCAN(json_to_u32, &ci.cltv));
		if (err) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Could not parse listincoming: %s",
				   err);
			continue;
		}
		ci.feebase = feebase.millisatoshis; /* Raw: feebase */

		/* Not presented if there's no channel_announcement for peer:
		 * we could use listpeers, but if it's private we probably
		 * don't want to blinded route through it! */
		pftok = json_get_member(buf, t, "peer_features");
		if (!pftok)
			continue;
		features = json_tok_bin_from_hex(tmpctx, buf, pftok);
		if (!feature_offered(features, data->needed_feature))
			continue;

		if (!best || amount_msat_greater(ci.capacity, best->capacity))
			best = tal_dup(tmpctx, struct chaninfo, &ci);
	}

	/* Free data if they don't */
	tal_steal(tmpctx, data);
	return data->cb(cmd, best, data->arg);
}

struct command_result *find_best_peer_(struct command *cmd,
				       int needed_feature,
				       struct command_result *(*cb)(struct command *,
								    const struct chaninfo *,
								    void *),
				       void *arg)
{
	struct out_req *req;
	struct find_best_peer_data *data = tal(cmd, struct find_best_peer_data);
	data->cb = cb;
	data->arg = arg;
	data->needed_feature = needed_feature;
	req = jsonrpc_request_start(cmd, "listincoming",
				    listincoming_done, forward_error, data);
	return send_outreq(req);
}

static const struct plugin_hook hooks[] = {
	{
		"onion_message_recv",
		onion_message_recv
	},
	{
		"onion_message_recv_secret",
		onion_message_recv
	},
	{
		"invoice_payment",
		invoice_payment,
	},
};

static struct command_result *block_added_notify(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const char *err = json_scan(cmd, buf, params, "{block_added:{height:%}}",
				    JSON_SCAN(json_to_u32, &blockheight));
	if (err)
		plugin_err(cmd->plugin, "Failed to parse block_added (%.*s): %s",
			   json_tok_full_len(params),
			   json_tok_full(buf, params),
			   err);
	return notification_handled(cmd);
}

static const struct plugin_notification notifications[] = {
	{
		"block_added",
		block_added_notify,
	},
};


struct decodable {
	const char *type;
	struct bolt11 *b11;
	struct tlv_offer *offer;
	struct tlv_invoice *invoice;
	struct tlv_invoice_request *invreq;
	struct rune *rune;
	u8 *emergency_recover;
};

static u8 *encrypted_decode(const tal_t *ctx, const char *str, char **fail) {
	if (strlen(str) < 8) {
		*fail = tal_fmt(ctx, "invalid payload");
		return NULL;
	}

	size_t hrp_maxlen = strlen(str) - 6;
	char *hrp = tal_arr(ctx, char, hrp_maxlen);

	size_t data_maxlen = strlen(str) - 8;
	u5 *data = tal_arr(ctx, u5, data_maxlen);
	size_t datalen = 0;

	if (bech32_decode(hrp, data, &datalen, str, (size_t)-1)
		== BECH32_ENCODING_NONE) {
		*fail = tal_fmt(ctx, "invalid bech32 encoding");
		goto fail;
	}

	if (!streq(hrp, "clnemerg")) {
		*fail = tal_fmt(ctx, "hrp should be `clnemerg`");
		goto fail;
	}
	u8 *data8bit = tal_arr(data, u8, 0);
	bech32_pull_bits(&data8bit, data, datalen*5);

	return data8bit;
fail:
	tal_free(data);
	return NULL;
}

static struct command_result *param_decodable(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *token,
					      struct decodable *decodable)
{
	char *likely_fail = NULL, *fail;
	jsmntok_t tok;

	/* BOLT #11:
	 *
	 * If a URI scheme is desired, the current recommendation is to either
	 * use 'lightning:' as a prefix before the BOLT-11 encoding
	 */
	tok = *token;
	if (json_tok_startswith(buffer, &tok, "lightning:")
	    || json_tok_startswith(buffer, &tok, "LIGHTNING:"))
		tok.start += strlen("lightning:");

	decodable->offer = offer_decode(cmd, buffer + tok.start,
					tok.end - tok.start,
					plugin_feature_set(cmd->plugin), NULL,
					json_tok_startswith(buffer, &tok, "lno1")
					? &likely_fail : &fail);
	if (decodable->offer) {
		decodable->type = "bolt12 offer";
		return NULL;
	}

	decodable->invoice = invoice_decode(cmd, buffer + tok.start,
					    tok.end - tok.start,
					    plugin_feature_set(cmd->plugin),
					    NULL,
					    json_tok_startswith(buffer, &tok,
								"lni1")
					    ? &likely_fail : &fail);
	if (decodable->invoice) {
		decodable->type = "bolt12 invoice";
		return NULL;
	}

	decodable->invreq = invrequest_decode(cmd, buffer + tok.start,
					      tok.end - tok.start,
					      plugin_feature_set(cmd->plugin),
					      NULL,
					      json_tok_startswith(buffer, &tok,
								  "lnr1")
					      ? &likely_fail : &fail);
	if (decodable->invreq) {
		decodable->type = "bolt12 invoice_request";
		return NULL;
	}

	decodable->emergency_recover = encrypted_decode(cmd, tal_strndup(tmpctx, buffer + tok.start,
						     tok.end - tok.start),
						     json_tok_startswith(buffer, &tok,
									"clnemerg1")
						     ? &likely_fail : &fail);

	if (decodable->emergency_recover) {
		decodable->type = "emergency recover";
		return NULL;
	}

	/* If no other was likely, bolt11 decoder gives us failure string. */
	decodable->b11 = bolt11_decode(cmd,
				       tal_strndup(tmpctx, buffer + tok.start,
						   tok.end - tok.start),
				       plugin_feature_set(cmd->plugin),
				       NULL, NULL,
				       likely_fail ? &fail : &likely_fail);
	if (decodable->b11) {
		decodable->type = "bolt11 invoice";
		return NULL;
	}

	decodable->rune = rune_from_base64n(decodable, buffer + tok.start,
					    tok.end - tok.start);
	if (decodable->rune) {
		decodable->type = "rune";
		return NULL;
	}

	/* Return failure message from most likely parsing candidate */
	return command_fail_badparam(cmd, name, buffer, &tok, likely_fail);
}

static void json_add_chains(struct json_stream *js,
			    const char *fieldname,
			    const struct bitcoin_blkid *chains)
{
	json_array_start(js, fieldname);
	for (size_t i = 0; i < tal_count(chains); i++)
		json_add_sha256(js, NULL, &chains[i].shad.sha);
	json_array_end(js);
}

static void json_add_onionmsg_path(struct json_stream *js,
				   const char *fieldname,
				   const struct blinded_path_hop *hop)
{
	json_object_start(js, fieldname);
	json_add_pubkey(js, "blinded_node_id", &hop->blinded_node_id);
	json_add_hex_talarr(js, "encrypted_recipient_data", hop->encrypted_recipient_data);
	json_object_end(js);
}

/* Returns true if valid */
static bool json_add_blinded_paths(struct command *cmd,
				   struct json_stream *js,
				   const char *fieldname,
				   struct blinded_path **paths,
				   struct blinded_payinfo **blindedpay)
{
	json_array_start(js, fieldname);
	for (size_t i = 0; i < tal_count(paths); i++) {
		json_object_start(js, NULL);
		if (paths[i]->first_node_id.is_pubkey) {
			json_add_pubkey(js, "first_node_id",
					&paths[i]->first_node_id.pubkey);
		} else {
			json_add_short_channel_id(js, "first_scid",
						  paths[i]->first_node_id.scidd.scid);
			json_add_u32(js, "first_scid_dir",
				     paths[i]->first_node_id.scidd.dir);
		}

		if (command_deprecated_out_ok(cmd, "blinding", "v24.11", "v25.05"))
			json_add_pubkey(js, "blinding", &paths[i]->first_path_key);
		json_add_pubkey(js, "first_path_key", &paths[i]->first_path_key);

		/* Don't crash if we're short a payinfo! */
		if (i < tal_count(blindedpay)) {
			json_object_start(js, "payinfo");
			json_add_amount_msat(js, "fee_base_msat",
						  amount_msat(blindedpay[i]->fee_base_msat));
			json_add_u32(js, "fee_proportional_millionths",
				     blindedpay[i]->fee_proportional_millionths);
			json_add_u32(js, "cltv_expiry_delta",
				     blindedpay[i]->cltv_expiry_delta);
			json_add_hex_talarr(js, "features", blindedpay[i]->features);
			json_object_end(js);
		}

		json_array_start(js, "path");
		for (size_t j = 0; j < tal_count(paths[i]->path); j++) {
			json_add_onionmsg_path(js, NULL, paths[i]->path[j]);
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `invoice_blindedpay` does not contain
	 *   exactly one `blinded_payinfo` per `invoice_paths`.`blinded_path`.
	 */
	if (blindedpay && tal_count(blindedpay) != tal_count(paths)) {
		json_add_str_fmt(js, "warning_invalid_invoice_blindedpay",
				 "invoice has %zu blinded_payinfo but %zu paths",
				 tal_count(blindedpay), tal_count(paths));
		return false;
	}

	/* BOLT-offers #12:
	 *  - if `num_hops` is 0 in any `blinded_path` in `offer_paths`:
	 *    - MUST NOT respond to the offer.
	 */
	for (size_t i = 0; i < tal_count(paths); i++) {
		if (tal_count(paths[i]->path) == 0) {
			json_add_str_fmt(js, "warning_empty_blinded_path",
					 "blinded path %zu has 0 hops",
					 i);
			return false;
		}
	}

	return true;
}

static const char *recurrence_time_unit_name(u8 time_unit)
{
	/* BOLT-offers-recurrence #12:
	 * `time_unit` defining 0 (seconds), 1 (days), 2 (months), 3 (years).
	 */
	switch (time_unit) {
	case 0:
		return "seconds";
	case 1:
		return "days";
	case 2:
		return "months";
	case 3:
		return "years";
	}
	return NULL;
}

static bool json_add_utf8(struct json_stream *js,
			  const char *fieldname,
			  const char *utf8str)
{
	if (utf8_check(utf8str, tal_bytelen(utf8str))) {
		json_add_stringn(js, fieldname, utf8str, tal_bytelen(utf8str));
		return true;
	}
	json_add_string(js, tal_fmt(tmpctx, "warning_invalid_%s", fieldname),
			"invalid UTF8");
	return false;
}

static bool json_add_offer_fields(struct command *cmd,
				  struct json_stream *js,
				  const struct bitcoin_blkid *offer_chains,
				  const u8 *offer_metadata,
				  const char *offer_currency,
				  const u64 *offer_amount,
				  const char *offer_description,
				  const u8 *offer_features,
				  const u64 *offer_absolute_expiry,
				  struct blinded_path **offer_paths,
				  const char *offer_issuer,
				  const u64 *offer_quantity_max,
				  const struct pubkey *offer_issuer_id,
				  const struct recurrence *offer_recurrence,
				  const struct recurrence_paywindow *offer_recurrence_paywindow,
				  const u32 *offer_recurrence_limit,
				  const struct recurrence_base *offer_recurrence_base)
{
	bool valid = true;

	if (offer_chains)
		json_add_chains(js, "offer_chains", offer_chains);
	if (offer_metadata)
		json_add_hex_talarr(js, "offer_metadata", offer_metadata);
	if (offer_currency) {
		const struct iso4217_name_and_divisor *iso4217;
		valid &= json_add_utf8(js, "offer_currency", offer_currency);
		if (offer_amount)
			json_add_u64(js, "offer_amount", *offer_amount);
		iso4217 = find_iso4217(offer_currency,
				       tal_bytelen(offer_currency));
		if (iso4217)
			json_add_num(js, "currency_minor_unit", iso4217->minor_unit);
		else
			json_add_string(js, "warning_unknown_offer_currency",
					"unknown currency code");
	} else if (offer_amount)
		json_add_amount_msat(js, "offer_amount_msat",
				     amount_msat(*offer_amount));
	/* BOLT-offers #12:
	 *
	 * - if `offer_amount` is set and `offer_description` is not set:
	 *    - MUST NOT respond to the offer.
	 */
	if (offer_description)
		valid &= json_add_utf8(js, "offer_description",
				       offer_description);
	else if (!offer_description && offer_amount) {
		json_add_string(js, "warning_missing_offer_description",
				"description is required if offer_amount is set (for the user to know what it was they paid for)");
		valid = false;
	}

	if (offer_issuer)
		valid &= json_add_utf8(js, "offer_issuer", offer_issuer);
	if (offer_features)
		json_add_hex_talarr(js, "offer_features", offer_features);
	if (offer_absolute_expiry)
		json_add_u64(js, "offer_absolute_expiry",
			     *offer_absolute_expiry);
	if (offer_paths)
		valid &= json_add_blinded_paths(cmd, js, "offer_paths",
						offer_paths, NULL);

	if (offer_quantity_max)
		json_add_u64(js, "offer_quantity_max", *offer_quantity_max);

	if (offer_recurrence) {
		const char *name;
		json_object_start(js, "offer_recurrence");
		json_add_num(js, "time_unit", offer_recurrence->time_unit);
		name = recurrence_time_unit_name(offer_recurrence->time_unit);
		if (name)
			json_add_string(js, "time_unit_name", name);
		json_add_num(js, "period", offer_recurrence->period);
		if (offer_recurrence_base) {
			json_add_u64(js, "basetime",
				     offer_recurrence_base->basetime);
			if (offer_recurrence_base->start_any_period)
				json_add_bool(js, "start_any_period", true);
		}
		if (offer_recurrence_limit)
			json_add_u32(js, "limit", *offer_recurrence_limit);
		if (offer_recurrence_paywindow) {
			json_object_start(js, "paywindow");
			json_add_u32(js, "seconds_before",
				     offer_recurrence_paywindow->seconds_before);
			json_add_u32(js, "seconds_after",
				     offer_recurrence_paywindow->seconds_after);
			if (offer_recurrence_paywindow->proportional_amount)
				json_add_bool(js, "proportional_amount", true);
			json_object_end(js);
		}
		json_object_end(js);
	}

	if (offer_issuer_id)
		json_add_pubkey(js, "offer_issuer_id", offer_issuer_id);

	return valid;
}

static void json_add_extra_fields(struct json_stream *js,
				  const char *fieldname,
				  const struct tlv_field *fields)
{
	bool have_extra = false;

	for (size_t i = 0; i < tal_count(fields); i++) {
		if (fields[i].meta)
			continue;
		if (!have_extra) {
			json_array_start(js, fieldname);
			have_extra = true;
		}
		json_object_start(js, NULL);
		json_add_u64(js, "type", fields[i].numtype);
		json_add_u64(js, "length", fields[i].length);
		json_add_hex(js, "value",
			     fields[i].value, fields[i].length);
		json_object_end(js);
	}
	if (have_extra)
		json_array_end(js);
}

static void json_add_offer(struct command *cmd, struct json_stream *js, const struct tlv_offer *offer)
{
	struct sha256 offer_id;
	bool valid = true;

	offer_offer_id(offer, &offer_id);
	json_add_sha256(js, "offer_id", &offer_id);

	valid &= json_add_offer_fields(cmd, js,
				       offer->offer_chains,
				       offer->offer_metadata,
				       offer->offer_currency,
				       offer->offer_amount,
				       offer->offer_description,
				       offer->offer_features,
				       offer->offer_absolute_expiry,
				       offer->offer_paths,
				       offer->offer_issuer,
				       offer->offer_quantity_max,
				       offer->offer_issuer_id,
				       offer->offer_recurrence,
				       offer->offer_recurrence_paywindow,
				       offer->offer_recurrence_limit,
				       offer->offer_recurrence_base);
	/* BOLT-offers #12:
	 * - if neither `offer_issuer_id` nor `offer_paths` are set:
	 *   - MUST NOT respond to the offer.
	 */
	if (!offer->offer_issuer_id && !offer->offer_paths) {
		json_add_string(js, "warning_missing_offer_issuer_id",
				"offers without an issuer_id or paths are invalid");
		valid = false;
	}
	json_add_extra_fields(js, "unknown_offer_tlvs", offer->fields);
	json_add_bool(js, "valid", valid);
}

static bool json_add_invreq_fields(struct command *cmd,
				   struct json_stream *js,
				   const u8 *invreq_metadata,
				   const struct bitcoin_blkid *invreq_chain,
				   const u64 *invreq_amount,
				   const u8 *invreq_features,
				   const u64 *invreq_quantity,
				   const struct pubkey *invreq_payer_id,
				   const utf8 *invreq_payer_note,
				   struct blinded_path **invreq_paths,
				   struct tlv_invoice_request_invreq_bip_353_name *bip353,
				   const u32 *invreq_recurrence_counter,
				   const u32 *invreq_recurrence_start)
{
	bool valid = true;

	/* BOLT-offers #12:
	 *   - MUST fail the request if `invreq_payer_id` or `invreq_metadata` are not present.
	 */
	if (invreq_metadata)
		json_add_hex_talarr(js, "invreq_metadata",
				    invreq_metadata);
	else {
		json_add_string(js, "warning_missing_invreq_metadata",
				"invreq_metadata required");
		valid = false;
	}

	/* This can be missing for an invoice though! */
	if (invreq_payer_id)
		json_add_pubkey(js, "invreq_payer_id", invreq_payer_id);

	if (invreq_chain)
		json_add_sha256(js, "invreq_chain", &invreq_chain->shad.sha);

	if (invreq_amount)
		json_add_amount_msat(js, "invreq_amount_msat",
				     amount_msat(*invreq_amount));
	if (invreq_features)
		json_add_hex_talarr(js, "invreq_features", invreq_features);
	if (invreq_quantity)
		json_add_u64(js, "invreq_quantity", *invreq_quantity);
	if (invreq_payer_note)
		valid &= json_add_utf8(js, "invreq_payer_note", invreq_payer_note);
	if (invreq_paths)
		valid &= json_add_blinded_paths(cmd, js, "invreq_paths",
						invreq_paths, NULL);

	if (bip353) {
		json_object_start(js, "invreq_bip_353_name");
		if (bip353->name) {
			json_add_str_fmt(js, "name", "%.*s",
					 (int)tal_bytelen(bip353->name),
					 (char *)bip353->name);
		}
		if (bip353->domain) {
			json_add_str_fmt(js, "domain", "%.*s",
					 (int)tal_bytelen(bip353->domain),
					 (char *)bip353->domain);
		}
		json_object_end(js);

		if (!bolt12_bip353_valid_string(bip353->name,
						tal_bytelen(bip353->name))) {
			valid = false;
			json_add_string(js, "warning_invreq_bip_353_name_name_invalid",
					"bip353 name field contains invalid characters");
		}
		if (!bolt12_bip353_valid_string(bip353->domain,
						tal_bytelen(bip353->domain))) {
			valid = false;
			json_add_string(js, "warning_invreq_bip_353_name_domain_invalid",
					"bip353 domain field contains invalid characters");
		}
	}

	if (invreq_recurrence_counter) {
		json_add_u32(js, "invreq_recurrence_counter",
			     *invreq_recurrence_counter);
		if (invreq_recurrence_start)
			json_add_u32(js, "invreq_recurrence_start",
				     *invreq_recurrence_start);
	}

	return valid;
}

/* Returns true if valid */
static bool json_add_fallback_address(struct json_stream *js,
				      const struct chainparams *chain,
				      u8 version, const u8 *address)
{
	char out[73 + strlen(chain->onchain_hrp)];

	/* Does extra checks, in particular checks v0 sizes */
	if (segwit_addr_encode(out, chain->onchain_hrp, version,
			       address, tal_bytelen(address))) {
		json_add_string(js, "address", out);
		return true;
	}
	json_add_string(js,
			"warning_invalid_invoice_fallbacks_address",
			"invalid fallback address for this version");
	return false;
}

/* Returns true if valid */
static bool json_add_fallbacks(struct json_stream *js,
			       const struct bitcoin_blkid *chains,
			       struct fallback_address **fallbacks)
{
	const struct chainparams *chain;
	bool valid = true;

	/* Present address as first chain mentioned. */
	if (tal_count(chains) != 0)
		chain = chainparams_by_chainhash(&chains[0]);
	else
		chain = chainparams_for_network("bitcoin");

	json_array_start(js, "invoice_fallbacks");
	for (size_t i = 0; i < tal_count(fallbacks); i++) {
		size_t addrlen = tal_bytelen(fallbacks[i]->address);

		json_object_start(js, NULL);
		json_add_u32(js, "version", fallbacks[i]->version);
		json_add_hex_talarr(js, "hex", fallbacks[i]->address);

		/* BOLT-offers #12:
		 * - for the bitcoin chain, if the invoice specifies `invoice_fallbacks`:
		 *   - MUST ignore any `fallback_address` for which `version` is
		 *     greater than 16.
		 * -  MUST ignore any `fallback_address` for which `address` is
		 *    less than 2 or greater than 40 bytes.
		 * - MUST ignore any `fallback_address` for which `address` does
		 *   not meet known requirements for the given `version`
		 */
		if (fallbacks[i]->version > 16) {
			json_add_string(js,
					"warning_invalid_invoice_fallbacks_version",
					"invoice fallback version > 16");
			valid = false;
		} else if (addrlen < 2 || addrlen > 40) {
			json_add_string(js,
					"warning_invalid_invoice_fallbacks_address",
					"invoice fallback address bad length");
			valid = false;
		} else if (chain) {
			valid &= json_add_fallback_address(js, chain,
							   fallbacks[i]->version,
							   fallbacks[i]->address);
		}
		json_object_end(js);
	}
	json_array_end(js);

	return valid;
}

static void json_add_invoice_request(struct command *cmd,
				     struct json_stream *js,
				     const struct tlv_invoice_request *invreq)
{
	bool valid = true;

	/* If there's an offer_issuer_id or offer_paths, then there's an offer. */
	if (invreq->offer_issuer_id || invreq->offer_paths) {
		struct sha256 offer_id;

		invreq_offer_id(invreq, &offer_id);
		json_add_sha256(js, "offer_id", &offer_id);
	}

	valid &= json_add_offer_fields(cmd, js,
				       invreq->offer_chains,
				       invreq->offer_metadata,
				       invreq->offer_currency,
				       invreq->offer_amount,
				       invreq->offer_description,
				       invreq->offer_features,
				       invreq->offer_absolute_expiry,
				       invreq->offer_paths,
				       invreq->offer_issuer,
				       invreq->offer_quantity_max,
				       invreq->offer_issuer_id,
				       invreq->offer_recurrence,
				       invreq->offer_recurrence_paywindow,
				       invreq->offer_recurrence_limit,
				       invreq->offer_recurrence_base);
	valid &= json_add_invreq_fields(cmd, js,
					invreq->invreq_metadata,
					invreq->invreq_chain,
					invreq->invreq_amount,
					invreq->invreq_features,
					invreq->invreq_quantity,
					invreq->invreq_payer_id,
					invreq->invreq_payer_note,
					invreq->invreq_paths,
					invreq->invreq_bip_353_name,
					invreq->invreq_recurrence_counter,
					invreq->invreq_recurrence_start);

	/* BOLT-offers #12:
	 *   - MUST fail the request if `invreq_payer_id` or `invreq_metadata` are not present.
	 */
	if (!invreq->invreq_payer_id) {
		json_add_string(js, "warning_missing_invreq_payer_id",
				"invreq_payer_id required");
		valid = false;
	}

	/* BOLT-offers #12:
	 * - MUST fail the request if `signature` is not correct as detailed
	 *   in [Signature Calculation](#signature-calculation) using the
	 *  `invreq_payer_id`.
	 */
	if (invreq->signature) {
		if (invreq->invreq_payer_id
		    && !bolt12_check_signature(invreq->fields,
					       "invoice_request",
					       "signature",
					       invreq->invreq_payer_id,
					       invreq->signature)) {
			json_add_string(js, "warning_invalid_invoice_request_signature",
					"Bad signature");
			valid = false;
		} else {
			json_add_bip340sig(js, "signature", invreq->signature);
		}
	} else {
		json_add_string(js, "warning_missing_invoice_request_signature",
				"Missing signature");
		valid = false;
	}

	json_add_extra_fields(js, "unknown_invoice_request_tlvs", invreq->fields);
	json_add_bool(js, "valid", valid);
}

static void json_add_b12_invoice(struct command *cmd,
				 struct json_stream *js,
				 const struct tlv_invoice *invoice)
{
	bool valid = true;
	/* FIXME: Technically, different types! */
	struct tlv_invoice_request_invreq_bip_353_name *bip353;

	if (invoice->invreq_bip_353_name) {
		bip353 = tal(tmpctx, struct tlv_invoice_request_invreq_bip_353_name);
		bip353->name = invoice->invreq_bip_353_name->name;
		bip353->domain = invoice->invreq_bip_353_name->domain;
	} else {
		bip353 = NULL;
	}

	/* If there's an offer_issuer_id or offer_paths, then there's an offer. */
	if (invoice->offer_issuer_id || invoice->offer_paths) {
		struct sha256 offer_id;

		invoice_offer_id(invoice, &offer_id);
		json_add_sha256(js, "offer_id", &offer_id);
	}

	valid &= json_add_offer_fields(cmd, js,
				       invoice->offer_chains,
				       invoice->offer_metadata,
				       invoice->offer_currency,
				       invoice->offer_amount,
				       invoice->offer_description,
				       invoice->offer_features,
				       invoice->offer_absolute_expiry,
				       invoice->offer_paths,
				       invoice->offer_issuer,
				       invoice->offer_quantity_max,
				       invoice->offer_issuer_id,
				       invoice->offer_recurrence,
				       invoice->offer_recurrence_paywindow,
				       invoice->offer_recurrence_limit,
				       invoice->offer_recurrence_base);
	valid &= json_add_invreq_fields(cmd, js,
					invoice->invreq_metadata,
					invoice->invreq_chain,
					invoice->invreq_amount,
					invoice->invreq_features,
					invoice->invreq_quantity,
					invoice->invreq_payer_id,
					invoice->invreq_payer_note,
					invoice->invreq_paths,
					bip353,
					invoice->invreq_recurrence_counter,
					invoice->invreq_recurrence_start);

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `invoice_paths` is not present
	 *   or is empty.
	 * - MUST reject the invoice if `num_hops` is 0 in any `blinded_path` in `invoice_paths`.
	 * - MUST reject the invoice if `invoice_blindedpay` is not present.
	 * - MUST reject the invoice if `invoice_blindedpay` does not contain
	 *   exactly one `blinded_payinfo` per `invoice_paths`.`blinded_path`.
	 */
	if (invoice->invoice_paths) {
		if (!invoice->invoice_blindedpay) {
			json_add_string(js, "warning_missing_invoice_blindedpay",
					"invoices with paths without blindedpay are invalid");
			valid = false;
		}
		valid &= json_add_blinded_paths(cmd, js, "invoice_paths",
						invoice->invoice_paths,
						invoice->invoice_blindedpay);
	} else {
		json_add_string(js, "warning_missing_invoice_paths",
				"invoices without a invoice_paths are invalid");
		valid = false;
	}

	if (invoice->invoice_created_at) {
		json_add_u64(js, "invoice_created_at", *invoice->invoice_created_at);
	} else {
		json_add_string(js, "warning_missing_invoice_created_at",
				"invoices without created_at are invalid");
		valid = false;
	}

	/* BOLT-offers #12:
	 *
	 * - if `invoice_relative_expiry` is present:
	 *   - MUST reject the invoice if the current time since 1970-01-01 UTC
	 *     is greater than `invoice_created_at` plus `seconds_from_creation`.
	 * - otherwise:
	 *   - MUST reject the invoice if the current time since 1970-01-01 UTC
	 *     is greater than `invoice_created_at` plus 7200.
	 */
	if (invoice->invoice_relative_expiry)
		json_add_u32(js, "invoice_relative_expiry", *invoice->invoice_relative_expiry);
	else
		json_add_u32(js, "invoice_relative_expiry", BOLT12_DEFAULT_REL_EXPIRY);

	if (invoice->invoice_payment_hash)
		json_add_sha256(js, "invoice_payment_hash", invoice->invoice_payment_hash);
	else {
		json_add_string(js, "warning_missing_invoice_payment_hash",
				"invoices without a payment_hash are invalid");
		valid = false;
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `invoice_amount` is not present.
	 */
	if (invoice->invoice_amount)
		json_add_amount_msat(js, "invoice_amount_msat",
				     amount_msat(*invoice->invoice_amount));
	else {
		json_add_string(js, "warning_missing_invoice_amount",
				"invoices without an amount are invalid");
		valid = false;
	}

	if (invoice->invoice_fallbacks)
		valid &= json_add_fallbacks(js,
					    invoice->invreq_chain,
					    invoice->invoice_fallbacks);

	if (invoice->invoice_features)
		json_add_hex_talarr(js, "features", invoice->invoice_features);

	if (invoice->invoice_node_id)
		json_add_pubkey(js, "invoice_node_id", invoice->invoice_node_id);
	else {
		json_add_string(js, "warning_missing_invoice_node_id",
				"invoices without an invoice_node_id are invalid");
		valid = false;
	}

	/* BOLT-offers-recurrence #12:
	 * - if the offer contained `recurrence`:
	 *   - MUST reject the invoice if `recurrence_basetime` is not
	 *     set.
	 */
	if (invoice->offer_recurrence) {
		if (invoice->invoice_recurrence_basetime)
			json_add_u64(js, "invoice_recurrence_basetime",
				     *invoice->invoice_recurrence_basetime);
		else {
			json_add_string(js, "warning_missing_invoice_recurrence_basetime",
					"recurring invoices without a recurrence_basetime are invalid");
			valid = false;
		}
	}

	/* invoice_decode checked this */
	json_add_bip340sig(js, "signature", invoice->signature);

	json_add_extra_fields(js, "unknown_invoice_tlvs", invoice->fields);
	json_add_bool(js, "valid", valid);
}

static void json_add_rune(struct command *cmd, struct json_stream *js, const struct rune *rune)
{
	const char *string;

	/* Simplest to check everything for UTF-8 compliance at once.
	 * Since separators are | and & (which cannot appear inside
	 * UTF-8 multichars), if the entire thing is valid UTF-8 then
	 * each part is. */
	string = rune_to_string(tmpctx, rune);
	if (!utf8_check(string, strlen(string))) {
		json_add_hex(js, "hex", string, strlen(string));
		json_add_string(js, "warning_rune_invalid_utf8",
				"Rune contains invalid UTF-8 strings");
		json_add_bool(js, "valid", false);
		return;
	}

	if (rune->unique_id)
		json_add_string(js, "unique_id", rune->unique_id);
	if (rune->version)
		json_add_string(js, "version", rune->version);
	json_add_string(js, "string", take(string));

	json_array_start(js, "restrictions");
	for (size_t i = rune->unique_id ? 1 : 0; i < tal_count(rune->restrs); i++) {
		const struct rune_restr *restr = rune->restrs[i];
		char *summary = tal_strdup(tmpctx, "");
		const char *sep = "";

		json_object_start(js, NULL);
		json_array_start(js, "alternatives");
		for (size_t j = 0; j < tal_count(restr->alterns); j++) {
			const struct rune_altern *alt = restr->alterns[j];
			const char *annotation, *value;
			bool int_val = false, time_val = false;

			if (streq(alt->fieldname, "time")) {
				annotation = "in seconds since 1970";
				time_val = true;
			} else if (streq(alt->fieldname, "id"))
				annotation = "of commanding peer";
			else if (streq(alt->fieldname, "method"))
				annotation = "of command";
			else if (streq(alt->fieldname, "pnum")) {
				annotation = "number of command parameters";
				int_val = true;
			} else if (streq(alt->fieldname, "rate")) {
				annotation = "max per minute";
				int_val = true;
			} else if (strstarts(alt->fieldname, "parr")) {
				annotation = tal_fmt(tmpctx, "array parameter #%s", alt->fieldname+4);
			} else if (strstarts(alt->fieldname, "pname"))
				annotation = tal_fmt(tmpctx, "object parameter '%s'", alt->fieldname+5);
			else
				annotation = "unknown condition?";

			tal_append_fmt(&summary, "%s", sep);

			/* Where it's ambiguous, quote if it's not treated as an int */
			if (int_val)
				value = alt->value;
			else if (time_val) {
				u64 t = atol(alt->value);

				if (t) {
					u64 diff, now = time_now().ts.tv_sec;
					/* Need a non-const during construction */
					char *v;

					if (now > t)
						diff = now - t;
					else
						diff = t - now;
					if (diff < 60)
						v = tal_fmt(tmpctx, "%"PRIu64" seconds", diff);
					else if (diff < 60 * 60)
						v = tal_fmt(tmpctx, "%"PRIu64" minutes %"PRIu64" seconds",
							    diff / 60, diff % 60);
					else {
						v = tal_strdup(tmpctx, "approximately ");
						/* diff is in minutes */
						diff /= 60;
						if (diff < 48 * 60)
							tal_append_fmt(&v, "%"PRIu64" hours %"PRIu64" minutes",
								       diff / 60, diff % 60);
						else {
							/* hours */
							diff /= 60;
							if (diff < 60 * 24)
								tal_append_fmt(&v, "%"PRIu64" days %"PRIu64" hours",
									       diff / 24, diff % 24);
							else {
								/* days */
								diff /= 24;
								if (diff < 365 * 2)
									tal_append_fmt(&v, "%"PRIu64" months %"PRIu64" days",
										       diff / 30, diff % 30);
								else {
									/* months */
									diff /= 30;
									tal_append_fmt(&v, "%"PRIu64" years %"PRIu64" months",
										       diff / 12, diff % 12);
								}
							}
						}
					}
					if (now > t)
						tal_append_fmt(&v, " ago");
					else
						tal_append_fmt(&v, " from now");
					value = tal_fmt(tmpctx, "%s (%s)", alt->value, v);
				} else
					value = alt->value;
			} else
				value = tal_fmt(tmpctx, "'%s'", alt->value);

			switch (alt->condition) {
			case RUNE_COND_IF_MISSING:
				tal_append_fmt(&summary, "%s (%s) is missing", alt->fieldname, annotation);
				break;
			case RUNE_COND_EQUAL:
				tal_append_fmt(&summary, "%s (%s) equal to %s", alt->fieldname, annotation, value);
				break;
			case RUNE_COND_NOT_EQUAL:
				tal_append_fmt(&summary, "%s (%s) unequal to %s", alt->fieldname, annotation, value);
				break;
			case RUNE_COND_BEGINS:
				tal_append_fmt(&summary, "%s (%s) starts with '%s'", alt->fieldname, annotation, alt->value);
				break;
			case RUNE_COND_ENDS:
				tal_append_fmt(&summary, "%s (%s) ends with '%s'", alt->fieldname, annotation, alt->value);
				break;
			case RUNE_COND_CONTAINS:
				tal_append_fmt(&summary, "%s (%s) contains '%s'", alt->fieldname, annotation, alt->value);
				break;
			case RUNE_COND_INT_LESS:
				tal_append_fmt(&summary, "%s (%s) less than %s", alt->fieldname, annotation,
					       time_val ? value : alt->value);
				break;
			case RUNE_COND_INT_GREATER:
				tal_append_fmt(&summary, "%s (%s) greater than %s", alt->fieldname, annotation,
					       time_val ? value : alt->value);
				break;
			case RUNE_COND_LEXO_BEFORE:
				tal_append_fmt(&summary, "%s (%s) sorts before '%s'", alt->fieldname, annotation, alt->value);
				break;
			case RUNE_COND_LEXO_AFTER:
				tal_append_fmt(&summary, "%s (%s) sorts after '%s'", alt->fieldname, annotation, alt->value);
				break;
			case RUNE_COND_COMMENT:
				tal_append_fmt(&summary, "[comment: %s%s]", alt->fieldname, alt->value);
				break;
			}
			sep = " OR ";
			json_add_str_fmt(js, NULL, "%s%c%s", alt->fieldname, alt->condition, alt->value);
		}
		json_array_end(js);
		json_add_string(js, "summary", summary);
		json_object_end(js);
	}
	json_array_end(js);
	/* FIXME: do some sanity checks? */
	json_add_bool(js, "valid", true);
}

static struct command_result *after_makesecret(struct command *cmd,
					       const char *method,
					       const char *buf,
					       const jsmntok_t *result,
					       struct decodable *decodable)
{
	struct secret secret;
	struct json_stream *response;
	const jsmntok_t *secrettok;

	secrettok = json_get_member(buf, result, "secret");
	json_to_secret(buf, secrettok, &secret);

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (tal_bytelen(decodable->emergency_recover) < ABYTES +
	    HEADER_LEN)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Can't decrypt, hex is too short!");

	u8 *decrypt_blob = tal_arr(tmpctx, u8,
				   tal_bytelen(decodable->emergency_recover) -
				   ABYTES -
				   HEADER_LEN);
	/* The header part */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state,
							    decodable->emergency_recover,
							    secret.data) != 0) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Can't decrypt!");
	}

	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, decrypt_blob,
						       NULL, 0,
						       decodable->emergency_recover +
						       HEADER_LEN,
						       tal_bytelen(decodable->emergency_recover) -
						       HEADER_LEN,
						       NULL, 0) != 0) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Can't decrypt!");
	}

	response = jsonrpc_stream_success(cmd);
	json_add_bool(response, "valid", true);
	json_add_string(response, "type", decodable->type);
	json_add_hex(response, "decrypted", decrypt_blob,
		     tal_bytelen(decrypt_blob));

	return command_finished(cmd, response);
}

static struct command_result *json_decode(struct command *cmd,
					  const char *buffer,
					  const jsmntok_t *params)
{
	struct decodable *decodable = talz(cmd, struct decodable);
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("string", param_decodable, decodable),
		   NULL))
		return command_param_failed();

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "type", decodable->type);
	if (decodable->offer)
		json_add_offer(cmd, response, decodable->offer);
	if (decodable->invreq)
		json_add_invoice_request(cmd, response, decodable->invreq);
	if (decodable->invoice)
		json_add_b12_invoice(cmd, response, decodable->invoice);
	if (decodable->b11) {
		/* The bolt11 decoder simply refuses to decode bad invs. */
		json_add_bolt11(response, decodable->b11);
		json_add_bool(response, "valid", true);
	}
	if (decodable->rune)
		json_add_rune(cmd, response, decodable->rune);
	if (decodable->emergency_recover) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd, "makesecret",
					    after_makesecret, &forward_error,
					    decodable);

		json_add_string(req->js, "string", "scb secret");
		return send_outreq(req);
	}

	return command_finished(cmd, response);
}

static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	rpc_scan(init_cmd, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_pubkey, &id));

	rpc_scan(init_cmd, "getchaininfo",
		 take(json_out_obj(NULL, "last_height", NULL)),
		 "{headercount:%}", JSON_SCAN(json_to_u32, &blockheight));

	rpc_scan(init_cmd, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{configs:"
		 "{cltv-final:{value_int:%}}}",
		 JSON_SCAN(json_to_u16, &cltv_final));

	rpc_scan(init_cmd, "makesecret",
		 take(json_out_obj(NULL, "string", BOLT12_ID_BASE_STRING)),
		 "{secret:%}",
		 JSON_SCAN(json_to_secret, &invoicesecret_base));

	rpc_scan(init_cmd, "makesecret",
		 take(json_out_obj(NULL, "string", "offer-blinded-path")),
		 "{secret:%}",
		 JSON_SCAN(json_to_secret, &offerblinding_base));

	rpc_scan(init_cmd, "makesecret",
		 take(json_out_obj(NULL, "string", NODE_ALIAS_BASE_STRING)),
		 "{secret:%}",
		 JSON_SCAN(json_to_secret, &nodealias_base));

	return NULL;
}

static const struct plugin_command commands[] = {
    {
	    "offer",
		json_offer
    },
    {
	    "invoicerequest",
		json_invoicerequest
    },
    {
	    "decode",
	    json_decode,
    },
    {
	    "fetchinvoice",
	    json_fetchinvoice,
    },
    {
	    "sendinvoice",
	    json_sendinvoice,
    },
    {
	    "dev-rawrequest",
	    json_dev_rawrequest,
	    .dev_only = true,
    },
};

static char *scid_option(struct plugin *plugin, const char *arg, bool check_only,
			 struct short_channel_id **scidp)
{
	struct short_channel_id scid;

	if (!short_channel_id_from_str(arg, strlen(arg), &scid))
		return tal_fmt(tmpctx, "'%s' is not an scid", arg);

	*scidp = notleak(tal_dup(plugin, struct short_channel_id, &scid));
	return NULL;
}

static bool scid_jsonfmt(struct plugin *plugin, struct json_stream *js, const char *fieldname,
			 struct short_channel_id **scid)
{
	if (!*scid)
		return false;
	json_add_short_channel_id(js, fieldname, **scid);
	return true;
}

int main(int argc, char *argv[])
{
	setup_locale();

	/* We deal in UTC; mktime() uses local time */
	setenv("TZ", "", 1);
	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    notifications, ARRAY_SIZE(notifications),
		    hooks, ARRAY_SIZE(hooks),
		    NULL, 0,
		    plugin_option("fetchinvoice-noconnect", "flag",
				  "Don't try to connect directly to fetch/pay an invoice.",
				  flag_option, flag_jsonfmt, &disable_connect),
		    plugin_option_dev("dev-invoice-bpath-scid", "flag",
				      "Use short_channel_id instead of pubkey when creating a blinded payment path",
				      flag_option, flag_jsonfmt, &dev_invoice_bpath_scid),
		    plugin_option_dev("dev-invoice-internal-scid", "string",
				      "Use short_channel_id instead of pubkey when creating a blinded payment path",
				      scid_option, scid_jsonfmt, &dev_invoice_internal_scid),
		    NULL);
}
