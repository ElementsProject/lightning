#include <ccan/mem/mem.h>
#include <common/blindedpath.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <gossipd/gossipd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/json.h>
#include <lightningd/onion_message.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

struct onion_message_hook_payload {
	/* Pre-spec or modern? */
	bool obsolete;

	/* Optional */
	struct pubkey *blinding_in; /* obsolete only */
	struct pubkey *reply_blinding;
	struct onionmsg_path **reply_path;
	struct pubkey *reply_first_node; /* non-obsolete only */
	struct pubkey *our_alias; /* non-obsolete only */

	struct tlv_onionmsg_payload *om;
};

static void json_add_blindedpath(struct json_stream *stream,
				 const char *fieldname,
				 const struct pubkey *blinding,
				 const struct pubkey *first_node_id,
				 struct onionmsg_path **path)
{
	json_object_start(stream, fieldname);
	json_add_pubkey(stream, "blinding", blinding);
	json_add_pubkey(stream, "first_node_id", first_node_id);
	json_array_start(stream, "hops");
	for (size_t i = 0; i < tal_count(path); i++) {
		json_object_start(stream, NULL);
		json_add_pubkey(stream, "id", &path[i]->node_id);
		json_add_hex_talarr(stream, "enctlv", path[i]->enctlv);
		json_object_end(stream);
	};
	json_array_end(stream);
	json_object_end(stream);
}

static void onion_message_serialize(struct onion_message_hook_payload *payload,
				    struct json_stream *stream,
				    struct plugin *plugin)
{
	json_object_start(stream, "onion_message");
	json_add_bool(stream, "obsolete", payload->obsolete);
	if (payload->blinding_in)
		json_add_pubkey(stream, "blinding_in", payload->blinding_in);
	if (payload->our_alias)
		json_add_pubkey(stream, "our_alias", payload->our_alias);

	/* Modern style. */
	if (payload->reply_first_node) {
		json_add_blindedpath(stream, "reply_blindedpath",
				     payload->reply_blinding,
				     payload->reply_first_node,
				     payload->reply_path);
	} else if (payload->reply_path) {
		json_array_start(stream, "reply_path");
		for (size_t i = 0; i < tal_count(payload->reply_path); i++) {
			json_object_start(stream, NULL);
			json_add_pubkey(stream, "id",
					&payload->reply_path[i]->node_id);
			if (tal_bytelen(payload->reply_path[i]->enctlv) != 0)
				json_add_hex_talarr(stream, "enctlv",
						    payload->reply_path[i]->enctlv);
			if (i == 0)
				json_add_pubkey(stream, "blinding",
						payload->reply_blinding);
			json_object_end(stream);
		}
		json_array_end(stream);
	}
	/* Common convenience fields */
	if (payload->om->invoice_request)
		json_add_hex_talarr(stream, "invoice_request",
				    payload->om->invoice_request);
	if (payload->om->invoice)
		json_add_hex_talarr(stream, "invoice", payload->om->invoice);

	if (payload->om->invoice_error)
		json_add_hex_talarr(stream, "invoice_error",
				    payload->om->invoice_error);

	json_array_start(stream, "unknown_fields");
	for (size_t i = 0; i < tal_count(payload->om->fields); i++) {
		if (payload->om->fields[i].meta)
			continue;
		json_object_start(stream, NULL);
		json_add_u64(stream, "number", payload->om->fields[i].numtype);
		json_add_hex(stream, "value",
			     payload->om->fields[i].value,
			     payload->om->fields[i].length);
		json_object_end(stream);
	}
	json_array_end(stream);
	json_object_end(stream);
}

static void
onion_message_hook_cb(struct onion_message_hook_payload *payload STEALS)
{
	/* plugin_hook_continue checks the "result"; anything other than continue
	 * just stops. */
	tal_free(payload);
}

/* Two hooks, because it's critical we only accept blinding if we expect that
 * exact blinding key.  Otherwise, we can be probed using old blinded paths. */
REGISTER_PLUGIN_HOOK(onion_message,
		     plugin_hook_continue,
		     onion_message_hook_cb,
		     onion_message_serialize,
		     struct onion_message_hook_payload *);

REGISTER_PLUGIN_HOOK(onion_message_blinded,
		     plugin_hook_continue,
		     onion_message_hook_cb,
		     onion_message_serialize,
		     struct onion_message_hook_payload *);

REGISTER_PLUGIN_HOOK(onion_message_ourpath,
		     plugin_hook_continue,
		     onion_message_hook_cb,
		     onion_message_serialize,
		     struct onion_message_hook_payload *);

void handle_obs_onionmsg_to_us(struct lightningd *ld, const u8 *msg)
{
	struct onion_message_hook_payload *payload;
	u8 *submsg;
	size_t submsglen;
	const u8 *subptr;

#if DEVELOPER
	if (ld->dev_ignore_obsolete_onion)
		return;
#endif

	payload = tal(ld, struct onion_message_hook_payload);
	payload->obsolete = true;
	payload->reply_first_node = NULL;
	payload->om = tlv_onionmsg_payload_new(payload);
	payload->our_alias = NULL;

	if (!fromwire_gossipd_got_obs_onionmsg_to_us(payload, msg,
						     &payload->blinding_in,
						     &payload->reply_blinding,
						     &payload->reply_path,
						     &submsg)) {
		log_broken(ld->log, "bad got_onionmsg_tous: %s",
			   tal_hex(tmpctx, msg));
		return;
	}
	submsglen = tal_bytelen(submsg);
	subptr = submsg;
	if (!fromwire_onionmsg_payload(&subptr,
				       &submsglen, payload->om)) {
		tal_free(payload);
		log_broken(ld->log, "bad got_onionmsg_tous om: %s",
			   tal_hex(tmpctx, msg));
		return;
	}
	tal_free(submsg);

	if (payload->reply_path && !payload->reply_blinding) {
		log_broken(ld->log,
			   "No reply blinding, ignoring reply path");
		payload->reply_path = tal_free(payload->reply_path);
	}

	log_debug(ld->log, "Got obsolete onionmsg%s%s",
		  payload->reply_blinding ? " reply_blinding": "",
		  payload->reply_path ? " reply_path": "");

	if (payload->blinding_in)
		plugin_hook_call_onion_message_blinded(ld, payload);
	else
		plugin_hook_call_onion_message(ld, payload);
}

void handle_obs_onionmsg_forward(struct lightningd *ld, const u8 *msg)
{
	struct short_channel_id *next_scid;
	struct node_id *next_node;
	struct pubkey *next_blinding;
	u8 *onion;

	if (!fromwire_gossipd_got_obs_onionmsg_forward(msg, msg, &next_scid,
						       &next_node,
						       &next_blinding, &onion)) {
		log_broken(ld->log, "bad got_onionmsg_forward: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (next_scid) {
		struct channel *outchan = any_channel_by_scid(ld, next_scid);
		if (outchan)
			next_node = &outchan->peer->id;
	}

	if (!next_node) {
		log_debug(ld->log, "Cannot forward onionmsg to %s",
			  next_scid ? type_to_string(tmpctx,
						     struct short_channel_id,
						     next_scid)
			  : "unspecified dest");
	} else {
		subd_send_msg(ld->gossip,
			      take(towire_gossipd_send_obs_onionmsg(NULL,
								    next_node,
								    onion,
								    next_blinding)));
	}
}

void handle_onionmsg_to_us(struct lightningd *ld, const u8 *msg)
{
	struct onion_message_hook_payload *payload;
	u8 *submsg;
	struct secret *self_id;
	size_t submsglen;
	const u8 *subptr;

#if DEVELOPER
	if (ld->dev_ignore_modern_onion)
		return;
#endif

	payload = tal(ld, struct onion_message_hook_payload);
	payload->obsolete = false;
	payload->om = tlv_onionmsg_payload_new(payload);
	payload->blinding_in = NULL;
	payload->our_alias = tal(payload, struct pubkey);

	if (!fromwire_gossipd_got_onionmsg_to_us(payload, msg,
						 payload->our_alias,
						 &self_id,
						 &payload->reply_blinding,
						 &payload->reply_first_node,
						 &payload->reply_path,
						 &submsg)) {
		log_broken(ld->log, "bad got_onionmsg_tous: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	/* If there's no self_id, or it's not correct, ignore alias: alias
	 * means we created the path it's using. */
	if (!self_id || !secret_eq_consttime(self_id, &ld->onion_reply_secret))
		payload->our_alias = tal_free(payload->our_alias);

	submsglen = tal_bytelen(submsg);
	subptr = submsg;
	if (!fromwire_onionmsg_payload(&subptr,
				       &submsglen, payload->om)) {
		tal_free(payload);
		log_broken(ld->log, "bad got_onionmsg_tous om: %s",
			   tal_hex(tmpctx, msg));
		return;
	}
	tal_free(submsg);

	/* Make sure gossipd gets this right. */
	if (payload->reply_path
	    && (!payload->reply_blinding || !payload->reply_first_node)) {
		log_broken(ld->log,
			   "No reply blinding/first_node, ignoring reply path");
		payload->reply_path = tal_free(payload->reply_path);
	}

	log_debug(ld->log, "Got onionmsg%s%s",
		  payload->our_alias ? " via-ourpath": "",
		  payload->reply_path ? " reply_path": "");

	if (payload->our_alias)
		plugin_hook_call_onion_message_ourpath(ld, payload);
	else
		plugin_hook_call_onion_message_blinded(ld, payload);
}

struct hop {
	struct pubkey id;
	struct short_channel_id *scid;
	struct pubkey *blinding;
	u8 *enctlv;
	u8 *invoice;
	u8 *invoice_req;
	u8 *invoice_err;
	u8 *rawtlv;
};

static struct command_result *param_hops(struct command *cmd,
					 const char *name,
					 const char *buffer,
					 const jsmntok_t *tok,
					 struct hop **hops)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY || tok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be an (non-empty) array", name);

	*hops = tal_arr(cmd, struct hop, tok->size);
	json_for_each_arr(i, t, tok) {
		const jsmntok_t *tid, *tscid, *tblinding, *tenctlv, *trawtlv,
			*tinvoice, *tinvoicereq, *tinvoiceerr;

		tid = json_get_member(buffer, t, "id");
		if (!tid)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s[%zu] does not have 'id'",
					    name, i);
		tscid = json_get_member(buffer, t, "short_channel_id");
		tblinding = json_get_member(buffer, t, "blinding");
		tenctlv = json_get_member(buffer, t, "enctlv");
		tinvoice = json_get_member(buffer, t, "invoice");
		tinvoicereq = json_get_member(buffer, t, "invoice_request");
		tinvoiceerr = json_get_member(buffer, t, "invoice_error");
		trawtlv = json_get_member(buffer, t, "rawtlv");

		if (trawtlv && (tscid || tblinding || tenctlv || tinvoice || tinvoicereq))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s[%zu] has 'rawtlv' with other fields",
					    name, i);

		if (tblinding) {
			(*hops)[i].blinding = tal(*hops, struct pubkey);
			if (!json_to_pubkey(buffer, tblinding,
					    (*hops)[i].blinding))
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%s[%zu] 'blinding' is invalid", name, i);
		} else
			(*hops)[i].blinding = NULL;

		if (!json_to_pubkey(buffer, tid, &(*hops)[i].id))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s[%zu] 'id' is invalid", name, i);
		if (tscid) {
			(*hops)[i].scid = tal(*hops, struct short_channel_id);
			if (!json_to_short_channel_id(buffer, tscid,
						      (*hops)[i].scid))
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%s[%zu] 'short_channel_id' is invalid", name, i);
		} else
			(*hops)[i].scid = NULL;

		if (tenctlv) {
			(*hops)[i].enctlv =
				json_tok_bin_from_hex(*hops, buffer, tenctlv);
			if (!(*hops)[i].enctlv)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%s[%zu] 'enctlv' is invalid", name, i);
		} else
			(*hops)[i].enctlv = NULL;

		if (tinvoice) {
			(*hops)[i].invoice =
				json_tok_bin_from_hex(*hops, buffer, tinvoice);
			if (!(*hops)[i].invoice)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%s[%zu] 'invoice' is invalid", name, i);
		} else
			(*hops)[i].invoice = NULL;

		if (tinvoicereq) {
			(*hops)[i].invoice_req =
				json_tok_bin_from_hex(*hops, buffer, tinvoicereq);
			if (!(*hops)[i].invoice_req)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%s[%zu] 'invoice_request' is invalid", name, i);
		} else
			(*hops)[i].invoice_req = NULL;

		if (tinvoiceerr) {
			(*hops)[i].invoice_err =
				json_tok_bin_from_hex(*hops, buffer, tinvoiceerr);
			if (!(*hops)[i].invoice_err)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%s[%zu] 'invoice_request' is invalid", name, i);
		} else
			(*hops)[i].invoice_err = NULL;

		if (trawtlv) {
			(*hops)[i].rawtlv =
				json_tok_bin_from_hex(*hops, buffer, trawtlv);
			if (!(*hops)[i].rawtlv)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "%s[%zu] 'rawtlv' is invalid", name, i);
		} else
			(*hops)[i].rawtlv = NULL;
	}
	return NULL;
}

static struct command_result *param_reply_path(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct tlv_onionmsg_payload_obs_reply_path **reply_path)
{
	const jsmntok_t *tblinding, *tpath, *t;
	size_t i;

	*reply_path = tal(cmd, struct tlv_onionmsg_payload_obs_reply_path);
	tblinding = json_get_member(buffer, tok, "blinding");
	if (!tblinding)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s has no 'blinding'", name);
	if (!json_to_pubkey(buffer, tblinding, &(*reply_path)->blinding))
		return command_fail_badparam(cmd, name, buffer, tblinding,
					     "'blinding' should be valid pubkey");

	tpath = json_get_member(buffer, tok, "path");
	if (!tpath || tpath->type != JSMN_ARRAY)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s has no 'path' array", name);

	(*reply_path)->path = tal_arr(*reply_path, struct onionmsg_path *,
				      tpath->size);
	json_for_each_arr(i, t, tpath) {
		const jsmntok_t *tid, *tenctlv;
		struct onionmsg_path *path;

		path = (*reply_path)->path[i] = tal((*reply_path)->path,
						    struct onionmsg_path);
		tid = json_get_member(buffer, t, "id");
		if (!tid)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s path[%zu] 'id' is missing",
					    name, i);
		if (!json_to_pubkey(buffer, tid, &path->node_id))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s path[%zu] 'id' is invalid",
					    name, i);

		tenctlv = json_get_member(buffer, t, "enctlv");
		if (!tenctlv) {
			/* Optional for final destination */
			if (i != tpath->size - 1)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s path[%zu] 'enctlv' is missing",
					    name, i);
			path->enctlv = NULL;
		} else {
			path->enctlv = json_tok_bin_from_hex(path,
							     buffer, tenctlv);
			if (!path->enctlv)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s path[%zu] 'enctlv' is invalid",
					    name, i);
		}
	}

	return NULL;
}

/* Generate ->rawtlv if not already supplied. */
static void populate_tlvs(struct hop *hops,
			  struct tlv_onionmsg_payload_obs_reply_path *reply_path)
{
	for (size_t i = 0; i < tal_count(hops); i++) {
		struct tlv_onionmsg_payload *tlv;

		if (hops[i].rawtlv)
			continue;

		tlv = tlv_onionmsg_payload_new(tmpctx);
		/* If they don't give scid, use next node id */
		if (hops[i].scid) {
			tlv->obs_next_short_channel_id
				= tal_dup(tlv, struct short_channel_id,
					  hops[i].scid);
		} else if (i != tal_count(hops)-1) {
			tlv->obs_next_node_id = tal_dup(tlv, struct pubkey,
							&hops[i+1].id);
		}
		if (hops[i].blinding) {
			tlv->obs_blinding = tal_dup(tlv, struct pubkey,
						    hops[i].blinding);
		}
		/* Note: tal_dup_talarr returns NULL for NULL */
		tlv->enctlv = tal_dup_talarr(tlv, u8, hops[i].enctlv);
		tlv->invoice = tal_dup_talarr(tlv, u8, hops[i].invoice);
		tlv->invoice_request = tal_dup_talarr(tlv, u8,
						      hops[i].invoice_req);
		tlv->invoice_error = tal_dup_talarr(tlv, u8,
						    hops[i].invoice_err);

		if (i == tal_count(hops)-1 && reply_path)
			tlv->obs_reply_path = reply_path;

		hops[i].rawtlv = tal_arr(hops, u8, 0);
		towire_onionmsg_payload(&hops[i].rawtlv, tlv);
	}
}

static struct command_result *json_send_obs_onion_message(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *obj UNNEEDED,
							  const jsmntok_t *params)
{
	struct hop *hops;
	struct tlv_onionmsg_payload_obs_reply_path *reply_path;
	struct sphinx_path *sphinx_path;
	struct onionpacket *op;
	struct secret *path_secrets;
	struct node_id first_id;
	size_t onion_size;

	if (!param(cmd, buffer, params,
		   p_req("hops", param_hops, &hops),
		   p_opt("reply_path", param_reply_path, &reply_path),
		   NULL))
		return command_param_failed();

	if (!feature_offered(cmd->ld->our_features->bits[NODE_ANNOUNCE_FEATURE],
			     OPT_ONION_MESSAGES))
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-onion-messages not enabled");

	node_id_from_pubkey(&first_id, &hops[0].id);

	/* Sanity check first; gossipd doesn't bother telling us if peer
	 * can't be reached. */
	if (!peer_by_id(cmd->ld, &first_id))
		return command_fail(cmd, LIGHTNINGD, "Unknown first peer");

	/* Create an onion which encodes this. */
	populate_tlvs(hops, reply_path);
	sphinx_path = sphinx_path_new(cmd, NULL);
	for (size_t i = 0; i < tal_count(hops); i++)
		sphinx_add_modern_hop(sphinx_path, &hops[i].id, hops[i].rawtlv);

	/* BOLT-onion-message #4:
	 * - SHOULD set `len` to 1366 or 32834.
	 */
	if (sphinx_path_payloads_size(sphinx_path) <= ROUTING_INFO_SIZE)
		onion_size = ROUTING_INFO_SIZE;
	else
		onion_size = 32768;

	op = create_onionpacket(tmpctx, sphinx_path, onion_size, &path_secrets);
	if (!op)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Creating onion failed (tlvs too long?)");

	subd_send_msg(cmd->ld->gossip,
		      take(towire_gossipd_send_obs_onionmsg(NULL, &first_id,
					serialize_onionpacket(tmpctx, op),
					NULL)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command send_obs_onion_message_command = {
	"sendobsonionmessage",
	"utility",
	json_send_obs_onion_message,
	"Send message over {hops} (id, [short_channel_id], [blinding], [enctlv], [invoice], [invoice_request], [invoice_error], [rawtlv]) with optional {reply_path} (blinding, path[id, enctlv])"
};
AUTODATA(json_command, &send_obs_onion_message_command);

struct onion_hop {
	struct pubkey node;
	u8 *tlv;
};

static struct command_result *param_onion_hops(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct onion_hop **hops)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY || tok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be an (non-empty) array", name);

	*hops = tal_arr(cmd, struct onion_hop, tok->size);
	json_for_each_arr(i, t, tok) {
		const char *err;

		err = json_scan(cmd, buffer, t, "{id:%,tlv:%}",
				JSON_SCAN(json_to_pubkey, &(*hops)[i].node),
				JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex,
					      &(*hops)[i].tlv));
		if (err)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s[%zu]: %s", name, i, err);
	}
	return NULL;
}

static struct command_result *json_sendonionmessage(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *obj UNNEEDED,
						    const jsmntok_t *params)
{
	struct onion_hop *hops;
	struct node_id *first_id;
	struct pubkey *blinding;
	struct sphinx_path *sphinx_path;
	struct onionpacket *op;
	struct secret *path_secrets;
	size_t onion_size;

	if (!param(cmd, buffer, params,
		   p_req("first_id", param_node_id, &first_id),
		   p_req("blinding", param_pubkey, &blinding),
		   p_req("hops", param_onion_hops, &hops),
		   NULL))
		return command_param_failed();

	if (!feature_offered(cmd->ld->our_features->bits[NODE_ANNOUNCE_FEATURE],
			     OPT_ONION_MESSAGES))
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-onion-messages not enabled");

	/* Sanity check first; gossipd doesn't bother telling us if peer
	 * can't be reached. */
	if (!peer_by_id(cmd->ld, first_id))
		return command_fail(cmd, LIGHTNINGD, "Unknown first peer");

	/* Create an onion which encodes this. */
	sphinx_path = sphinx_path_new(cmd, NULL);
	for (size_t i = 0; i < tal_count(hops); i++)
		sphinx_add_modern_hop(sphinx_path, &hops[i].node, hops[i].tlv);

	/* BOLT-onion-message #4:
	 * - SHOULD set `len` to 1366 or 32834.
	 */
	if (sphinx_path_payloads_size(sphinx_path) <= ROUTING_INFO_SIZE)
		onion_size = ROUTING_INFO_SIZE;
	else
		onion_size = 32768;

	op = create_onionpacket(tmpctx, sphinx_path, onion_size, &path_secrets);
	if (!op)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Creating onion failed (tlvs too long?)");

	subd_send_msg(cmd->ld->gossip,
		      take(towire_gossipd_send_onionmsg(NULL, first_id,
					serialize_onionpacket(tmpctx, op),
					blinding)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command sendonionmessage_command = {
	"sendonionmessage",
	"utility",
	json_sendonionmessage,
	"Send message to {first_id}, using {blinding}, encoded over {hops} (id, tlv)"
};
AUTODATA(json_command, &sendonionmessage_command);

static struct command_result *param_pubkeys(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    struct pubkey **pubkeys)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY || tok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be an (non-empty) array", name);

	*pubkeys = tal_arr(cmd, struct pubkey, tok->size);
	json_for_each_arr(i, t, tok) {
		if (!json_to_pubkey(buffer, t, &(*pubkeys)[i]))
			return command_fail_badparam(cmd, name, buffer, t,
						     "should be a compressed pubkey");
	}
	return NULL;
}

static struct command_result *json_blindedpath(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct pubkey *ids;
	struct onionmsg_path **path;
	struct privkey blinding_iter;
	struct pubkey first_blinding, first_node, me;
	size_t nhops;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("ids", param_pubkeys, &ids),
		   NULL))
		return command_param_failed();

	nhops = tal_count(ids);

	/* Final id should be us! */
	if (!pubkey_from_node_id(&me, &cmd->ld->id))
		fatal("My id %s is invalid?",
		      type_to_string(tmpctx, struct node_id, &cmd->ld->id));

	first_node = ids[0];
	if (!pubkey_eq(&ids[nhops-1], &me))
		return command_fail(cmd, LIGHTNINGD,
				    "Final of ids must be this node (%s), not %s",
				    type_to_string(tmpctx, struct pubkey, &me),
				    type_to_string(tmpctx, struct pubkey,
						   &ids[nhops-1]));

	randombytes_buf(&blinding_iter, sizeof(blinding_iter));
	if (!pubkey_from_privkey(&blinding_iter, &first_blinding))
		/* Should not happen! */
		return command_fail(cmd, LIGHTNINGD,
				    "Could not convert blinding to pubkey!");

	/* We convert ids into aliases as we go. */
	path = tal_arr(cmd, struct onionmsg_path *, nhops);

	for (size_t i = 0; i < nhops - 1; i++) {
		path[i] = tal(path, struct onionmsg_path);
		path[i]->enctlv = create_enctlv(path[i],
						&blinding_iter,
						&ids[i],
						&ids[i+1],
						/* FIXME: Pad? */
						0,
						NULL,
						&blinding_iter,
						&path[i]->node_id);
	}

	/* FIXME: Add padding! */
	path[nhops-1] = tal(path, struct onionmsg_path);
	path[nhops-1]->enctlv = create_final_enctlv(path[nhops-1],
						    &blinding_iter,
						    &ids[nhops-1],
						    /* FIXME: Pad? */
						    0,
						    &cmd->ld->onion_reply_secret,
						    &path[nhops-1]->node_id);

	response = json_stream_success(cmd);
	json_add_blindedpath(response, "blindedpath",
			     &first_blinding, &first_node, path);
	return command_success(cmd, response);
}

static const struct json_command blindedpath_command = {
	"blindedpath",
	"utility",
	json_blindedpath,
	"Create blinded path to us along {ids} (pubkey array ending in our id)"
};
AUTODATA(json_command, &blindedpath_command);
