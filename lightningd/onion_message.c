#include <common/json_helpers.h>
#include <gossipd/gossipd_wiregen.h>
#include <lightningd/lightningd.h>
#include <lightningd/onion_message.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>

#if EXPERIMENTAL_FEATURES
struct onion_message_hook_payload {
	/* Optional */
	struct pubkey *blinding_in;
	struct pubkey *reply_blinding;
	struct onionmsg_path **reply_path;

	struct tlv_onionmsg_payload *om;
};

static void
onion_message_serialize(struct onion_message_hook_payload *payload,
			   struct json_stream *stream)
{
	json_object_start(stream, "onion_message");
	if (payload->blinding_in)
		json_add_pubkey(stream, "blinding_in", payload->blinding_in);
	if (payload->reply_path) {
		json_array_start(stream, "reply_path");
		for (size_t i = 0; i < tal_count(payload->reply_path); i++) {
			json_object_start(stream, NULL);
			json_add_pubkey(stream, "id",
					&payload->reply_path[i]->node_id);
			if (payload->reply_path[i]->enctlv)
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

void handle_onionmsg_to_us(struct lightningd *ld, const u8 *msg)
{
	struct onion_message_hook_payload *payload;
	u8 *submsg;
	size_t submsglen;

	payload = tal(ld, struct onion_message_hook_payload);
	payload->om = tlv_onionmsg_payload_new(payload);

	if (!fromwire_gossipd_got_onionmsg_to_us(payload, msg,
						 &payload->blinding_in,
						 &payload->reply_blinding,
						 &payload->reply_path,
						 &submsg)) {
		log_broken(ld->log, "bad got_onionmsg_tous: %s",
			   tal_hex(tmpctx, msg));
		return;
	}
	submsglen = tal_bytelen(submsg);
	if (!fromwire_onionmsg_payload(cast_const2(const u8 **, &submsg),
				       &submsglen, payload->om)) {
		log_broken(ld->log, "bad got_onionmsg_tous om: %s",
			   tal_hex(tmpctx, msg));
		return;
	}

	if (payload->reply_path && !payload->reply_blinding) {
		log_broken(ld->log,
			   "No reply blinding, ignoring reply path");
		payload->reply_path = tal_free(payload->reply_path);
	}

	log_debug(ld->log, "Got onionmsg%s%s",
		  payload->reply_blinding ? " reply_blinding": "",
		  payload->reply_path ? " reply_path": "");

	if (payload->blinding_in)
		plugin_hook_call_onion_message_blinded(ld, payload);
	else
		plugin_hook_call_onion_message(ld, payload);
}

void handle_onionmsg_forward(struct lightningd *ld, const u8 *msg)
{
	struct short_channel_id *next_scid;
	struct node_id *next_node;
	struct pubkey *next_blinding;
	u8 onion[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];

	if (!fromwire_gossipd_got_onionmsg_forward(msg, msg, &next_scid,
						   &next_node,
						   &next_blinding, onion)) {
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
			      take(towire_gossipd_send_onionmsg(NULL,
								next_node,
								onion,
								next_blinding)));
	}
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
					       struct tlv_onionmsg_payload_reply_path **reply_path)
{
	const jsmntok_t *tblinding, *tpath, *t;
	size_t i;

	*reply_path = tal(cmd, struct tlv_onionmsg_payload_reply_path);
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
			  struct tlv_onionmsg_payload_reply_path *reply_path)
{
	for (size_t i = 0; i < tal_count(hops); i++) {
		struct tlv_onionmsg_payload *tlv;

		if (hops[i].rawtlv)
			continue;

		tlv = tlv_onionmsg_payload_new(tmpctx);
		/* If they don't give scid, use next node id */
		if (hops[i].scid) {
			tlv->next_short_channel_id
				= tal_dup(tlv, struct short_channel_id,
					  hops[i].scid);
		} else if (i != tal_count(hops)-1) {
			tlv->next_node_id = tal_dup(tlv, struct pubkey,
						    &hops[i+1].id);
		}
		if (hops[i].blinding) {
			tlv->blinding = tal_dup(tlv, struct pubkey,
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
			tlv->reply_path = reply_path;

		hops[i].rawtlv = tal_arr(hops, u8, 0);
		towire_onionmsg_payload(&hops[i].rawtlv, tlv);
	}
}

static struct command_result *json_send_onion_message(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *obj UNNEEDED,
						      const jsmntok_t *params)
{
	struct hop *hops;
	struct tlv_onionmsg_payload_reply_path *reply_path;
	struct sphinx_path *sphinx_path;
	struct onionpacket *op;
	struct secret *path_secrets;
	struct node_id first_id;

	if (!param(cmd, buffer, params,
		   p_req("hops", param_hops, &hops),
		   p_opt("reply_path", param_reply_path, &reply_path),
		   NULL))
		return command_param_failed();

	node_id_from_pubkey(&first_id, &hops[0].id);

	/* Sanity check first; gossipd doesn't bother telling us if peer
	 * can't be reached. */
	if (!peer_by_id(cmd->ld, &first_id))
		return command_fail(cmd, LIGHTNINGD, "Unknown first peer");

	/* Create an onion which encodes this. */
	populate_tlvs(hops, reply_path);
	sphinx_path = sphinx_path_new(cmd, NULL);
	for (size_t i = 0; i < tal_count(hops); i++) {
		/* FIXME: Remove legacy, then length prefix can be removed! */
		u8 *tlv_with_len = tal_arr(NULL, u8, 0);
		towire_bigsize(&tlv_with_len, tal_bytelen(hops[i].rawtlv));
		towire_u8_array(&tlv_with_len,
				hops[i].rawtlv, tal_bytelen(hops[i].rawtlv));
		sphinx_add_hop(sphinx_path, &hops[i].id, take(tlv_with_len));
	}
	op = create_onionpacket(tmpctx, sphinx_path, ROUTING_INFO_SIZE, &path_secrets);
	if (!op)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Creating onion failed (tlvs too long?)");

	subd_send_msg(cmd->ld->gossip,
		      take(towire_gossipd_send_onionmsg(NULL, &first_id,
					serialize_onionpacket(tmpctx, op),
					NULL)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command send_onion_message_command = {
	"sendonionmessage",
	"utility",
	json_send_onion_message,
	"Send message over {hops} (id, [short_channel_id], [blinding], [enctlv], [invoice], [invoice_request], [invoice_error], [rawtlv]) with optional {reply_path} (blinding, path[id, enctlv])"
};
AUTODATA(json_command, &send_onion_message_command);
#endif /* EXPERIMENTAL_FEATURES */
