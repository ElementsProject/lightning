#include <channeld/gen_channel_wire.h>
#include <common/json_helpers.h>
#include <lightningd/channel.h>
#include <lightningd/lightningd.h>
#include <lightningd/onion_message.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

#if EXPERIMENTAL_FEATURES
/* Returns false if we can't tell it */
static bool make_peer_send(struct lightningd *ld,
			   struct channel *dst, const u8 *msg TAKES)
{
	/* Take ownership of msg (noop if it's taken) */
	msg = tal_dup_talarr(tmpctx, u8, msg);

	if (!dst) {
		log_debug(ld->log, "Can't send %s: no channel",
			  channel_wire_type_name(fromwire_peektype(msg)));
		return false;
	}

	if (!dst->owner) {
		log_debug(ld->log, "Can't send %s: not connected",
			  channel_wire_type_name(fromwire_peektype(msg)));
		return false;
	}

	/* FIXME: We should allow this for closingd too, and we should
	 * allow incoming via openingd!. */
	if (!streq(dst->owner->name, "channeld")) {
		log_debug(ld->log, "Can't send %s: owned by %s",
			  channel_wire_type_name(fromwire_peektype(msg)),
			  dst->owner->name);
		return false;
	}
	subd_send_msg(dst->owner, take(msg));
	return true;
}

void handle_onionmsg_to_us(struct channel *channel, const u8 *msg)
{
	struct pubkey *reply_blinding;
	struct onionmsg_path **reply_path;

	if (!fromwire_got_onionmsg_to_us(msg, msg,
					 &reply_blinding, &reply_path)) {
		channel_internal_error(channel, "bad got_onionmsg_tous: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	log_info(channel->log, "Got onionmsg%s%s",
		 reply_blinding ? " reply_blinding": "",
		 reply_path ? " reply_path": "");
}

void handle_onionmsg_forward(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct short_channel_id *next_scid;
	struct node_id *next_node;
	struct pubkey *next_blinding;
	u8 onion[TOTAL_PACKET_SIZE];
	struct channel *outchan;

	if (!fromwire_got_onionmsg_forward(msg, msg, &next_scid, &next_node,
					   &next_blinding, onion)) {
		channel_internal_error(channel, "bad got_onionmsg_forward: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	if (next_scid)
		outchan = active_channel_by_scid(ld, next_scid);
	else if (next_node) {
		struct peer *p = peer_by_id(ld, next_node);
		if (p)
			outchan = peer_active_channel(p);
		else
			outchan = NULL;
	} else
		outchan = NULL;

	make_peer_send(ld, outchan,
		       take(towire_send_onionmsg(NULL, onion, next_blinding)));
}

struct hop {
	struct pubkey id;
	struct short_channel_id *scid;
	struct pubkey *blinding;
	u8 *enctlv;
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
		const jsmntok_t *tid, *tscid, *tblinding, *tenctlv, *trawtlv;

		tid = json_get_member(buffer, t, "id");
		if (!tid)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s[%zu] does not have 'id'",
					    name, i);
		tscid = json_get_member(buffer, t, "short_channel_id");
		tblinding = json_get_member(buffer, t, "blinding");
		tenctlv = json_get_member(buffer, t, "enctlv");
		trawtlv = json_get_member(buffer, t, "rawtlv");

		if (trawtlv && (tscid || tblinding || tenctlv))
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
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s 'blinding' invalid pubkey", name);

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
			tlv->next_short_channel_id = tal(tlv, struct tlv_onionmsg_payload_next_short_channel_id);
			tlv->next_short_channel_id->short_channel_id = *hops[i].scid;
		} else if (i != tal_count(hops)-1) {
			tlv->next_node_id = tal(tlv, struct tlv_onionmsg_payload_next_node_id);
			tlv->next_node_id->node_id = hops[i+1].id;
		}
		if (hops[i].blinding) {
			tlv->blinding = tal(tlv, struct tlv_onionmsg_payload_blinding);
			tlv->blinding->blinding = *hops[i].blinding;
		}
		if (hops[i].enctlv) {
			tlv->enctlv = tal(tlv, struct tlv_onionmsg_payload_enctlv);
			tlv->enctlv->enctlv = hops[i].enctlv;
		}

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
	struct channel *first_hop;
	struct node_id first_id;

	if (!param(cmd, buffer, params,
		   p_req("hops", param_hops, &hops),
		   p_opt("reply_path", param_reply_path, &reply_path),
		   NULL))
		return command_param_failed();

	/* FIXME: Allow sending to non-channel peers! */
	node_id_from_pubkey(&first_id, &hops[0].id);
	first_hop = active_channel_by_id(cmd->ld, &first_id, NULL);
	if (!first_hop)
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
	op = create_onionpacket(tmpctx, sphinx_path, &path_secrets);
	if (!op)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Creating onion failed (tlvs too long?)");

	if (!make_peer_send(cmd->ld, first_hop,
			    take(towire_send_onionmsg(NULL,
						      serialize_onionpacket(tmpctx, op),
						      NULL))))
		return command_fail(cmd, LIGHTNINGD, "First peer not ready");

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command send_onion_message_command = {
	"sendonionmessage",
	"utility",
	json_send_onion_message,
	"Send message over {hops} (id, [short_channel_id], [blinding], [enctlv], [rawtlv]) with optional {reply_path} (blinding, path[id, enctlv])"
};
AUTODATA(json_command, &send_onion_message_command);
#endif /* EXPERIMENTAL_FEATURES */
