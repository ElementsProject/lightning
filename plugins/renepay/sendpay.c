#include "config.h"
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/onion_encode.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/sendpay.h>

static struct command_result *param_route_hops(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct route_hop **hops)
{
	size_t i;
	const jsmntok_t *t;
	const char *err;

	if (tok->type != JSMN_ARRAY)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be an array", name);

	*hops = tal_arr(cmd, struct route_hop, tok->size);
	json_for_each_arr(i, t, tok)
	{
		struct amount_msat amount_msat;
		struct node_id id;
		struct short_channel_id channel;
		unsigned delay, direction;

		err = json_scan(tmpctx, buffer, t,
				"{amount_msat:%,id:%,channel:%,direction:%,delay:%}",
				JSON_SCAN(json_to_msat, &amount_msat),
				JSON_SCAN(json_to_node_id, &id),
				JSON_SCAN(json_to_short_channel_id, &channel),
				JSON_SCAN(json_to_number, &direction),
				JSON_SCAN(json_to_number, &delay)
			);
		if (err != NULL) {
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Error parsing route_hop %s[%zu]: %s", name, i,
			    err);
		}

		if (direction != 0 && direction != 1)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "direction must be either 0 or 1");

		(*hops)[i].amount = amount_msat;
		(*hops)[i].node_id = id;
		(*hops)[i].delay = delay;
		(*hops)[i].scid = channel;
		(*hops)[i].direction = direction;
	}
	return NULL;
}

static struct command_result *param_blinded_path(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct blinded_path **blinded_path)
{
	size_t i;
	const jsmntok_t *t, *pathtok, *datatok;
	const char *err;

	*blinded_path = tal(cmd, struct blinded_path);
	err = json_scan(
	    tmpctx, buffer, tok, "{first_node_id:%,first_path_key:%}",
	    JSON_SCAN(json_to_pubkey, &(*blinded_path)->first_node_id.pubkey),
	    JSON_SCAN(json_to_pubkey, &(*blinded_path)->first_path_key));
	if (err != NULL) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Error parsing blinded_path %s: %s", name,
				    err);
	}
	pathtok = json_get_member(buffer, tok, "path");
	if (!pathtok)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s does not have a path", name);
	if (pathtok->type != JSMN_ARRAY)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "path in %s must be an array", name);

	(*blinded_path)->path =
	    tal_arr(*blinded_path, struct blinded_path_hop *, pathtok->size);
	json_for_each_arr(i, t, pathtok)
	{
		(*blinded_path)->path[i] =
		    tal((*blinded_path)->path, struct blinded_path_hop);
		struct blinded_path_hop *hop = (*blinded_path)->path[i];

		err =
		    json_scan(tmpctx, buffer, t, "{blinded_node_id:%}",
			      JSON_SCAN(json_to_pubkey, &hop->blinded_node_id));
		if (err != NULL)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Error parsing path[%zu]: %s", i,
					    err);

		datatok =
		    json_get_member(buffer, t, "encrypted_recipient_data");
		if (!datatok)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Error parsing path[%zu]: unable "
					    "to get encrypted_recipient_data",
					    i);
		hop->encrypted_recipient_data =
		    json_tok_bin_from_hex(hop, buffer, datatok);
	}
	return NULL;
}

struct renesendpay {
	struct route_hop *route;
	struct sha256 payment_hash;
	u64 groupid, partid;

	u32 final_cltv;
	struct amount_msat total_amount;
	struct amount_msat deliver_amount;
	struct amount_msat sent_amount;
	struct node_id destination;

	struct secret *payment_secret;
	struct blinded_path *blinded_path;

	const char *invoice, *label, *description;
	const u8 *metadata;

	struct secret *shared_secrets;
	unsigned int blockheight;
};

static struct command_result *sendpay_rpc_failure(struct command *cmd,
						  const char *method UNUSED,
						  const char *buffer,
						  const jsmntok_t *toks,
						  struct renesendpay *renesendpay)
{
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	u32 errcode;
	if (codetok != NULL)
		json_to_u32(buffer, codetok, &errcode);
	else
		errcode = LIGHTNINGD;

	return command_fail(
	    cmd, errcode, "renesendpay failed to error in RPC: %.*s",
	    json_tok_full_len(toks), json_tok_full(buffer, toks));
}

static void sphinx_append_blinded_path(const tal_t *ctx,
				       struct sphinx_path *sp,
				       const struct blinded_path *blinded_path,
				       const struct amount_msat deliver,
				       const struct amount_msat total,
				       const u32 final_cltv)
{
	const size_t pathlen = tal_count(blinded_path->path);
	bool ret;

	for (size_t i = 0; i < pathlen; i++) {
		bool first = (i == 0);
		bool final = (i == pathlen - 1);

		const struct blinded_path_hop *bhop = blinded_path->path[i];
		const u8 *payload = onion_blinded_hop(
		    ctx, final ? &deliver : NULL, final ? &total : NULL,
		    final ? &final_cltv : NULL, bhop->encrypted_recipient_data,
		    first ? &blinded_path->first_path_key : NULL);
		// FIXME: better handle error here
		ret = sphinx_add_hop_has_length(
		    sp,
		    first ? &blinded_path->first_node_id.pubkey
			  : &bhop->blinded_node_id,
		    take(payload));
		assert(ret);
	}
}

static void sphinx_append_final_hop(const tal_t *ctx,
				    struct sphinx_path *sp,
				    const struct secret *payment_secret,
				    const struct node_id *node,
				    const struct amount_msat deliver,
				    const struct amount_msat total,
				    const u32 final_cltv,
				    const u8 *payment_metadata)
{
	struct pubkey destination;
	bool ret = pubkey_from_node_id(&destination, node);
	assert(ret);

	const u8 *payload = onion_final_hop(ctx, deliver, final_cltv, total,
					    payment_secret, payment_metadata);
	// FIXME: better handle error here
	ret = sphinx_add_hop_has_length(sp, &destination, take(payload));
	assert(ret);
}

static const u8 *create_onion(const tal_t *ctx,
			      struct renesendpay *renesendpay,
			      const struct node_id first_node,
			      const size_t first_index)
{
	bool ret;
	const tal_t *this_ctx = tal(ctx, tal_t);
	struct node_id current_node = first_node;
	struct pubkey node;
	const u8 *payload;
	const size_t pathlen = tal_count(renesendpay->route);

	struct sphinx_path *sp =
	    sphinx_path_new(this_ctx, renesendpay->payment_hash.u.u8,
			    sizeof(renesendpay->payment_hash.u.u8));

	for (size_t i = first_index; i < pathlen; i++) {
		/* Encrypted message is for node[i] but the data is hop[i+1],
		 * therein lays the problem with sendpay's API. */
		ret = pubkey_from_node_id(&node, &current_node);
		assert(ret);

		struct route_hop *hop = &renesendpay->route[i];
		payload =
		    onion_nonfinal_hop(this_ctx, &hop->scid, hop->amount,
				       hop->delay + renesendpay->blockheight);
		// FIXME: better handle error here
		ret = sphinx_add_hop_has_length(sp, &node, take(payload));
		assert(ret);
		current_node = renesendpay->route[i].node_id;
	}

	const u32 final_cltv = renesendpay->final_cltv + renesendpay->blockheight;
	if(renesendpay->blinded_path){
		sphinx_append_blinded_path(this_ctx,
					   sp,
					   renesendpay->blinded_path,
					   renesendpay->deliver_amount,
					   renesendpay->total_amount,
					   final_cltv);
	}else{
		sphinx_append_final_hop(this_ctx,
					sp,
					renesendpay->payment_secret,
					&current_node,
					renesendpay->deliver_amount,
					renesendpay->total_amount,
					final_cltv,
					renesendpay->metadata);
	}

	struct secret *shared_secrets;
	struct onionpacket *packet = create_onionpacket(
	    this_ctx, sp, ROUTING_INFO_SIZE, &shared_secrets);
	renesendpay->shared_secrets = tal_steal(renesendpay, shared_secrets);

	const u8 *onion = serialize_onionpacket(ctx, packet);
	tal_free(this_ctx);
	return onion;
}

static struct command_result *sendonion_done(struct command *cmd,
					     const char *method UNUSED,
					     const char *buffer,
					     const jsmntok_t *toks,
					     struct renesendpay *renesendpay)
{
	const char *err;
	u64 created_index;
	u32 timestamp;
	err = json_scan(tmpctx, buffer, toks, "{created_index:%,created_at:%}",
			JSON_SCAN(json_to_u64, &created_index),
			JSON_SCAN(json_to_u32, &timestamp));
	if (err)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "renesendpay failed to read response from sendonion: %s",
		    err);

	struct json_stream *response = jsonrpc_stream_success(cmd);
	json_add_string(response, "message",
			"Monitor status with listpays or waitsendpay");

	json_add_u64(response, "created_index", created_index);
	json_add_u32(response, "created_at", timestamp);
	json_add_sha256(response, "payment_hash", &renesendpay->payment_hash);
	json_add_u64(response, "groupid", renesendpay->groupid);
	json_add_u64(response, "partid", renesendpay->partid);
	json_add_node_id(response, "destination", &renesendpay->destination);
	json_add_amount_msat(response, "amount_sent_msat",
			     renesendpay->sent_amount);
	json_add_amount_msat(response, "amount_delivered_msat",
			     renesendpay->deliver_amount);
	json_add_amount_msat(response, "amount_total_msat",
			     renesendpay->total_amount);
	json_add_string(response, "invoice", renesendpay->invoice);

	if (renesendpay->label)
		json_add_string(response, "label", renesendpay->label);
	if (renesendpay->description)
		json_add_string(response, "description",
				renesendpay->description);
	if (renesendpay->metadata)
		json_add_hex_talarr(response, "payment_metadata",
				    renesendpay->metadata);

	/* FIXME: shall we report the blinded path, secret and route used? */
	return command_finished(cmd, response);
}

static struct command_result *waitblockheight_done(struct command *cmd,
						   const char *method UNUSED,
						   const char *buffer,
						   const jsmntok_t *toks,
						   struct renesendpay *renesendpay)
{
	const char *err;
	err = json_scan(tmpctx, buffer, toks, "{blockheight:%}",
			JSON_SCAN(json_to_u32, &renesendpay->blockheight));
	renesendpay->blockheight += 1;
	if (err)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "renesendpay failed to read blockheight "
				    "from waitblockheight response.");

	const u8 *onion;
	struct out_req *req;

	onion =
	    create_onion(tmpctx, renesendpay, renesendpay->route[0].node_id, 1);
	req = jsonrpc_request_start(cmd, "sendonion", sendonion_done,
				    sendpay_rpc_failure, renesendpay);
	json_add_hex_talarr(req->js, "onion", onion);
	json_add_sha256(req->js, "payment_hash", &renesendpay->payment_hash);
	json_add_u64(req->js, "partid", renesendpay->partid);
	json_add_u64(req->js, "groupid", renesendpay->groupid);
	json_add_node_id(req->js, "destination", &renesendpay->destination);
	json_add_amount_msat(req->js, "amount_msat", renesendpay->deliver_amount);

	const struct route_hop *hop = &renesendpay->route[0];
	json_object_start(req->js, "first_hop");
	json_add_amount_msat(req->js, "amount_msat", hop->amount);
	json_add_num(req->js, "delay", hop->delay + renesendpay->blockheight);
	json_add_node_id(req->js, "id", &hop->node_id);
	json_add_short_channel_id(req->js, "channel", hop->scid);
	json_object_end(req->js);

	json_array_start(req->js, "shared_secrets");
	for (size_t i = 0; i < tal_count(renesendpay->shared_secrets); i++) {
		json_add_secret(req->js, NULL, &renesendpay->shared_secrets[i]);
	}
	json_array_end(req->js);

	if (renesendpay->label)
		json_add_string(req->js, "label", renesendpay->label);
	if (renesendpay->description)
		json_add_string(req->js, "description",
				renesendpay->description);
	if (renesendpay->invoice)
		json_add_string(req->js, "bolt11", renesendpay->invoice);

	return send_outreq(req);
}

struct command_result *json_renesendpay(struct command *cmd,
					const char *buf,
					const jsmntok_t *params)
{
	struct route_hop *route;
	struct sha256 *payment_hash;
	const char *invoice, *label, *description;
	struct amount_msat *amount, *total_amount;
	u64 *groupid, *partid;
	u32 *final_cltv;
	struct node_id *destination;
	u8 *metadata;

	/* only used in the case of BOLT11 */
	struct secret *payment_secret;

	/* only used in the case of BOLT12 */
	struct blinded_path *blinded_path;

	if (!param(cmd, buf, params,
		   p_req("route", param_route_hops, &route),
		   p_req("payment_hash", param_sha256, &payment_hash),
		   p_req("groupid", param_u64, &groupid),
		   p_req("partid", param_u64, &partid),
		   p_req("amount_msat", param_msat, &amount),
		   p_req("total_amount_msat", param_msat, &total_amount),
		   p_req("destination", param_node_id, &destination),
		   p_req("final_cltv", param_u32, &final_cltv),
		   p_opt("payment_secret", param_secret, &payment_secret),
		   p_opt("blinded_path", param_blinded_path, &blinded_path),
		   p_opt("invoice", param_invstring, &invoice),
		   p_opt("label", param_string, &label),
		   p_opt("description", param_string, &description),
		   p_opt("metadata", param_bin_from_hex, &metadata),
		   NULL))
		return command_param_failed();

	if (payment_secret && blinded_path)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "A payment cannot have both a secret and a blinded path.");
	if (!payment_secret && !blinded_path)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "For a BOLT11 payment a payment_secret "
		    "must be specified and for a BOLT12 "
		    "payment a blinded_path must be specified.");

	plugin_log(cmd->plugin, LOG_DBG, "renesendpay called: %.*s",
		   json_tok_full_len(params), json_tok_full(buf, params));

	struct renesendpay *renesendpay = tal(cmd, struct renesendpay);
	renesendpay->route = tal_steal(renesendpay, route);
	renesendpay->payment_hash = *payment_hash;
	renesendpay->partid = *partid;
	renesendpay->groupid = *groupid;

	renesendpay->sent_amount = renesendpay->route[0].amount;
	renesendpay->total_amount = *total_amount;
	renesendpay->deliver_amount = *amount;
	renesendpay->final_cltv = *final_cltv;

	renesendpay->destination = *destination;

	renesendpay->payment_secret = tal_steal(renesendpay, payment_secret);
	renesendpay->blinded_path = tal_steal(renesendpay, blinded_path);

	renesendpay->invoice = tal_steal(renesendpay, invoice);
	renesendpay->label = tal_steal(renesendpay, label);
	renesendpay->description = tal_steal(renesendpay, description);
	renesendpay->metadata = tal_steal(renesendpay, metadata);

	struct out_req *req =
	    jsonrpc_request_start(cmd, "waitblockheight", waitblockheight_done,
				  sendpay_rpc_failure, renesendpay);
	json_add_num(req->js, "blockheight", 0);
	return send_outreq(req);
}
