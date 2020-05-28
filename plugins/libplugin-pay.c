#include "common/type_to_string.h"
#include <plugins/libplugin-pay.h>
#include <stdio.h>

#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>

#define DEFAULT_FINAL_CLTV_DELTA 9

struct payment *payment_new(tal_t *ctx, struct command *cmd,
			    struct payment *parent,
			    struct payment_modifier **mods)
{
	struct payment *p = tal(ctx, struct payment);
	p->children = tal_arr(p, struct payment *, 0);
	p->parent = parent;
	p->modifiers = mods;
	p->cmd = cmd;
	p->start_time = time_now();
	p->result = NULL;
	p->getroute_cltv = DEFAULT_FINAL_CLTV_DELTA;

	/* Copy over the relevant pieces of information. */
	if (parent != NULL) {
		assert(cmd == NULL);
		tal_arr_expand(&parent->children, p);
		p->destination = p->getroute_destination = parent->destination;
		p->getroute_cltv = parent->getroute_cltv;
		p->amount = parent->amount;
		p->payment_hash = parent->payment_hash;
		p->partid = payment_root(p->parent)->next_partid++;
		p->plugin = parent->plugin;
	} else {
		assert(cmd != NULL);
		p->partid = 0;
		p->next_partid = 1;
		p->plugin = cmd->plugin;
		p->channel_hints = tal_arr(p, struct channel_hint, 0);
		p->excluded_nodes = tal_arr(p, struct node_id, 0);
		p->abort = false;
	}

	/* Initialize all modifier data so we can point to the fields when
	 * wiring into the param() call in a JSON-RPC handler. The callback
	 * can also just `memcpy` the parent if this outside access is not
	 * required. */
	p->modifier_data = tal_arr(p, void *, 0);
	for (size_t i=0; mods[i] != NULL; i++) {
		if (mods[i]->data_init != NULL)
			tal_arr_expand(&p->modifier_data,
				       mods[i]->data_init(p));
		else
			tal_arr_expand(&p->modifier_data, NULL);
	}

	return p;
}

struct payment *payment_root(struct payment *p)
{
	if (p->parent == NULL)
		return p;
	else
		return payment_root(p->parent);
}

/* Generic handler for RPC failures that should end up failing the payment. */
static struct command_result *payment_rpc_failure(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *toks,
						  struct payment *p)
{
	plugin_log(p->plugin, LOG_DBG,
		   "Failing a partial payment due to a failed RPC call: %.*s",
		   toks->end - toks->start, buffer + toks->start);

	p->step = PAYMENT_STEP_FAILED;
	payment_continue(p);
	return command_still_pending(cmd);
}

struct payment_tree_result payment_collect_result(struct payment *p)
{
	struct payment_tree_result res;
	size_t numchildren = tal_count(p->children);
	res.sent = AMOUNT_MSAT(0);
	/* If we didn't have a route, we didn't attempt. */
	res.attempts = p->route == NULL ? 0 : 1;
	res.treestates = p->step;
	res.leafstates = 0;
	res.preimage = NULL;
	res.failure = NULL;
	if (p->step == PAYMENT_STEP_FAILED && p->result != NULL)
		res.failure = p->result;

	if (numchildren == 0) {
		res.leafstates |= p->step;
		if (p->result && p->result->state == PAYMENT_COMPLETE) {
			res.sent = p->result->amount_sent;
			res.preimage = p->result->payment_preimage;
		}
	}

	for (size_t i = 0; i < numchildren; i++) {
		struct payment_tree_result cres =
		    payment_collect_result(p->children[i]);

		/* Some of our subpayments have succeeded, aggregate how much
		 * we sent in total. */
		if (!amount_msat_add(&res.sent, res.sent, cres.sent))
			plugin_err(
			    p->plugin,
			    "Number overflow summing partial payments: %s + %s",
			    type_to_string(tmpctx, struct amount_msat,
					   &res.sent),
			    type_to_string(tmpctx, struct amount_msat,
					   &cres.sent));

		/* Bubble up the first preimage we see. */
		if (res.preimage == NULL && cres.preimage != NULL)
			res.preimage = cres.preimage;

		res.leafstates |= cres.leafstates;
		res.treestates |= cres.treestates;
		res.attempts += cres.attempts;

		/* We bubble the failure result with the highest failcode up
		 * to the root. */
		if (res.failure == NULL ||
		    (cres.failure != NULL &&
		     cres.failure->failcode > res.failure->failcode)) {
			res.failure = cres.failure;
		}
	}
	return res;
}

static struct command_result *payment_getinfo_success(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *toks,
						      struct payment *p)
{
	const jsmntok_t *blockheighttok =
	    json_get_member(buffer, toks, "blockheight");
	json_to_number(buffer, blockheighttok, &p->start_block);
	payment_continue(p);
	return command_still_pending(cmd);
}

void payment_start(struct payment *p)
{
	p->step = PAYMENT_STEP_INITIALIZED;
	p->current_modifier = -1;

	/* TODO If this is not the root, we can actually skip the getinfo call
	 * and just reuse the parent's value. */
	send_outreq(p->plugin,
		    jsonrpc_request_start(p->plugin, NULL, "getinfo",
					  payment_getinfo_success,
					  payment_rpc_failure, p));
}

static bool route_hop_from_json(struct route_hop *dst, const char *buffer,
				const jsmntok_t *toks)
{
	const jsmntok_t *idtok = json_get_member(buffer, toks, "id");
	const jsmntok_t *channeltok = json_get_member(buffer, toks, "channel");
	const jsmntok_t *directiontok = json_get_member(buffer, toks, "direction");
	const jsmntok_t *amounttok = json_get_member(buffer, toks, "amount_msat");
	const jsmntok_t *delaytok = json_get_member(buffer, toks, "delay");
	const jsmntok_t *styletok = json_get_member(buffer, toks, "style");

	if (idtok == NULL || channeltok == NULL || directiontok == NULL ||
	    amounttok == NULL || delaytok == NULL || styletok == NULL)
		return false;

	json_to_node_id(buffer, idtok, &dst->nodeid);
	json_to_short_channel_id(buffer, channeltok, &dst->channel_id);
	json_to_int(buffer, directiontok, &dst->direction);
	json_to_msat(buffer, amounttok, &dst->amount);
	json_to_number(buffer, delaytok, &dst->delay);
	dst->style = json_tok_streq(buffer, styletok, "legacy")
			 ? ROUTE_HOP_LEGACY
			 : ROUTE_HOP_TLV;
	return true;
}

static struct route_hop *
tal_route_from_json(const tal_t *ctx, const char *buffer, const jsmntok_t *toks)
{
	size_t num = toks->size, i;
	struct route_hop *hops;
	const jsmntok_t *rtok;
	if (toks->type != JSMN_ARRAY)
		return NULL;

	hops = tal_arr(ctx, struct route_hop, num);
	json_for_each_arr(i, rtok, toks) {
		if (!route_hop_from_json(&hops[i], buffer, rtok))
			return tal_free(hops);
	}
	return hops;
}

static struct command_result *payment_getroute_result(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *toks,
						      struct payment *p)
{
	const jsmntok_t *rtok = json_get_member(buffer, toks, "route");
	assert(rtok != NULL);
	p->route = tal_route_from_json(p, buffer, rtok);
	p->step = PAYMENT_STEP_GOT_ROUTE;

	/* Allow modifiers to modify the route, before
	 * payment_compute_onion_payloads uses the route to generate the
	 * onion_payloads */
	payment_continue(p);
	return command_still_pending(cmd);
}

static struct command_result *payment_getroute_error(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *toks,
						     struct payment *p)
{
	p->step = PAYMENT_STEP_FAILED;
	p->route = NULL;
	payment_continue(p);

	/* Let payment_finished_ handle this, so we mark it as pending */
	return command_still_pending(cmd);
}

/* Iterate through the channel_hints and exclude any channel that we are
 * confident will not be able to handle this payment. */
static void payment_getroute_add_excludes(struct payment *p,
					  struct json_stream *js)
{
	struct payment *root = payment_root(p);
	struct channel_hint *hint;

	json_array_start(js, "exclude");
	for (size_t i = 0; i < tal_count(root->channel_hints); i++) {
		hint = &root->channel_hints[i];

		if (!hint->enabled)
			json_add_short_channel_id_dir(js, NULL, &hint->scid);

		else if (amount_msat_greater_eq(p->amount,
						hint->estimated_capacity))
			json_add_short_channel_id_dir(js, NULL, &hint->scid);
	}
	json_array_end(js);
}

static void payment_getroute(struct payment *p)
{
	struct out_req *req;
	req = jsonrpc_request_start(p->plugin, NULL, "getroute",
				    payment_getroute_result,
				    payment_getroute_error, p);
	json_add_node_id(req->js, "id", p->getroute_destination);
	json_add_amount_msat_only(req->js, "msatoshi", p->amount);
	json_add_num(req->js, "riskfactor", 1);
	json_add_num(req->js, "cltv", p->getroute_cltv);
	payment_getroute_add_excludes(p, req->js);
	send_outreq(p->plugin, req);
}

static u8 *tal_towire_legacy_payload(const tal_t *ctx, const struct legacy_payload *payload)
{
	const u8 padding[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			      0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	/* Prepend 0 byte for realm */
	u8 *buf = tal_arrz(ctx, u8, 1);
	towire_short_channel_id(&buf, &payload->scid);
	towire_u64(&buf, payload->forward_amt.millisatoshis); /* Raw: low-level serializer */
	towire_u32(&buf, payload->outgoing_cltv);
	towire(&buf, padding, ARRAY_SIZE(padding));
	assert(tal_bytelen(buf) == 1 + 32);
	return buf;
}

static struct createonion_response *
tal_createonion_response_from_json(const tal_t *ctx, const char *buffer,
				   const jsmntok_t *toks)
{
	size_t i;
	struct createonion_response *resp;
	const jsmntok_t *oniontok = json_get_member(buffer, toks, "onion");
	const jsmntok_t *secretstok = json_get_member(buffer, toks, "shared_secrets");
	const jsmntok_t *cursectok;

	if (oniontok == NULL || secretstok == NULL)
		return NULL;
	resp = tal(ctx, struct createonion_response);

	if (oniontok->type != JSMN_STRING)
		goto fail;

	resp->onion = json_tok_bin_from_hex(resp, buffer, oniontok);
	resp->shared_secrets = tal_arr(resp, struct secret, secretstok->size);

	json_for_each_arr(i, cursectok, secretstok) {
		if (cursectok->type != JSMN_STRING)
			goto fail;
		json_to_secret(buffer, cursectok, &resp->shared_secrets[i]);
	}
	return resp;

fail:
	return tal_free(resp);
}

static struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buffer,
						    const jsmntok_t *toks)
{
	const jsmntok_t *idtok = json_get_member(buffer, toks, "id");
	const jsmntok_t *hashtok = json_get_member(buffer, toks, "payment_hash");
	const jsmntok_t *partidtok = json_get_member(buffer, toks, "partid");
	const jsmntok_t *senttok = json_get_member(buffer, toks, "amount_sent_msat");
	const jsmntok_t *statustok = json_get_member(buffer, toks, "status");
	const jsmntok_t *preimagetok = json_get_member(buffer, toks, "payment_preimage");
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	const jsmntok_t *datatok = json_get_member(buffer, toks, "data");
	const jsmntok_t *erridxtok, *msgtok, *failcodetok, *rawmsgtok,
		*failcodenametok, *errchantok, *errnodetok, *errdirtok;
	struct payment_result *result;

	/* Check if we have an error and need to descend into data to get
	 * details. */
	if (codetok != NULL && datatok != NULL) {
		idtok = json_get_member(buffer, datatok, "id");
		hashtok = json_get_member(buffer, datatok, "payment_hash");
		partidtok = json_get_member(buffer, datatok, "partid");
		senttok = json_get_member(buffer, datatok, "amount_sent_msat");
		statustok = json_get_member(buffer, datatok, "status");
	}

	/* Initial sanity checks, all these fields must exist. */
	if (idtok == NULL || idtok->type != JSMN_PRIMITIVE ||
	    hashtok == NULL || hashtok->type != JSMN_STRING ||
	    senttok == NULL || senttok->type != JSMN_STRING ||
	    statustok == NULL || statustok->type != JSMN_STRING) {
		return NULL;
	}

	result = tal(ctx, struct payment_result);

	if (codetok != NULL)
		json_to_u32(buffer, codetok, &result->code);
	else
		result->code = 0;

	/* If the partid is 0 it'd be omitted in waitsendpay, fix this here. */
	if (partidtok != NULL)
		json_to_u32(buffer, partidtok, &result->partid);
	else
		result->partid = 0;

	json_to_u64(buffer, idtok, &result->id);
	json_to_msat(buffer, senttok, &result->amount_sent);
	if (json_tok_streq(buffer, statustok, "pending")) {
		result->state = PAYMENT_PENDING;
	} else if (json_tok_streq(buffer, statustok, "complete")) {
		result->state = PAYMENT_COMPLETE;
	} else if (json_tok_streq(buffer, statustok, "failed")) {
		result->state = PAYMENT_FAILED;
	} else {
		goto fail;
	}

	if (preimagetok != NULL) {
		result->payment_preimage = tal(result, struct preimage);
		json_to_preimage(buffer, preimagetok, result->payment_preimage);
	}

	/* Now extract the error details if the error code is not 0 */
	if (result->code != 0) {
		erridxtok = json_get_member(buffer, datatok, "erring_index");
		errnodetok = json_get_member(buffer, datatok, "erring_node");
		errchantok = json_get_member(buffer, datatok, "erring_channel");
		errdirtok = json_get_member(buffer, datatok, "erring_direction");
		failcodetok = json_get_member(buffer, datatok, "failcode");
		failcodenametok =json_get_member(buffer, datatok, "failcodename");
		msgtok = json_get_member(buffer, toks, "message");
		rawmsgtok = json_get_member(buffer, datatok, "raw_message");
		if (failcodetok == NULL || failcodetok->type != JSMN_PRIMITIVE ||
		    failcodenametok == NULL || failcodenametok->type != JSMN_STRING ||
		    (erridxtok != NULL && erridxtok->type != JSMN_PRIMITIVE) ||
		    (errnodetok != NULL && errnodetok->type != JSMN_STRING) ||
		    (errchantok != NULL && errchantok->type != JSMN_STRING) ||
		    (errdirtok != NULL && errdirtok->type != JSMN_PRIMITIVE) ||
		    msgtok == NULL || msgtok->type != JSMN_STRING ||
		    (rawmsgtok != NULL && rawmsgtok->type != JSMN_STRING))
			goto fail;

		if (rawmsgtok != NULL)
			result->raw_message = json_tok_bin_from_hex(result, buffer, rawmsgtok);
		else
			result->raw_message = NULL;

		result->failcodename = json_strdup(result, buffer, failcodenametok);
		json_to_u32(buffer, failcodetok, &result->failcode);
		result->message = json_strdup(result, buffer, msgtok);

		if (erridxtok != NULL) {
			result->erring_index = tal(result, u32);
			json_to_u32(buffer, erridxtok, result->erring_index);
		} else {
			result->erring_index = NULL;
		}

		if (errdirtok != NULL) {
			result->erring_direction = tal(result, int);
			json_to_int(buffer, errdirtok, result->erring_direction);
		} else {
			result->erring_direction = NULL;
		}

		if (errnodetok != NULL) {
			result->erring_node = tal(result, struct node_id);
			json_to_node_id(buffer, errnodetok,
					result->erring_node);
		} else {
			result->erring_node = NULL;
		}

		if (errchantok != NULL) {
			result->erring_channel =
			    tal(result, struct short_channel_id);
			json_to_short_channel_id(buffer, errchantok,
						 result->erring_channel);
		} else {
			result->erring_channel = NULL;
		}
	}

	return result;
fail:
	return tal_free(result);
}

static struct command_result *
payment_waitsendpay_finished(struct command *cmd, const char *buffer,
			     const jsmntok_t *toks, struct payment *p)
{
	struct payment *root;
	struct channel_hint hint;
	struct route_hop *hop;
	assert(p->route != NULL);

	p->result = tal_sendpay_result_from_json(p, buffer, toks);

	if (p->result == NULL)
		plugin_err(
		    p->plugin, "Unable to parse `waitsendpay` result: %.*s",
		    json_tok_full_len(toks), json_tok_full(buffer, toks));

	if (p->result->state == PAYMENT_COMPLETE) {
		p->step = PAYMENT_STEP_SUCCESS;
		goto cont;
	}

	p->step = PAYMENT_STEP_FAILED;
	root = payment_root(p);

	switch (p->result->failcode) {
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_CHANNEL_DISABLED:
	case WIRE_UNKNOWN_NEXT_PEER:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		/* All of these result in the channel being marked as disabled. */
		assert(*p->result->erring_index < tal_count(p->route));
		hop = &p->route[*p->result->erring_index];
		hint.enabled = false;
		hint.scid.scid = hop->channel_id;
		hint.scid.dir = hop->direction;
		hint.estimated_capacity = AMOUNT_MSAT(0);
		tal_arr_expand(&root->channel_hints, hint);
		break;
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		/* These are an indication that the capacity was insufficient,
		 * remember the amount we tried as an estimate. */
		assert(*p->result->erring_index < tal_count(p->route));
		hop = &p->route[*p->result->erring_index];
		hint.enabled = true;
		hint.scid.scid = hop->channel_id;
		hint.scid.dir = hop->direction;
		hint.estimated_capacity.millisatoshis = hop->amount.millisatoshis * 0.75; /* Raw: Multiplication */
		tal_arr_expand(&root->channel_hints, hint);
		break;

	case WIRE_INVALID_ONION_PAYLOAD:
	case WIRE_INVALID_REALM:
	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
#if EXPERIMENTAL_FEATURES
	case WIRE_INVALID_ONION_BLINDING:
#endif
		/* These are reported by the last hop, i.e., the destination of hop i-1. */
		assert(*p->result->erring_index - 1 < tal_count(p->route));
		hop = &p->route[*p->result->erring_index - 1];
		tal_arr_expand(&root->excluded_nodes, hop->nodeid);
		break;

 	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_MPP_TIMEOUT:
		/* These are permanent failures that should abort all of our
		 * attempts right away. We'll still track pending partial
		 * payments correctly, just not start new ones. */
		root->abort = true;
		break;

	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_EXPIRY_TOO_FAR:
	case WIRE_EXPIRY_TOO_SOON:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		/* These are issues that are due to gossipd being out of date,
		 * we ignore them here, and wait for gossipd to adjust
		 * instead. */
		break;
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		/* These are symptoms of intermediate hops tampering with the
		 * payment. */
		hop = &p->route[*p->result->erring_index];
		plugin_log(
		    p->plugin, LOG_UNUSUAL,
		    "Node %s reported an incorrect HTLC amount, this could be "
		    "a prior hop messing with the amounts.",
		    type_to_string(tmpctx, struct node_id, &hop->nodeid));
		break;
	}

cont:
	payment_continue(p);
	return command_still_pending(cmd);
}

static struct command_result *payment_sendonion_success(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *toks,
							  struct payment *p)
{
	struct out_req *req;
	req = jsonrpc_request_start(p->plugin, NULL, "waitsendpay",
				    payment_waitsendpay_finished,
				    payment_waitsendpay_finished, p);
	json_add_sha256(req->js, "payment_hash", p->payment_hash);
	json_add_num(req->js, "partid", p->partid);
	send_outreq(p->plugin, req);

	return command_still_pending(cmd);
}

static struct command_result *payment_createonion_success(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *toks,
							  struct payment *p)
{
	struct out_req *req;
	struct route_hop *first = &p->route[0];
	struct secret *secrets;
	p->createonion_response = tal_createonion_response_from_json(p, buffer, toks);

	req = jsonrpc_request_start(p->plugin, NULL, "sendonion",
				    payment_sendonion_success,
				    payment_rpc_failure, p);
	json_add_hex_talarr(req->js, "onion", p->createonion_response->onion);

	json_object_start(req->js, "first_hop");
	json_add_short_channel_id(req->js, "channel", &first->channel_id);
	json_add_num(req->js, "direction", first->direction);
	json_add_amount_msat_only(req->js, "amount_msat", first->amount);
	json_add_num(req->js, "delay", first->delay);
	json_add_node_id(req->js, "id", &first->nodeid);
	json_object_end(req->js);

	json_add_sha256(req->js, "payment_hash", p->payment_hash);

	json_array_start(req->js, "shared_secrets");
	secrets = p->createonion_response->shared_secrets;
	for(size_t i=0; i<tal_count(secrets); i++)
		json_add_secret(req->js, NULL, &secrets[i]);
	json_array_end(req->js);

	json_add_num(req->js, "partid", p->partid);

	send_outreq(p->plugin, req);
	return command_still_pending(cmd);
}

/* Temporary serialization method for the tlv_payload.data until we rework the
 * API that is generated from the specs to use the setter/getter interface. */
static void tlvstream_set_tlv_payload_data(struct tlv_field **stream,
					   struct secret *payment_secret,
					   u64 total_msat)
{
	u8 *ser = tal_arr(NULL, u8, 0);
	towire_secret(&ser, payment_secret);
	towire_tu64(&ser, total_msat);
	tlvstream_set_raw(stream, TLV_TLV_PAYLOAD_PAYMENT_DATA, take(ser));
}
static void payment_add_hop_onion_payload(struct payment *p,
					  struct createonion_hop *dst,
					  struct route_hop *node,
					  struct route_hop *next,
					  bool final,
					  struct secret *payment_secret)
{
	struct createonion_request *cr = p->createonion_request;
	u32 cltv = p->start_block + next->delay;
	u64 msat = next->amount.millisatoshis; /* Raw: TLV payload generation*/
	struct tlv_field *fields;
	static struct short_channel_id all_zero_scid = {.u64 = 0};

	/* This is the information of the node processing this payload, while
	 * `next` are the instructions to include in the payload, which is
	 * basically the channel going to the next node. */
	dst->style = node->style;
	dst->pubkey = node->nodeid;

	switch (node->style) {
	case ROUTE_HOP_LEGACY:
		dst->legacy_payload = tal(cr->hops, struct legacy_payload);
		dst->legacy_payload->forward_amt = next->amount;

		if (!final)
			dst->legacy_payload->scid = next->channel_id;
		else
			dst->legacy_payload->scid = all_zero_scid;

		dst->legacy_payload->outgoing_cltv = cltv;
		break;
	case ROUTE_HOP_TLV:
		dst->tlv_payload = tlv_tlv_payload_new(cr->hops);
		fields = dst->tlv_payload->fields;
		tlvstream_set_tu64(&fields, TLV_TLV_PAYLOAD_AMT_TO_FORWARD,
				   msat);
		tlvstream_set_tu32(&fields, TLV_TLV_PAYLOAD_OUTGOING_CLTV_VALUE,
				   cltv);

		if (!final)
			tlvstream_set_short_channel_id(&fields,
						       TLV_TLV_PAYLOAD_SHORT_CHANNEL_ID,
						       &next->channel_id);

		if (payment_secret != NULL) {
			assert(final);
			tlvstream_set_tlv_payload_data(&fields, payment_secret,
						       msat);
		}
		break;
	}
}

static void payment_compute_onion_payloads(struct payment *p)
{
	struct createonion_request *cr;
	size_t hopcount;
	struct payment *root = payment_root(p);
	p->step = PAYMENT_STEP_ONION_PAYLOAD;
	hopcount = tal_count(p->route);

	/* Now compute the payload we're about to pass to `createonion` */
	cr = p->createonion_request = tal(p, struct createonion_request);
	cr->assocdata = tal_arr(cr, u8, 0);
	towire_sha256(&cr->assocdata, p->payment_hash);
	cr->session_key = NULL;
	cr->hops = tal_arr(cr, struct createonion_hop, tal_count(p->route));

	/* Non-final hops */
	for (size_t i = 0; i < hopcount - 1; i++) {
		/* The message is destined for hop i, but contains fields for
		 * i+1 */
		payment_add_hop_onion_payload(p, &cr->hops[i], &p->route[i],
					      &p->route[i + 1], false, NULL);
	}

	/* Final hop */
	payment_add_hop_onion_payload(
	    p, &cr->hops[hopcount - 1], &p->route[hopcount - 1],
	    &p->route[hopcount - 1], true, root->payment_secret);

	/* Now allow all the modifiers to mess with the payloads, before we
	 * serialize via a call to createonion in the next step. */
	payment_continue(p);
}

static void payment_sendonion(struct payment *p)
{
	struct out_req *req;
	u8 *payload, *tlv;
	req = jsonrpc_request_start(p->plugin, NULL, "createonion",
				    payment_createonion_success,
				    payment_rpc_failure, p);

	json_array_start(req->js, "hops");
	for (size_t i = 0; i < tal_count(p->createonion_request->hops); i++) {
		json_object_start(req->js, NULL);
		struct createonion_hop *hop = &p->createonion_request->hops[i];
		json_add_node_id(req->js, "pubkey", &hop->pubkey);
		if (hop->style == ROUTE_HOP_LEGACY) {
			payload = tal_towire_legacy_payload(tmpctx, hop->legacy_payload);
			json_add_hex_talarr(req->js, "payload", payload);
		}else {
			tlv = tal_arr(tmpctx, u8, 0);
			towire_tlvstream_raw(&tlv, hop->tlv_payload->fields);
			payload = tal_arr(tmpctx, u8, 0);
			towire_bigsize(&payload, tal_bytelen(tlv));
			towire(&payload, tlv, tal_bytelen(tlv));
			json_add_hex_talarr(req->js, "payload", payload);
			tal_free(tlv);
		}
		tal_free(payload);
		json_object_end(req->js);
	}
	json_array_end(req->js);

	json_add_hex_talarr(req->js, "assocdata",
			    p->createonion_request->assocdata);

	if (p->createonion_request->session_key)
		json_add_secret(req->js, "sessionkey",
				p->createonion_request->session_key);

	send_outreq(p->plugin, req);
}

/* Mutual recursion. */
static void payment_finished(struct payment *p);

/* A payment is finished if a) it is in a final state, of b) it's in a
 * child-spawning state and all of its children are in a final state. */
static bool payment_is_finished(const struct payment *p)
{
	if (p->step == PAYMENT_STEP_FAILED || p->step == PAYMENT_STEP_SUCCESS)
		return true;
	else if (p->step == PAYMENT_STEP_SPLIT || p->step == PAYMENT_STEP_RETRY) {
		bool running_children = false;
		for (size_t i = 0; i < tal_count(p->children); i++)
			running_children |= !payment_is_finished(p->children[i]);
		return !running_children;
	} else {
		return false;
	}
}

static enum payment_step payment_aggregate_states(struct payment *p)
{
	enum payment_step agg = p->step;

	for (size_t i=0; i<tal_count(p->children); i++)
		agg |= payment_aggregate_states(p->children[i]);

	return agg;
}

/* A payment is finished if a) it is in a final state, of b) it's in a
 * child-spawning state and all of its children are in a final state. */
static bool payment_is_success(struct payment *p)
{
	return (payment_aggregate_states(p) & PAYMENT_STEP_SUCCESS) != 0;
}

/* Function to bubble up completions to the root, which actually holds on to
 * the command that initiated the flow. */
static void payment_child_finished(struct payment *p,
						     struct payment *child)
{
	if (!payment_is_finished(p))
		return;

	/* Should we continue bubbling up? */
	payment_finished(p);
}

/* This function is called whenever a payment ends up in a final state, or all
 * leafs in the subtree rooted in the payment are all in a final state. It is
 * called only once, and it is guaranteed to be called in post-order
 * traversal, i.e., all children are finished before the parent is called. */
static void payment_finished(struct payment *p)
{
	struct payment_tree_result result = payment_collect_result(p);
	struct json_stream *ret;
	struct command *cmd = p->cmd;

	p->end_time = time_now();

	/* Either none of the leaf attempts succeeded yet, or we have a
	 * preimage. */
	assert((result.leafstates & PAYMENT_STEP_SUCCESS) == 0 ||
	       result.preimage != NULL);

	if (p->parent == NULL && cmd == NULL) {
		/* This is the tree root, but we already reported success or
		 * failure, so noop. */
		return;

	}  else if (p->parent == NULL) {
		if (payment_is_success(p)) {
			assert(result.treestates & PAYMENT_STEP_SUCCESS);
			assert(result.leafstates & PAYMENT_STEP_SUCCESS);
			assert(result.preimage != NULL);

			ret = jsonrpc_stream_success(p->cmd);
			json_add_sha256(ret, "payment_hash", p->payment_hash);
			json_add_num(ret, "parts", result.attempts);

			json_add_amount_msat_compat(ret, p->amount, "msatoshi",
						    "amount_msat");
			json_add_amount_msat_compat(ret, result.sent,
						    "msatoshi_sent",
						    "amount_sent_msat");

			if (result.leafstates != PAYMENT_STEP_SUCCESS)
				json_add_string(
				    ret, "warning",
				    "Some parts of the payment are not yet "
				    "completed, but we have the confirmation "
				    "from the recipient.");
			json_add_preimage(ret, "payment_preimage", result.preimage);

			json_add_string(ret, "status", "complete");

			/* Unset the pointer to the cmd so we don't attempt to
			 * return a response twice. */
			p->cmd = NULL;
			if (command_finished(cmd, ret)) {/* Ignore result. */}
			return;
		} else {
			if (command_fail(p->cmd, JSONRPC2_INVALID_REQUEST,
					 "Not functional yet")) {/* Ignore result. */}

			return;
		}
	} else {
		payment_child_finished(p->parent, p);
		return;
	}
}

void payment_continue(struct payment *p)
{
	struct payment_modifier *mod;
	void *moddata;
	/* If we are in the middle of calling the modifiers, continue calling
	 * them, otherwise we can continue with the payment state-machine. */
	p->current_modifier++;
	mod = p->modifiers[p->current_modifier];

	if (mod != NULL) {
		/* There is another modifier, so call it. */
		moddata = p->modifier_data[p->current_modifier];
		return mod->post_step_cb(moddata, p);
	} else {
		/* There are no more modifiers, so reset the call chain and
		 * proceed to the next state. */
		p->current_modifier = -1;
		switch (p->step) {
		case PAYMENT_STEP_INITIALIZED:
			payment_getroute(p);
			return;

		case PAYMENT_STEP_GOT_ROUTE:
			payment_compute_onion_payloads(p);
			return;

		case PAYMENT_STEP_ONION_PAYLOAD:
			payment_sendonion(p);
			return;

		case PAYMENT_STEP_SUCCESS:
		case PAYMENT_STEP_FAILED:
			payment_finished(p);
			return;

		case PAYMENT_STEP_RETRY:
		case PAYMENT_STEP_SPLIT:
			/* Do nothing, we'll get pinged by a child succeeding
			 * or failing. */
			return;
		}
	}
	/* We should never get here, it'd mean one of the state machine called
	 * `payment_continue` after the final state. */
	abort();
}

void *payment_mod_get_data(const struct payment *p,
			   const struct payment_modifier *mod)
{
	for (size_t i = 0; p->modifiers[i] != NULL; i++)
		if (p->modifiers[i] == mod)
			return p->modifier_data[i];

	/* If we ever get here it means that we asked for the data for a
	 * non-existent modifier. This is a compile-time/wiring issue, so we
	 * better check that modifiers match the data we ask for. */
	abort();
}

static inline struct dummy_data *
dummy_data_init(struct payment *p)
{
	return tal(p, struct dummy_data);
}

static inline void dummy_step_cb(struct dummy_data *dd,
				 struct payment *p)
{
	fprintf(stderr, "dummy_step_cb called for payment %p at step %d\n", p, p->step);
	payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(dummy, struct dummy_data *, dummy_data_init,
			  dummy_step_cb);

static struct retry_mod_data *retry_data_init(struct payment *p);

static inline void retry_step_cb(struct retry_mod_data *rd,
				 struct payment *p);

static struct retry_mod_data *
retry_data_init(struct payment *p)
{
	struct retry_mod_data *rdata = tal(p, struct retry_mod_data);
	struct retry_mod_data *parent_rdata;
	if (p->parent != NULL) {
		parent_rdata = payment_mod_retry_get_data(p->parent);
		rdata->retries = parent_rdata->retries - 1;
	} else {
		rdata->retries = 10;
	}
	return rdata;
}

/* Determine whether retrying could possibly succeed. Retrying in this case
 * means that we repeat the entire flow, including computing a new route, new
 * payload and a new sendonion call. It does not mean we retry the exact same
 * attempt that just failed. */
static bool payment_can_retry(struct payment *p)
{
	struct payment_result *res = p->result;
	u32 idx;
	bool is_final;

	if (p->result == NULL)
		return false;

	idx = res->erring_index != NULL ? *res->erring_index : 0;
	is_final = (idx == tal_count(p->route));

	/* Full matrix of failure code x is_final. Prefer to retry once too
	 * often over eagerly failing. */
	switch (res->failcode) {
	case WIRE_EXPIRY_TOO_FAR:
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_INVALID_ONION_PAYLOAD:
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_REALM:
	case WIRE_MPP_TIMEOUT:
	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_UNKNOWN_NEXT_PEER:
		return !is_final;

	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_CHANNEL_DISABLED:
	case WIRE_EXPIRY_TOO_SOON:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
#if EXPERIMENTAL_FEATURES
	case WIRE_INVALID_ONION_BLINDING:
#endif
		return true;
	}

	/* We should never get here, otherwise the above `switch` isn't
	 * exhaustive. Nevertheless the failcode is provided by the erring
	 * node, so retry anyway. `abort()`ing on externally supplied info is
	 * not a good idea. */
	return true;
}

static inline void retry_step_cb(struct retry_mod_data *rd,
				 struct payment *p)
{
	struct payment *subpayment;
	struct retry_mod_data *rdata = payment_mod_retry_get_data(p);

	if (p->step != PAYMENT_STEP_FAILED)
		return payment_continue(p);

	/* If we failed to find a route, it's unlikely we can suddenly find a
	 * new one without any other changes, so it's time to give up. */
	if (p->route == NULL)
		return payment_continue(p);

	/* If the root is marked as abort, we do not retry anymore */
	if (payment_root(p)->abort)
		return payment_continue(p);

	if (!payment_can_retry(p))
		return payment_continue(p);

	/* If the failure was not final, and we tried a route, try again. */
	if (rdata->retries > 0) {
		subpayment = payment_new(p, NULL, p, p->modifiers);
		payment_start(subpayment);
		p->step = PAYMENT_STEP_RETRY;
	}

	payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(retry, struct retry_mod_data *, retry_data_init,
			  retry_step_cb);

static struct command_result *
local_channel_hints_listpeers(struct command *cmd, const char *buffer,
			      const jsmntok_t *toks, struct payment *p)
{
	const jsmntok_t *peers, *peer, *channels, *channel, *spendsats, *scid, *dir, *connected;
	size_t i, j;
	peers = json_get_member(buffer, toks, "peers");

	if (peers == NULL)
		goto done;
        /* cppcheck-suppress uninitvar - cppcheck can't undestand these macros. */
	json_for_each_arr(i, peer, peers) {
		channels = json_get_member(buffer, peer, "channels");
		if (channels == NULL)
			continue;

		connected = json_get_member(buffer, peer, "connected");

		json_for_each_arr(j, channel, channels) {
			struct channel_hint h;
			spendsats = json_get_member(buffer, channel, "spendable_msat");
			scid = json_get_member(buffer, channel, "short_channel_id");
			dir = json_get_member(buffer, channel, "direction");
			assert(spendsats != NULL && scid != NULL && dir != NULL);

			json_to_bool(buffer, connected, &h.enabled);
			json_to_short_channel_id(buffer, scid, &h.scid.scid);
			json_to_int(buffer, dir, &h.scid.dir);

			json_to_msat(buffer, spendsats, &h.estimated_capacity);
			tal_arr_expand(&p->channel_hints, h);
		}
	}

done:
	payment_continue(p);
	return command_still_pending(cmd);
}

static void local_channel_hints_cb(void *d UNUSED, struct payment *p)
{
	struct out_req *req;
	/* If we are not the root we don't look up the channel balances since
	 * it is unlikely that the capacities have changed much since the root
	 * payment looked at them. We also only call `listpeers` when the
	 * payment is in state PAYMENT_STEP_INITIALIZED, right before calling
	 * `getroute`. */
	if (p->parent != NULL || p->step != PAYMENT_STEP_INITIALIZED)
		return payment_continue(p);

	req = jsonrpc_request_start(p->plugin, NULL, "listpeers",
				    local_channel_hints_listpeers,
				    local_channel_hints_listpeers, p);
	send_outreq(p->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(local_channel_hints, void *, NULL, local_channel_hints_cb);
