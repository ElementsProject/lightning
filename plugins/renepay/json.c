#include "config.h"
#include <common/json_stream.h>
#include <common/onionreply.h>
#include <common/sphinx.h>
#include <plugins/renepay/json.h>

/* See if this notification is about one of our flows. */
struct routekey *tal_routekey_from_json(const tal_t *ctx, const char *buf,
					const jsmntok_t *obj)
{
	struct routekey *key = tal(ctx, struct routekey);

	const jsmntok_t *hashtok = json_get_member(buf, obj, "payment_hash");
	const jsmntok_t *groupidtok = json_get_member(buf, obj, "groupid");
	const jsmntok_t *partidtok = json_get_member(buf, obj, "partid");

	if (hashtok == NULL || groupidtok == NULL)
		goto fail;

	if (!json_to_u64(buf, groupidtok, &key->groupid))
		goto fail;
	if (!json_to_sha256(buf, hashtok, &key->payment_hash))
		goto fail;
	if (partidtok == NULL)
		key->partid = 0;
	else if (!json_to_u64(buf, partidtok, &key->partid))
		goto fail;

	return key;
fail:

	return tal_free(key);
}

struct route *tal_route_from_json(const tal_t *ctx, const char *buf,
				  const jsmntok_t *obj)
{
	struct route *route = tal(ctx, struct route);

	const jsmntok_t *hashtok = json_get_member(buf, obj, "payment_hash");
	const jsmntok_t *groupidtok = json_get_member(buf, obj, "groupid");
	const jsmntok_t *partidtok = json_get_member(buf, obj, "partid");
	const jsmntok_t *amttok = json_get_member(buf, obj, "amount_msat");
	const jsmntok_t *senttok =
	    json_get_member(buf, obj, "amount_sent_msat");

	if (hashtok == NULL || groupidtok == NULL || amttok == NULL ||
	    senttok == NULL)
		goto fail;

	if (!json_to_u64(buf, groupidtok, &route->key.groupid))
		goto fail;
	if (!json_to_sha256(buf, hashtok, &route->key.payment_hash))
		goto fail;
	if (!json_to_msat(buf, amttok, &route->amount_deliver))
		goto fail;
	if (!json_to_msat(buf, senttok, &route->amount_sent))
		goto fail;
	if (partidtok == NULL)
		route->key.partid = 0;
	else if (!json_to_u64(buf, partidtok, &route->key.partid))
		goto fail;

	route->success_prob = 0;
	route->result = NULL;
	route->hops = NULL;
	route->final_msg = NULL;
	route->final_error = LIGHTNINGD;
	route->shared_secrets = NULL;

	return route;
fail:

	return tal_free(route);
}

static bool get_data_details_onionreply(struct payment_result *result,
					const char *buffer,
					const jsmntok_t *datatok,
					struct secret *shared_secrets)
{
	const tal_t *this_ctx = tal(result, tal_t);
	const jsmntok_t *onionreplytok;
	struct onionreply *onionreply, *wonionreply;
	const u8 *replymsg;
	int index;

	onionreplytok = json_get_member(buffer, datatok, "onionreply");
	if (!onionreplytok || !shared_secrets)
		goto fail;
	onionreply = new_onionreply(
	    this_ctx,
	    take(json_tok_bin_from_hex(this_ctx, buffer, onionreplytok)));
	assert(onionreply);
	/* FIXME: It seems that lightningd will unwrap top portion of the
	 * onionreply for us before serializing it, while unwrap_onionreply will
	 * try to do the entire unwraping. It would be a better API if either
	 * lightningd unwraps the entire thing or it doesn't do any unwraping.
	 * Also it wouldn't hurt if injectpaymentonion accepted the shared
	 * secrets to allow lightningd do the decoding for us. */
	wonionreply = wrap_onionreply(this_ctx, &shared_secrets[0], onionreply);
	replymsg = unwrap_onionreply(this_ctx, shared_secrets,
				     tal_count(shared_secrets),
				     wonionreply, &index);
	if (replymsg) {
		result->failcode = tal(result, enum onion_wire);
		*result->failcode = fromwire_peektype(replymsg);

		result->erring_index = tal(result, u32);
		*result->erring_index = index;
	}
	tal_free(this_ctx);
	return true;
fail:
	tal_free(this_ctx);
	return false;
}

static bool get_data_details(struct payment_result *result,
			     const char *buffer,
			     const jsmntok_t *datatok)
{

	const jsmntok_t *erridxtok, *failcodetok, *errnodetok, *errchantok,
	    *errdirtok, *rawmsgtok, *failcodenametok;
	erridxtok = json_get_member(buffer, datatok, "erring_index");
	failcodetok = json_get_member(buffer, datatok, "failcode");

	if (!erridxtok || !failcodetok)
		return false;
	result->failcode = tal(result, enum onion_wire);
	json_to_u32(buffer, failcodetok, result->failcode);

	result->erring_index = tal(result, u32);
	json_to_u32(buffer, erridxtok, result->erring_index);

	// search for other fields
	errnodetok = json_get_member(buffer, datatok, "erring_node");
	errchantok = json_get_member(buffer, datatok, "erring_channel");
	errdirtok = json_get_member(buffer, datatok, "erring_direction");
	failcodenametok = json_get_member(buffer, datatok, "failcodename");
	rawmsgtok = json_get_member(buffer, datatok, "raw_message");

	if (errnodetok != NULL) {
		result->erring_node = tal(result, struct node_id);
		json_to_node_id(buffer, errnodetok, result->erring_node);
	}

	if (errchantok != NULL) {
		result->erring_channel = tal(result, struct short_channel_id);
		json_to_short_channel_id(buffer, errchantok,
					 result->erring_channel);
	}
	if (errdirtok != NULL) {
		result->erring_direction = tal(result, int);
		json_to_int(buffer, errdirtok, result->erring_direction);
	}
	if (rawmsgtok != NULL)
		result->raw_message =
		    json_tok_bin_from_hex(result, buffer, rawmsgtok);

	if (failcodenametok != NULL)
		result->failcodename =
		    json_strdup(result, buffer, failcodenametok);

	return true;
}

struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buffer,
						    const jsmntok_t *toks,
						    struct secret *shared_secrets)
{
	const jsmntok_t *idtok = json_get_member(buffer, toks, "created_index");
	const jsmntok_t *hashtok =
	    json_get_member(buffer, toks, "payment_hash");
	const jsmntok_t *senttok =
	    json_get_member(buffer, toks, "amount_sent_msat");
	const jsmntok_t *statustok = json_get_member(buffer, toks, "status");
	const jsmntok_t *preimagetok =
	    json_get_member(buffer, toks, "payment_preimage");
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	const jsmntok_t *msgtok = json_get_member(buffer, toks, "message");
	const jsmntok_t *datatok = json_get_member(buffer, toks, "data");
	struct payment_result *result;

	/* Check if we have an error and need to descend into data to get
	 * details. */
	if (codetok != NULL && datatok != NULL) {
		idtok = json_get_member(buffer, datatok, "create_index");
		hashtok = json_get_member(buffer, datatok, "payment_hash");
		senttok = json_get_member(buffer, datatok, "amount_sent_msat");
		statustok = json_get_member(buffer, datatok, "status");
	}

	/* Initial sanity checks, all these fields must exist. */
	if (hashtok == NULL || hashtok->type != JSMN_STRING ||
	    senttok == NULL || statustok == NULL ||
	    statustok->type != JSMN_STRING) {
		return NULL;
	}

	result = tal(ctx, struct payment_result);
	memset(result, 0, sizeof(struct payment_result));

	if (msgtok)
		result->message = json_strdup(result, buffer, msgtok);
	else
		result->message = NULL;

	if (codetok != NULL)
		// u32? isn't this an int?
		// json_to_u32(buffer, codetok, &result->code);
		json_to_int(buffer, codetok, &result->code);
	else
		result->code = 0;

	if (idtok) {
		result->created_index = tal(result, u64);
		json_to_u64(buffer, idtok, result->created_index);
	} else
		result->created_index = NULL;

	json_to_msat(buffer, senttok, &result->amount_sent);
	if (json_tok_streq(buffer, statustok, "pending")) {
		result->status = SENDPAY_PENDING;
	} else if (json_tok_streq(buffer, statustok, "complete")) {
		result->status = SENDPAY_COMPLETE;
	} else if (json_tok_streq(buffer, statustok, "failed")) {
		result->status = SENDPAY_FAILED;
	} else {
		goto fail;
	}

	if (preimagetok != NULL) {
		result->payment_preimage = tal(result, struct preimage);
		json_to_preimage(buffer, preimagetok, result->payment_preimage);
	}

	/* Now extract the error details if the error code is not 0 */
	if (result->code != 0 && datatok) {
		/* try one, then try the other, then fail */
		if (!get_data_details(result, buffer, datatok) &&
		    !get_data_details_onionreply(result, buffer, datatok,
						 shared_secrets))
			goto fail;
	}
	return result;
fail:
	return tal_free(result);
}

// TODO add verbose option to include more or less details or change the schema,
// checkout docs/schema/renepay.schema.json and
// docs/schema/renepaystatus.schema.json
void json_add_payment(struct json_stream *s, const struct payment *payment)
{
	assert(s);
	assert(payment);
	const struct payment_info *pinfo = &payment->payment_info;

	if (pinfo->label != NULL)
		json_add_string(s, "label", pinfo->label);
	if (pinfo->invstr != NULL)
		json_add_invstring(s, pinfo->invstr);

	json_add_amount_msat(s, "amount_msat", pinfo->amount);
	json_add_sha256(s, "payment_hash", &pinfo->payment_hash);
	json_add_node_id(s, "destination", &pinfo->destination);

	/* FIXME: we have not declared "description" in renepay's response
	 * schema
	if (pinfo->description)
		json_add_string(s, "description", pinfo->description);
	*/

	json_add_timeabs(s, "created_at", pinfo->start_time);
	json_add_u64(s, "groupid", payment->groupid);
	json_add_u64(s, "parts", payment->next_partid);

	switch (payment->status) {
	case PAYMENT_SUCCESS:
		assert(payment->preimage);

		json_add_string(s, "status", "complete");
		json_add_preimage(s, "payment_preimage", payment->preimage);
		json_add_amount_msat(s, "amount_sent_msat",
				     payment->total_sent);
		break;
	case PAYMENT_FAIL:
		json_add_string(s, "status", "failed");
		break;
	case PAYMENT_PENDING:
		json_add_string(s, "status", "pending");
		break;
	}

	// FIXME: add more verbose outputs?
	// json_array_start(s, "notes");
	// for (size_t i = 0; i < tal_count(payment->paynotes); i++)
	// 	json_add_string(s, NULL, payment->paynotes[i]);
	// json_array_end(s);

	// TODO(eduardo): maybe we should add also:
	// - payment_secret?
	// - payment_metadata?
	// - number of parts?
}

void json_add_route(struct json_stream *js, const struct route *route,
		    const struct payment *payment)
{
	assert(js);
	assert(route);
	assert(payment);

	const struct payment_info *pinfo = &payment->payment_info;

	assert(route->hops);
	const size_t pathlen = tal_count(route->hops);

	json_array_start(js, "route");
	/* An empty route means a payment to oneself, pathlen=0 */
	for (size_t j = 0; j < pathlen; j++) {
		const struct route_hop *hop = &route->hops[j];

		json_object_start(js, NULL);
		json_add_node_id(js, "id", &hop->node_id);
		json_add_short_channel_id(js, "channel", hop->scid);
		json_add_amount_msat(js, "amount_msat", hop->amount);
		json_add_num(js, "direction", hop->direction);
		json_add_u32(js, "delay", hop->delay);
		json_add_string(js, "style", "tlv");
		json_object_end(js);
	}
	json_array_end(js);
	json_add_sha256(js, "payment_hash", &pinfo->payment_hash);

	if (pinfo->payment_secret)
		json_add_secret(js, "payment_secret", pinfo->payment_secret);

	/* FIXME: sendpay has a check that we don't total more than
	 * the exact amount, if we're setting partid (i.e. MPP).
	 * However, we always set partid, and we add a shadow amount if
	 * we've only have one part, so we have to use that amount
	 * here.
	 *
	 * The spec was loosened so you are actually allowed
	 * to overpay, so this check is now overzealous. */
	if (pathlen > 0 &&
	    amount_msat_greater(route_delivers(route), pinfo->amount)) {
		json_add_amount_msat(js, "amount_msat", route_delivers(route));
	} else {
		json_add_amount_msat(js, "amount_msat", pinfo->amount);
	}
	json_add_u64(js, "partid", route->key.partid);
	json_add_u64(js, "groupid", route->key.groupid);

	/* FIXME: some of these fields might not be required for all
	 * payment parts. */
	json_add_string(js, "bolt11", pinfo->invstr);

	if (pinfo->payment_metadata)
		json_add_hex_talarr(js, "payment_metadata",
				    pinfo->payment_metadata);
	if (pinfo->label)
		json_add_string(js, "label", pinfo->label);
	if (pinfo->description)
		json_add_string(js, "description", pinfo->description);

}

void json_myadd_blinded_path(struct json_stream *s,
			     const char *fieldname,
			     const struct blinded_path *blinded_path)
{
	// FIXME: how can we support the case when the entry point is a
	// scid?
	assert(blinded_path->first_node_id.is_pubkey);
	json_object_start(s, fieldname);
	json_add_pubkey(s, "first_node_id",
			&blinded_path->first_node_id.pubkey);
	json_add_pubkey(s, "first_path_key", &blinded_path->first_path_key);
	json_array_start(s, "path");
	for (size_t i = 0; i < tal_count(blinded_path->path); i++) {
		const struct blinded_path_hop *hop = blinded_path->path[i];
		json_object_start(s, NULL);
		json_add_pubkey(s, "blinded_node_id", &hop->blinded_node_id);
		json_add_hex_talarr(s, "encrypted_recipient_data",
				    hop->encrypted_recipient_data);
		json_object_end(s);
	}
	json_array_end(s);
	json_object_end(s);
}
