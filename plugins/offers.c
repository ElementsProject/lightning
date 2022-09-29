/* This plugin covers both sending and receiving offers */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/rune/rune.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bolt11.h>
#include <common/bolt11_json.h>
#include <common/bolt12_merkle.h>
#include <common/iso4217.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/offers.h>
#include <plugins/offers_inv_hook.h>
#include <plugins/offers_invreq_hook.h>
#include <plugins/offers_offer.h>

struct point32 id;
u16 cltv_final;
bool offers_enabled;

static struct command_result *finished(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       void *unused)
{
	return command_hook_success(cmd);
}

static struct command_result *sendonionmessage_error(struct command *cmd,
						     const char *buf,
						     const jsmntok_t *err,
						     void *unused)
{
	/* This can happen if the peer goes offline or wasn't directly
	 * connected: "Unknown first peer" */
	plugin_log(cmd->plugin, LOG_DBG,
		   "sendonionmessage gave JSON error: %.*s",
		   json_tok_full_len(err),
		   json_tok_full(buf, err));
	return command_hook_success(cmd);
}

struct command_result *
send_onion_reply(struct command *cmd,
		 struct tlv_onionmsg_payload_reply_path *reply_path,
		 struct tlv_onionmsg_payload *payload)
{
	struct out_req *req;
	size_t nhops;

	req = jsonrpc_request_start(cmd->plugin, cmd, "sendonionmessage",
				    finished, sendonionmessage_error, NULL);

	json_add_pubkey(req->js, "first_id", &reply_path->first_node_id);
	json_add_pubkey(req->js, "blinding", &reply_path->blinding);
	json_array_start(req->js, "hops");

	nhops = tal_count(reply_path->path);
	for (size_t i = 0; i < nhops; i++) {
		struct tlv_onionmsg_payload *omp;
		u8 *tlv;

		json_object_start(req->js, NULL);
		json_add_pubkey(req->js, "id", &reply_path->path[i]->node_id);

		/* Put payload in last hop. */
		if (i == nhops - 1)
			omp = payload;
		else
			omp = tlv_onionmsg_payload_new(tmpctx);

		omp->encrypted_data_tlv = reply_path->path[i]->encrypted_recipient_data;

		tlv = tal_arr(tmpctx, u8, 0);
		towire_tlv_onionmsg_payload(&tlv, omp);
		json_add_hex_talarr(req->js, "tlv", tlv);
		json_object_end(req->js);
	}
	json_array_end(req->js);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *onion_message_modern_call(struct command *cmd,
							const char *buf,
							const jsmntok_t *params)
{
	const jsmntok_t *om, *replytok, *invreqtok, *invtok;
	struct tlv_onionmsg_payload_reply_path *reply_path = NULL;

	if (!offers_enabled)
		return command_hook_success(cmd);

	om = json_get_member(buf, params, "onion_message");
	replytok = json_get_member(buf, om, "reply_blindedpath");
	if (replytok) {
		reply_path = json_to_reply_path(cmd, buf, replytok);
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
						      reply_path);
		else
			plugin_log(cmd->plugin, LOG_DBG,
				   "invoice_request without reply_path");
	}

	invtok = json_get_member(buf, om, "invoice");
	if (invtok) {
		const u8 *invbin = json_tok_bin_from_hex(tmpctx, buf, invtok);
		if (invbin)
			return handle_invoice(cmd, invbin, reply_path);
	}

	return command_hook_success(cmd);
}

static const struct plugin_hook hooks[] = {
	{
		"onion_message_blinded",
		onion_message_modern_call
	},
};

struct decodable {
	const char *type;
	struct bolt11 *b11;
	struct tlv_offer *offer;
	struct tlv_invoice *invoice;
	struct tlv_invoice_request *invreq;
	struct rune *rune;
};

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
			    const struct bitcoin_blkid *chains)
{
	json_array_start(js, "chains");
	for (size_t i = 0; i < tal_count(chains); i++)
		json_add_sha256(js, NULL, &chains[i].shad.sha);
	json_array_end(js);
}

static void json_add_onionmsg_path(struct json_stream *js,
				   const char *fieldname,
				   const struct onionmsg_path *path,
				   const struct blinded_payinfo *payinfo)
{
	json_object_start(js, fieldname);
	json_add_pubkey(js, "node_id", &path->node_id);
	json_add_hex_talarr(js, "encrypted_recipient_data", path->encrypted_recipient_data);
	if (payinfo) {
		json_add_u32(js, "fee_base_msat", payinfo->fee_base_msat);
		json_add_u32(js, "fee_proportional_millionths",
			     payinfo->fee_proportional_millionths);
		json_add_u32(js, "cltv_expiry_delta",
			     payinfo->cltv_expiry_delta);
		json_add_hex_talarr(js, "features", payinfo->features);
	}
	json_object_end(js);
}

/* Returns true if valid */
static bool json_add_blinded_paths(struct json_stream *js,
				   struct blinded_path **paths,
				   struct blinded_payinfo **blindedpay)
{
	size_t n = 0;
	json_array_start(js, "paths");
	for (size_t i = 0; i < tal_count(paths); i++) {
		json_object_start(js, NULL);
		json_add_pubkey(js, "blinding", &paths[i]->blinding);
		json_array_start(js, "path");
		for (size_t j = 0; j < tal_count(paths[i]->path); j++) {
			json_add_onionmsg_path(js, NULL, paths[i]->path[j],
					       n < tal_count(blindedpay)
					       ? blindedpay[n] : NULL);
			n++;
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `blinded_payinfo` does not contain
	 *   exactly as many `payinfo` as total `onionmsg_path` in
	 *   `blinded_path`.
	 */
	if (blindedpay && n != tal_count(blindedpay)) {
		json_add_string(js, "warning_invoice_invalid_blinded_payinfo",
				"invoice does not have correct number of blinded_payinfo");
		return false;
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

static void json_add_offer(struct json_stream *js, const struct tlv_offer *offer)
{
	struct sha256 offer_id;
	bool valid = true;

	merkle_tlv(offer->fields, &offer_id);
	json_add_sha256(js, "offer_id", &offer_id);
	if (offer->chains)
		json_add_chains(js, offer->chains);
	if (offer->currency) {
		const struct iso4217_name_and_divisor *iso4217;
		json_add_stringn(js, "currency",
				 offer->currency, tal_bytelen(offer->currency));
		if (offer->amount)
			json_add_u64(js, "amount", *offer->amount);
		iso4217 = find_iso4217(offer->currency,
				       tal_bytelen(offer->currency));
		if (iso4217)
			json_add_num(js, "minor_unit", iso4217->minor_unit);
		else
			json_add_string(js, "warning_offer_unknown_currency",
					"unknown currency code");
	} else if (offer->amount)
		json_add_amount_msat_only(js, "amount_msat",
					  amount_msat(*offer->amount));
	if (offer->send_invoice)
		json_add_bool(js, "send_invoice", true);
	if (offer->refund_for)
		json_add_sha256(js, "refund_for", offer->refund_for);

	/* BOLT-offers #12:
	 * A reader of an offer:
	 *...
	 *  - if `node_id` or `description` is not set:
	 *    - MUST NOT respond to the offer.
	 */
	if (offer->description)
		json_add_stringn(js, "description",
				 offer->description,
				 tal_bytelen(offer->description));
	else {
		json_add_string(js, "warning_offer_missing_description",
				"offers without a description are invalid");
		valid = false;
	}

	if (offer->issuer)
		json_add_stringn(js, "issuer", offer->issuer,
				 tal_bytelen(offer->issuer));
	if (offer->features)
		json_add_hex_talarr(js, "features", offer->features);
	if (offer->absolute_expiry)
		json_add_u64(js, "absolute_expiry",
			     *offer->absolute_expiry);
	if (offer->paths)
		valid &= json_add_blinded_paths(js, offer->paths, NULL);

	if (offer->quantity_min)
		json_add_u64(js, "quantity_min", *offer->quantity_min);
	if (offer->quantity_max)
		json_add_u64(js, "quantity_max", *offer->quantity_max);
	if (offer->recurrence) {
		const char *name;
		json_object_start(js, "recurrence");
		json_add_num(js, "time_unit", offer->recurrence->time_unit);
		name = recurrence_time_unit_name(offer->recurrence->time_unit);
		if (name)
			json_add_string(js, "time_unit_name", name);
		json_add_num(js, "period", offer->recurrence->period);
		if (offer->recurrence_base) {
			json_add_u64(js, "basetime",
				     offer->recurrence_base->basetime);
			if (offer->recurrence_base->start_any_period)
				json_add_bool(js, "start_any_period", true);
		}
		if (offer->recurrence_limit)
			json_add_u32(js, "limit", *offer->recurrence_limit);
		if (offer->recurrence_paywindow) {
			json_object_start(js, "paywindow");
			json_add_u32(js, "seconds_before",
				     offer->recurrence_paywindow->seconds_before);
			json_add_u32(js, "seconds_after",
				     offer->recurrence_paywindow->seconds_after);
			if (offer->recurrence_paywindow->proportional_amount)
				json_add_bool(js, "proportional_amount", true);
			json_object_end(js);
		}
		json_object_end(js);
	}

	if (offer->node_id)
		json_add_point32(js, "node_id", offer->node_id);
	else
		valid = false;

	/* If it's present, offer_decode checked it was valid */
	if (offer->signature)
		json_add_bip340sig(js, "signature", offer->signature);

	json_add_bool(js, "valid", valid);
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
			"warning_invoice_fallbacks_address_invalid",
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

	json_array_start(js, "fallbacks");
	for (size_t i = 0; i < tal_count(fallbacks); i++) {
		size_t addrlen = tal_bytelen(fallbacks[i]->address);

		json_object_start(js, NULL);
		json_add_u32(js, "version", fallbacks[i]->version);
		json_add_hex_talarr(js, "hex", fallbacks[i]->address);

		/* BOLT-offers #12:
		 * - for the bitcoin chain, if the invoice specifies `fallbacks`:
		 *   - MUST ignore any `fallback_address` for which `version` is
		 *     greater than 16.
		 * -  MUST ignore any `fallback_address` for which `address` is
		 *    less than 2 or greater than 40 bytes.
		 * - MUST ignore any `fallback_address` for which `address` does
		 *   not meet known requirements for the given `version`
		 */
		if (fallbacks[i]->version > 16) {
			json_add_string(js,
					"warning_invoice_fallbacks_version_invalid",
					"invoice fallback version > 16");
			valid = false;
		} else if (addrlen < 2 || addrlen > 40) {
			json_add_string(js,
					"warning_invoice_fallbacks_address_invalid",
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

static void json_add_b12_invoice(struct json_stream *js,
				 const struct tlv_invoice *invoice)
{
	bool valid = true;

	if (invoice->chain)
		json_add_sha256(js, "chain", &invoice->chain->shad.sha);
	if (invoice->offer_id)
		json_add_sha256(js, "offer_id", invoice->offer_id);

	/* BOLT-offers #12:
	 *   - MUST reject the invoice if `msat` is not present.
	 */
	if (invoice->amount)
		json_add_amount_msat_only(js, "amount_msat",
					  amount_msat(*invoice->amount));
	else {
		json_add_string(js, "warning_invoice_missing_amount",
				"invoices without an amount are invalid");
		valid = false;
	}

	/* BOLT-offers #12:
	 *  - MUST reject the invoice if `description` is not present.
	 */
	if (invoice->description)
		json_add_stringn(js, "description", invoice->description,
				 tal_bytelen(invoice->description));
	else {
		json_add_string(js, "warning_invoice_missing_description",
				"invoices without a description are invalid");
		valid = false;
	}

	if (invoice->issuer)
		json_add_stringn(js, "issuer", invoice->issuer,
				 tal_bytelen(invoice->issuer));
	if (invoice->features)
		json_add_hex_talarr(js, "features", invoice->features);
	if (invoice->paths) {
		/* BOLT-offers #12:
		 * - if `blinded_path` is present:
		 *   - MUST reject the invoice if `blinded_payinfo` is not
		 *     present.
		 *   - MUST reject the invoice if `blinded_payinfo` does not
		 *     contain exactly as many `payinfo` as total `onionmsg_path`
		 *     in `blinded_path`.
		 */
		if (!invoice->blindedpay) {
			json_add_string(js, "warning_invoice_missing_blinded_payinfo",
					"invoices with blinded_path without blinded_payinfo are invalid");
			valid = false;
		}
		valid &= json_add_blinded_paths(js, invoice->paths, invoice->blindedpay);
	}
	if (invoice->quantity)
		json_add_u64(js, "quantity", *invoice->quantity);
	if (invoice->send_invoice)
		json_add_bool(js, "send_invoice", true);
	if (invoice->refund_for)
		json_add_sha256(js, "refund_for", invoice->refund_for);
	if (invoice->recurrence_counter) {
		json_add_u32(js, "recurrence_counter",
			     *invoice->recurrence_counter);
		if (invoice->recurrence_start)
			json_add_u32(js, "recurrence_start",
				     *invoice->recurrence_start);
		/* BOLT-offers-recurrence #12:
		 * - if the offer contained `recurrence`:
		 *   - MUST reject the invoice if `recurrence_basetime` is not
		 *     set.
		 */
		if (invoice->recurrence_basetime)
			json_add_u64(js, "recurrence_basetime",
				     *invoice->recurrence_basetime);
		else {
			json_add_string(js, "warning_invoice_missing_recurrence_basetime",
					"recurring invoices without a recurrence_basetime are invalid");
			valid = false;
		}
	}

	if (invoice->payer_key)
		json_add_point32(js, "payer_key", invoice->payer_key);
	if (invoice->payer_info)
		json_add_hex_talarr(js, "payer_info", invoice->payer_info);
	if (invoice->payer_note)
		json_add_stringn(js, "payer_note", invoice->payer_note,
				 tal_bytelen(invoice->payer_note));

	/* BOLT-offers #12:
	 *   - MUST reject the invoice if `created_at` is not present.
	 */
	if (invoice->created_at) {
		json_add_u64(js, "created_at", *invoice->created_at);
	} else {
		json_add_string(js, "warning_invoice_missing_created_at",
				"invoices without created_at are invalid");
		valid = false;
	}

	/* BOLT-offers #12:
	 *   - MUST reject the invoice if `payment_hash` is not present.
	 */
	if (invoice->payment_hash)
		json_add_sha256(js, "payment_hash", invoice->payment_hash);
	else {
		json_add_string(js, "warning_invoice_missing_payment_hash",
				"invoices without a payment_hash are invalid");
		valid = false;
	}

	/* BOLT-offers #12:
	 *
	 * - if the expiry for accepting payment is not 7200 seconds after
	 *   `created_at`:
	 *      - MUST set `relative_expiry`
	 */
	if (invoice->relative_expiry)
		json_add_u32(js, "relative_expiry", *invoice->relative_expiry);
	else
		json_add_u32(js, "relative_expiry", 7200);

	/* BOLT-offers #12:
	 * - if the `min_final_cltv_expiry` for the last HTLC in the route is
	 *   not 18:
	 *   - MUST set `min_final_cltv_expiry`.
	 */
	if (invoice->cltv)
		json_add_u32(js, "min_final_cltv_expiry", *invoice->cltv);
	else
		json_add_u32(js, "min_final_cltv_expiry", 18);

	if (invoice->fallbacks)
		valid &= json_add_fallbacks(js,
					    invoice->chain,
					    invoice->fallbacks);

	/* BOLT-offers #12:
	 * - if the offer contained `refund_for`:
	 *   - MUST reject the invoice if `payer_key` does not match the invoice
	 *     whose `payment_hash` is equal to `refund_for`
	 *    `refunded_payment_hash`
	 *   - MUST reject the invoice if `refund_signature` is not set.
	 *   - MUST reject the invoice if `refund_signature` is not a valid
	 *     signature using `payer_key` as described in
	 *     [Signature Calculation](#signature-calculation).
	 */
	if (invoice->refund_signature) {
		json_add_bip340sig(js, "refund_signature",
				   invoice->refund_signature);
		if (!invoice->payer_key) {
			json_add_string(js, "warning_invoice_refund_signature_missing_payer_key",
					"Can't have refund_signature without payer key");
			valid = false;
		} else if (!bolt12_check_signature(invoice->fields,
						   "invoice",
						   "refund_signature",
						   invoice->payer_key,
						   invoice->refund_signature)) {
			json_add_string(js, "warning_invoice_refund_signature_invalid",
					"refund_signature does not match");
			valid = false;
		}
	} else if (invoice->refund_for) {
		json_add_string(js, "warning_invoice_refund_missing_signature",
				"refund_for requires refund_signature");
		valid = false;
	}

	/* invoice_decode checked these */
	json_add_point32(js, "node_id", invoice->node_id);
	json_add_bip340sig(js, "signature", invoice->signature);

	json_add_bool(js, "valid", valid);
}

static void json_add_invoice_request(struct json_stream *js,
				     const struct tlv_invoice_request *invreq)
{
	bool valid = true;

	if (invreq->chain)
		json_add_sha256(js, "chain", &invreq->chain->shad.sha);

	/* BOLT-offers #12:
	 * - MUST fail the request if `payer_key` is not present.
	 *...
	 * - MUST fail the request if `features` contains unknown even bits.
	 * - MUST fail the request if `offer_id` is not present.
	 */
	if (invreq->offer_id)
		json_add_sha256(js, "offer_id", invreq->offer_id);
	else {
		json_add_string(js, "warning_invoice_request_missing_offer_id",
				"invoice_request requires offer_id");
		valid = false;
	}
	if (invreq->amount)
		json_add_amount_msat_only(js, "amount_msat",
					  amount_msat(*invreq->amount));
	if (invreq->features)
		json_add_hex_talarr(js, "features", invreq->features);
	if (invreq->quantity)
		json_add_u64(js, "quantity", *invreq->quantity);

	if (invreq->recurrence_counter)
		json_add_u32(js, "recurrence_counter",
			     *invreq->recurrence_counter);
	if (invreq->recurrence_start)
		json_add_u32(js, "recurrence_start",
			     *invreq->recurrence_start);
	if (invreq->payer_key)
		json_add_point32(js, "payer_key", invreq->payer_key);
	else {
		json_add_string(js, "warning_invoice_request_missing_payer_key",
				"invoice_request requires payer_key");
		valid = false;
	}
	if (invreq->payer_info)
		json_add_hex_talarr(js, "payer_info", invreq->payer_info);
	if (invreq->payer_note)
		json_add_stringn(js, "payer_note", invreq->payer_note,
				 tal_bytelen(invreq->payer_note));

	/* BOLT-offers #12:
	 *  - MUST fail the request if there is no `signature` field.
	 *  - MUST fail the request if `signature` is not correct.
	 */
	if (invreq->signature) {
		if (invreq->payer_key
		    && !bolt12_check_signature(invreq->fields,
					       "invoice_request",
					       "signature",
					       invreq->payer_key,
					       invreq->signature)) {
			json_add_string(js, "warning_invoice_request_invalid_signature",
					"Bad signature");
			valid = false;
		}
	} else {
		json_add_string(js, "warning_invoice_request_missing_signature",
				"Missing signature");
		valid = false;
	}

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
		json_add_offer(response, decodable->offer);
	if (decodable->invreq)
		json_add_invoice_request(response, decodable->invreq);
	if (decodable->invoice)
		json_add_b12_invoice(response, decodable->invoice);
	if (decodable->b11) {
		/* The bolt11 decoder simply refuses to decode bad invs. */
		json_add_bolt11(response, decodable->b11);
		json_add_bool(response, "valid", true);
	}
	if (decodable->rune)
		json_add_rune(cmd, response, decodable->rune);
	return command_finished(cmd, response);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct pubkey k;

	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_pubkey, &k));
	if (secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &id.pubkey,
					       NULL, &k.pubkey) != 1)
		abort();

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{cltv-final:%,experimental-offers:%}",
		 JSON_SCAN(json_to_u16, &cltv_final),
		 JSON_SCAN(json_to_bool, &offers_enabled));

	return NULL;
}

static const struct plugin_command commands[] = {
    {
	    "offer",
	    "payment",
	    "Create an offer to accept money",
            "Create an offer for invoices of {amount} with {description}, optional {issuer}, internal {label}, {quantity_min}, {quantity_max}, {absolute_expiry}, {recurrence}, {recurrence_base}, {recurrence_paywindow}, {recurrence_limit} and {single_use}",
            json_offer
    },
    {
	    "offerout",
	    "payment",
	    "Create an offer to send money",
            "Create an offer to pay invoices of {amount} with {description}, optional {issuer}, internal {label}, {absolute_expiry} and {refund_for}",
            json_offerout
    },
    {
	    "decode",
	    "utility",
	    "Decode {string} message, returning {type} and information.",
	    NULL,
	    json_decode,
    },
};

int main(int argc, char *argv[])
{
	setup_locale();

	/* We deal in UTC; mktime() uses local time */
	setenv("TZ", "", 1);
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, hooks, ARRAY_SIZE(hooks),
		    NULL, 0, NULL);
}
