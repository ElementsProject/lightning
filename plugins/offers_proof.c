#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/bolt12.h>
#include <common/bolt12_proof.h>
#include <common/json_param.h>
#include <common/json_parse_simple.h>
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <common/utils.h>
#include <plugins/libplugin.h>
#include <plugins/offers.h>
#include <plugins/offers_proof.h>

/* Default field types to include (in addition to mandatory ones). */
static const bigsize_t default_extras[] = {
	TLV_INVOICE_OFFER_DESCRIPTION,
	TLV_INVOICE_OFFER_ISSUER_ID,
	TLV_INVOICE_INVOICE_CREATED_AT,
	TLV_INVOICE_INVOICE_AMOUNT,
};

/* Mandatory field types (always included). */
static const bigsize_t mandatory_types[] = {
	TLV_INVOICE_INVREQ_PAYER_ID,
	TLV_INVOICE_INVOICE_PAYMENT_HASH,
	TLV_INVOICE_INVOICE_FEATURES,
	TLV_INVOICE_INVOICE_NODE_ID,
};

/* Name-to-number mapping for all known bolt12 invoice fields. */
static const struct {
	const char *name;
	bigsize_t num;
} field_names[] = {
	{ "offer_chains",            TLV_INVOICE_OFFER_CHAINS },
	{ "offer_metadata",          TLV_INVOICE_OFFER_METADATA },
	{ "offer_currency",          TLV_INVOICE_OFFER_CURRENCY },
	{ "offer_amount",            TLV_INVOICE_OFFER_AMOUNT },
	{ "offer_description",       TLV_INVOICE_OFFER_DESCRIPTION },
	{ "offer_features",          TLV_INVOICE_OFFER_FEATURES },
	{ "offer_absolute_expiry",   TLV_INVOICE_OFFER_ABSOLUTE_EXPIRY },
	{ "offer_paths",             TLV_INVOICE_OFFER_PATHS },
	{ "offer_issuer",            TLV_INVOICE_OFFER_ISSUER },
	{ "offer_quantity_max",      TLV_INVOICE_OFFER_QUANTITY_MAX },
	{ "offer_issuer_id",         TLV_INVOICE_OFFER_ISSUER_ID },
	{ "invreq_chain",            TLV_INVOICE_INVREQ_CHAIN },
	{ "invreq_amount",           TLV_INVOICE_INVREQ_AMOUNT },
	{ "invreq_features",         TLV_INVOICE_INVREQ_FEATURES },
	{ "invreq_quantity",         TLV_INVOICE_INVREQ_QUANTITY },
	{ "invreq_payer_id",         TLV_INVOICE_INVREQ_PAYER_ID },
	{ "invreq_payer_note",       TLV_INVOICE_INVREQ_PAYER_NOTE },
	{ "invreq_paths",            TLV_INVOICE_INVREQ_PATHS },
	{ "invreq_bip_353_name",     TLV_INVOICE_INVREQ_BIP_353_NAME },
	{ "invoice_paths",           TLV_INVOICE_INVOICE_PATHS },
	{ "invoice_blindedpay",      TLV_INVOICE_INVOICE_BLINDEDPAY },
	{ "invoice_created_at",      TLV_INVOICE_INVOICE_CREATED_AT },
	{ "invoice_relative_expiry", TLV_INVOICE_INVOICE_RELATIVE_EXPIRY },
	{ "invoice_payment_hash",    TLV_INVOICE_INVOICE_PAYMENT_HASH },
	{ "invoice_amount",          TLV_INVOICE_INVOICE_AMOUNT },
	{ "invoice_fallbacks",       TLV_INVOICE_INVOICE_FALLBACKS },
	{ "invoice_features",        TLV_INVOICE_INVOICE_FEATURES },
	{ "invoice_node_id",         TLV_INVOICE_INVOICE_NODE_ID },
	{ "signature",               TLV_INVOICE_SIGNATURE },
};

/* Returns name for a TLV type, or NULL if unknown. */
static const char *tlv_type_name(bigsize_t num)
{
	for (size_t i = 0; i < ARRAY_SIZE(field_names); i++) {
		if (field_names[i].num == num)
			return field_names[i].name;
	}
	return NULL;
}

/* Returns TLV type number for a field name, or UINT64_MAX if unknown. */
static bigsize_t tlv_name_to_num(const char *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(field_names); i++) {
		if (streq(field_names[i].name, name))
			return field_names[i].num;
	}
	return UINT64_MAX;
}

/* Which "layer" does this TLV type belong to? */
enum field_layer { LAYER_OFFER, LAYER_INVREQ, LAYER_INVOICE, LAYER_UNKNOWN };

static enum field_layer tlv_layer(bigsize_t num)
{
	/* BOLT #12:
	 * A writer of an offer:
	 * - MUST NOT set any TLV fields outside the inclusive ranges:
              1 to 79 and 1000000000 to 1999999999. */
	if ((num >= 1 && num <= 79)
	    || (num >= 1000000000 && num <= 1999999999))
		return LAYER_OFFER;
	/* BOLT #12:
	 * ## Requirements for Invoice Requests
	 * The writer:
	 *...
	 * MUST NOT set any non-signature TLV fields outside the inclusive
	 * ranges: 0 to 159 and 1000000000 to 2999999999
	 */
	if ((num >= 80 && num <= 159)
	    || (num >= 2000000000 && num <= 2999999999))
		return LAYER_INVREQ;
	/* BOLT #12:
	 * *signature TLV elements*: TLV types 240 through 1000 (inclusive)
	 */
	/* So, by implication, <= 239 is the invoice field, BUT we also
	 * copy the signature field */
	if ((num >= 160 && num <= 239)
	    || (num >= 3000000000 && num <= 3999999999)
	    || num == TLV_INVOICE_SIGNATURE)
		return LAYER_INVOICE;

	return LAYER_UNKNOWN;
}

static bool u64arr_contains(const bigsize_t *types, bigsize_t type)
{
	for (size_t i = 0; i < tal_count(types); i++) {
		if (types[i] == type)
			return true;
	}
	return false;
}

/* Callback for make_unsigned_proof: include field if in include_types array. */
static bool include_field_fn(const struct tlv_field *f, bigsize_t *types)
{
	return u64arr_contains(types, f->numtype);
}

struct one_proof {
	struct createproof_state *state;

	const struct tlv_invoice *inv;
	struct preimage preimage;
	struct tlv_payer_proof *pptlv;
	/* Filled in as sigs arrive */
	const char *encoded;
};

/* Describes the decoded form of the `invstring` parameter. */
enum bolt12_invtype { INVTYPE_INVOICE, INVTYPE_OFFER, INVTYPE_BIP353 };

struct bolt12_invinfo {
	const char *invstring;  /* canonicalized */
	enum bolt12_invtype type;
	/* INVTYPE_OFFER: */
	struct sha256 offer_id;
	/* INVTYPE_BIP353: */
	struct bip_353_name bip353;
};

struct createproof_state {
	const char *note;
	bigsize_t *include_types;  /* tal_arr */

	struct bolt12_invinfo *invinfo;

	/* One for each proof we're getting sigs for */
	struct one_proof **proofs;
	/* Count down to how many sigs remaining */
	size_t n_outstanding;
};

/* Parse a 64-byte bip340 signature from a JSON hex token. */
static bool json_to_bip340sig(const char *buf, const jsmntok_t *tok,
			      struct bip340sig *sig)
{
	return hex_decode(buf + tok->start, tok->end - tok->start,
			  sig->u8, sizeof(sig->u8));
}

static void json_add_tlv_arr_level(struct json_stream *js,
				   const char *fieldname,
				   enum field_layer layer,
				   const struct tlv_field *fields)
{
	json_array_start(js, fieldname);
	for (size_t i = 0; i < tal_count(fields); i++) {
		const char *name;

		if (tlv_layer(fields[i].numtype) != layer)
			continue;

		name = tlv_type_name(fields[i].numtype);
		if (name)
			json_add_string(js, NULL, name);
		else
			json_add_u64(js, NULL, fields[i].numtype);
	}
	json_array_end(js);
}

/* Output the fields_included arrays for a payer_proof TLV. */
static void json_add_fields_included(struct json_stream *js,
				     const struct tlv_payer_proof *pptlv)
{
	json_add_tlv_arr_level(js, "offer_fields_included",
			       LAYER_OFFER, pptlv->fields);
	json_add_tlv_arr_level(js, "invreq_fields_included",
			       LAYER_INVREQ, pptlv->fields);
	json_add_tlv_arr_level(js, "invoice_fields_included",
			       LAYER_INVOICE, pptlv->fields);
}

static struct command_result *payersign_done(struct command *cmd,
					     const char *method UNNEEDED,
					     const char *buf,
					     const jsmntok_t *result,
					     struct one_proof *proof)
{
	struct createproof_state *state = proof->state;
	const jsmntok_t *sigtok;

	proof->pptlv->proof_signature = tal(proof->pptlv, struct bip340sig);
	sigtok = json_get_member(buf, result, "signature");
	if (!sigtok)
		plugin_err(cmd->plugin, "payersign: no signature in result");
	if (!json_to_bip340sig(buf, sigtok, proof->pptlv->proof_signature))
		plugin_err(cmd->plugin, "payersign: bad signature hex");

	/* Encode as lnp1... string */
	proof->encoded = payer_proof_encode(proof, proof->pptlv);

	/* When all outstanding are done, output all proofs and finish */
	if (--state->n_outstanding != 0)
		return command_still_pending(cmd);

	struct json_stream *response = jsonrpc_stream_success(cmd);
	json_array_start(response, "proofs");
	for (size_t i = 0; i < tal_count(state->proofs); i++) {
		json_object_start(response, NULL);
		json_add_string(response, "bolt12", state->proofs[i]->encoded);
		json_add_fields_included(response, state->proofs[i]->pptlv);
		json_object_end(response);
	}
	json_array_end(response);
	return command_finished(cmd, response);
}

static struct command_result *listsendpays_done(struct command *cmd,
						const char *method UNNEEDED,
						const char *buf,
						const jsmntok_t *result,
						struct createproof_state *state)
{
	const jsmntok_t *arr, *t;
	size_t i;

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY)
		return command_fail(cmd, LIGHTNINGD,
				    "Unexpected listsendpays result");

	state->proofs = tal_arr(state, struct one_proof *, 0);

	json_for_each_arr(i, t, arr) {
		const jsmntok_t *statustok, *b12tok, *preimagetok;
		const char *b12str;
		struct tlv_invoice *inv;
		struct preimage preimage;
		const char *fail;
		struct one_proof *proof;
		struct sha256 mroot;
		struct out_req *req;

		statustok = json_get_member(buf, t, "status");
		if (!statustok || !json_tok_streq(buf, statustok, "complete"))
			continue;

		preimagetok = json_get_member(buf, t, "payment_preimage");
		if (!preimagetok)
			continue;
		if (!json_to_preimage(buf, preimagetok, &preimage))
			continue;

		b12tok = json_get_member(buf, t, "bolt12");
		if (!b12tok)
			continue;

		b12str = json_strdup(tmpctx, buf, b12tok);
		inv = invoice_decode(tmpctx, b12str, strlen(b12str),
				     NULL, chainparams, &fail);
		if (!inv)
			continue;

		switch (state->invinfo->type) {
		case INVTYPE_OFFER: {
			/* offer_id matching means invoice is for this offer */
			struct sha256 inv_offer_id;
			invoice_offer_id(inv, &inv_offer_id);
			if (!sha256_eq(&state->invinfo->offer_id, &inv_offer_id))
				continue;
			break;
		}
		case INVTYPE_BIP353:
			if (!inv->invreq_bip_353_name)
				continue;
			if (!memeq(state->invinfo->bip353.name,
				   tal_bytelen(state->invinfo->bip353.name),
				   inv->invreq_bip_353_name->name,
				   tal_bytelen(inv->invreq_bip_353_name->name)))
				continue;
			if (!memeq(state->invinfo->bip353.domain,
				   tal_bytelen(state->invinfo->bip353.domain),
				   inv->invreq_bip_353_name->domain,
				   tal_bytelen(inv->invreq_bip_353_name->domain)))
				continue;
			break;
		case INVTYPE_INVOICE:
			/* We already told listsendpays to only give us this invoice */
			break;
		}

		proof = tal(state->proofs, struct one_proof);
		proof->state = state;
		proof->inv = tal_steal(proof, inv);
		proof->preimage = preimage;
		proof->pptlv = make_unsigned_proof(proof,
						   proof->inv,
						   &proof->preimage,
						   state->note,
						   include_field_fn,
						   state->include_types);
		bolt12_payer_proof_merkle(proof->pptlv, &mroot);

		req = jsonrpc_request_start(cmd, "payersign",
					    &payersign_done,
					    &plugin_broken_cb,
					    proof);
		json_add_string(req->js, "messagename", "payer_proof");
		json_add_string(req->js, "fieldname", "proof_signature");
		json_add_sha256(req->js, "merkle", &mroot);
		json_add_hex(req->js, "tweak",
			     proof->inv->invreq_metadata,
			     tal_bytelen(proof->inv->invreq_metadata));
		send_outreq(req);

		tal_arr_expand(&state->proofs, proof);
	}

	state->n_outstanding = tal_count(state->proofs);
	if (state->n_outstanding == 0)
		return command_fail(cmd, CREATEPROOF_NO_PAYMENT,
				    "No successful payment found for that invstring");

	return command_still_pending(cmd);
}

/* param_ callback for the `include` array parameter.
 * Accepts an array of field name strings or u64 numbers.
 * Always prepends the mandatory_types. */
static struct command_result *param_include_types(struct command *cmd,
						  const char *name,
						  const char *buf,
						  const jsmntok_t *tok,
						  bigsize_t **types)
{
	const jsmntok_t *t;
	size_t i;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buf, tok,
					     "Expected array");

	*types = tal_arr(cmd, bigsize_t, 0);

	/* Always start with mandatory types */
	for (size_t j = 0; j < ARRAY_SIZE(mandatory_types); j++)
		tal_arr_expand(types, mandatory_types[j]);

	/* Add user-specified fields, skipping duplicates */
	json_for_each_arr(i, t, tok) {
		bigsize_t num;

		if (t->type == JSMN_STRING) {
			char *fname = json_strdup(tmpctx, buf, t);
			num = tlv_name_to_num(fname);
			if (num == UINT64_MAX)
				return command_fail_badparam(cmd, name, buf, t,
							     "Unknown field name");
		} else if (t->type == JSMN_PRIMITIVE) {
			u64 v;
			if (!json_to_u64(buf, t, &v))
				return command_fail_badparam(cmd, name, buf, t,
							     "Expected name or number");
			num = v;
		} else {
			return command_fail_badparam(cmd, name, buf, t,
						     "Expected name or number");
		}

		if (!u64arr_contains(*types, num))
			tal_arr_expand(types, num);
	}

	return NULL;
}

/* param_ callback for `invstring`: canonicalizes and decodes offer/BIP353. */
static struct command_result *param_bolt12_invstring(struct command *cmd,
						     const char *name,
						     const char *buf,
						     const jsmntok_t *tok,
						     struct bolt12_invinfo **invinfo)
{
	const char *invstring = to_canonical_invstr(cmd, json_strdup(tmpctx, buf, tok));
	const char *fail;

	*invinfo = tal(cmd, struct bolt12_invinfo);
	(*invinfo)->invstring = invstring;

	if (strstarts(invstring, "lni1")) {
		(*invinfo)->type = INVTYPE_INVOICE;
	} else if (strstarts(invstring, "lno1")) {
		struct tlv_offer *offer;
		offer = offer_decode(tmpctx, invstring, strlen(invstring),
				     NULL, chainparams, &fail);
		if (!offer)
			return command_fail_badparam(cmd, name, buf, tok,
						     tal_fmt(tmpctx, "Invalid offer: %s", fail));
		offer_offer_id(offer, &(*invinfo)->offer_id);
		(*invinfo)->type = INVTYPE_OFFER;
	} else if (strchr(invstring, '@')) {
		/* BOLT #12:
		 *  - if it received the offer from which it constructed this
		 *    `invoice_request` using BIP 353 resolution:
		 *     - MUST include `invreq_bip_353_name` with,
		 *       - `name` set to the post-₿, pre-@ part of the BIP 353 HRN,
		 *       - `domain` set to the post-@ part of the BIP 353 HRN.
		 */
		char *str = json_strdup(tmpctx, buf, tok);
		char *at;

		if (!utf8_check(str, strlen(str)))
			return command_fail_badparam(cmd, name, buf, tok,
						     "Invalid UTF-8");
		/* Strip ₿ if present (0xE2 0x82 0xBF) */
		if (strstarts(str, "₿"))
			str += strlen("₿");
		at = strchr(str, '@');
		if (!at)
			return command_fail_badparam(cmd, name, buf, tok,
						     "Missing @ in BIP353 address");
		(*invinfo)->bip353.name
			= tal_dup_arr(*invinfo, u8, (const u8 *)str,
				      at - str, 0);
		(*invinfo)->bip353.domain
			= tal_dup_arr(*invinfo, u8, (const u8 *)(at + 1),
				      strlen(at + 1), 0);
		(*invinfo)->type = INVTYPE_BIP353;
	} else {
		return command_fail_badparam(cmd, name, buf, tok,
					     "Expected bolt12 invoice (lni1...), "
					     "offer (lno1...), or user@domain");
	}
	return NULL;
}

struct command_result *json_createproof(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params)
{
	struct createproof_state *state;
	struct out_req *req;

	state = tal(cmd, struct createproof_state);
	if (!param(cmd, buffer, params,
		   p_req("invstring", param_bolt12_invstring, &state->invinfo),
		   p_opt("note", param_string, &state->note),
		   p_opt("include", param_include_types, &state->include_types),
		   NULL))
		return command_param_failed();

	if (!state->include_types) {
		/* Default: mandatory + extras */
		state->include_types = tal_arr(state, bigsize_t, 0);
		for (size_t i = 0; i < ARRAY_SIZE(mandatory_types); i++)
			tal_arr_expand(&state->include_types, mandatory_types[i]);
		for (size_t i = 0; i < ARRAY_SIZE(default_extras); i++)
			tal_arr_expand(&state->include_types, default_extras[i]);
	}

	/* Look up completed payments.
	 * For bolt12 invoices, listsendpays filters by payment_hash.
	 * For offers and BIP353, we get all and filter in the callback. */
	req = jsonrpc_request_start(cmd, "listsendpays",
				    &listsendpays_done,
				    &forward_error,
				    state);
	if (state->invinfo->type == INVTYPE_INVOICE)
		json_add_string(req->js, "bolt11", state->invinfo->invstring);
	json_add_string(req->js, "status", "complete");
	return send_outreq(req);
}
