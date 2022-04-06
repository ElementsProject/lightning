#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/take/take.h>
#include <common/bolt12_merkle.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <secp256k1_schnorrsig.h>
#include <sodium/randombytes.h>
#include <wire/wire_sync.h>

static void json_populate_offer(struct json_stream *response,
				const struct sha256 *offer_id,
				const char *b12,
				const char *b12_nosig,
				const struct json_escape *label,
				enum offer_status status)
{
	json_add_sha256(response, "offer_id", offer_id);
	json_add_bool(response, "active", offer_status_active(status));
	json_add_bool(response, "single_use", offer_status_single(status));
	json_add_string(response, "bolt12", b12);
	if (b12_nosig)
		json_add_string(response, "bolt12_unsigned", b12_nosig);
	json_add_bool(response, "used", offer_status_used(status));
	if (label)
		json_add_escaped_string(response, "label", label);
}

static struct command_result *param_b12_offer(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct tlv_offer **offer)
{
	char *fail;
	*offer = offer_decode(cmd, buffer + tok->start,
			      tok->end - tok->start,
			      cmd->ld->our_features, chainparams, &fail);
	if (!*offer)
		return command_fail_badparam(cmd, name, buffer, tok, fail);
	if ((*offer)->signature)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must be unsigned offer");
	return NULL;
}

static void hsm_sign_b12(struct lightningd *ld,
			 const char *messagename,
			 const char *fieldname,
			 const struct sha256 *merkle,
			 const u8 *publictweak,
			 const struct point32 *key,
			 struct bip340sig *sig)
{
	u8 *msg;
	struct sha256 sighash;

	msg = towire_hsmd_sign_bolt12(NULL, messagename, fieldname, merkle,
				      publictweak);
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
        if (!fromwire_hsmd_sign_bolt12_reply(msg, sig))
		fatal("HSM gave bad sign_offer_reply %s",
		      tal_hex(msg, msg));

	/* Now we sanity-check! */
	sighash_from_merkle(messagename, fieldname, merkle, &sighash);
	if (secp256k1_schnorrsig_verify(secp256k1_ctx, sig->u8,
					sighash.u.u8, sizeof(sighash.u.u8), &key->pubkey) != 1)
		fatal("HSM gave bad signature %s for pubkey %s",
		      type_to_string(tmpctx, struct bip340sig, sig),
		      type_to_string(tmpctx, struct point32, key));
}

static struct command_result *json_createoffer(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct json_stream *response;
	struct json_escape *label;
	struct tlv_offer *offer;
	struct sha256 merkle;
	const char *b12str, *b12str_nosig;
	bool *single_use;
	enum offer_status status;
	struct point32 key;
	bool created;

	if (!param(cmd, buffer, params,
		   p_req("bolt12", param_b12_offer, &offer),
		   p_opt("label", param_label, &label),
		   p_opt_def("single_use", param_bool, &single_use, false),
		   NULL))
		return command_param_failed();

	if (*single_use)
		status = OFFER_SINGLE_USE_UNUSED;
	else
		status = OFFER_MULTIPLE_USE_UNUSED;
 	merkle_tlv(offer->fields, &merkle);
	offer->signature = tal(offer, struct bip340sig);
	if (!point32_from_node_id(&key, &cmd->ld->id))
		fatal("invalid own node_id?");
	hsm_sign_b12(cmd->ld, "offer", "signature", &merkle, NULL, &key,
		     offer->signature);
	b12str = offer_encode(cmd, offer);

	/* If it already exists, we use that one instead (and then
	 * the offer plugin will complain if it's inactive or expired) */
	if (!wallet_offer_create(cmd->ld->wallet, &merkle,
				 b12str, label, status)) {
		if (!wallet_offer_find(cmd, cmd->ld->wallet, &merkle,
				       cast_const2(const struct json_escape **,
						   &label),
				       &status)) {
			return command_fail(cmd, LIGHTNINGD,
					    "Could not create, nor find offer");
		}
		created = false;
	} else
		created = true;

	offer->signature = tal_free(offer->signature);
	b12str_nosig = offer_encode(cmd, offer);

	response = json_stream_success(cmd);
	json_populate_offer(response, &merkle, b12str, b12str_nosig, label, status);
	json_add_bool(response, "created", created);
	return command_success(cmd, response);
}

static const struct json_command createoffer_command = {
	"createoffer",
	"payment",
	json_createoffer,
	"Create and sign an offer {bolt12} with and optional {label}."
};
AUTODATA(json_command, &createoffer_command);

/* We store strings in the db, so removing signatures is easiest by conversion */
static const char *offer_str_nosig(const tal_t *ctx,
				   struct lightningd *ld,
				   const char *b12str)
{
	char *fail;
	struct tlv_offer *offer = offer_decode(tmpctx, b12str, strlen(b12str),
					       ld->our_features, chainparams,
					       &fail);

	if (!offer) {
		log_broken(ld->log, "Cannot reparse offerstr from db %s: %s",
			   b12str, fail);
		return NULL;
	}
	offer->signature = tal_free(offer->signature);
	return offer_encode(ctx, offer);
}

static struct command_result *json_listoffers(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct sha256 *offer_id;
	struct json_stream *response;
	struct wallet *wallet = cmd->ld->wallet;
	const char *b12;
	const struct json_escape *label;
	bool *active_only;
	enum offer_status status;

	if (!param(cmd, buffer, params,
		   p_opt("offer_id", param_sha256, &offer_id),
		   p_opt_def("active_only", param_bool, &active_only, false),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "offers");
	if (offer_id) {
		b12 = wallet_offer_find(tmpctx, wallet, offer_id, &label,
					&status);
		if (b12 && offer_status_active(status) >= *active_only) {
			json_object_start(response, NULL);
			json_populate_offer(response,
					    offer_id, b12,
					    offer_str_nosig(tmpctx, cmd->ld, b12),
					    label, status);
			json_object_end(response);
		}
	} else {
		struct db_stmt *stmt;
		struct sha256 id;

		for (stmt = wallet_offer_id_first(cmd->ld->wallet, &id);
		     stmt;
		     stmt = wallet_offer_id_next(cmd->ld->wallet, stmt, &id)) {
			b12 = wallet_offer_find(tmpctx, wallet, &id,
						&label, &status);
			if (offer_status_active(status) >= *active_only) {
				json_object_start(response, NULL);
				json_populate_offer(response,
						    &id, b12,
						    offer_str_nosig(tmpctx,
								    cmd->ld, b12),
						    label, status);
				json_object_end(response);
			}
		}
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listoffers_command = {
	"listoffers",
	"payment",
	json_listoffers,
	"If {offer_id} is set, show that."
	" Otherwise, if {showdisabled} is true, list all, otherwise just non-disabled ones."
};
AUTODATA(json_command, &listoffers_command);

static struct command_result *json_disableoffer(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_stream *response;
	struct sha256 *offer_id;
	struct wallet *wallet = cmd->ld->wallet;
	const char *b12;
	const struct json_escape *label;
	enum offer_status status;

	if (!param(cmd, buffer, params,
		   p_req("offer_id", param_sha256, &offer_id),
		   NULL))
		return command_param_failed();

	b12 = wallet_offer_find(tmpctx, wallet, offer_id, &label, &status);
	if (!b12)
		return command_fail(cmd, LIGHTNINGD, "Unknown offer");

	if (!offer_status_active(status))
		return command_fail(cmd, OFFER_ALREADY_DISABLED,
				    "offer is not active");
	status = wallet_offer_disable(wallet, offer_id, status);

	response = json_stream_success(cmd);
	json_populate_offer(response, offer_id, b12,
			    offer_str_nosig(tmpctx,
					    cmd->ld, b12),
			    label, status);
	return command_success(cmd, response);
}

static const struct json_command disableoffer_command = {
	"disableoffer",
	"payment",
	json_disableoffer,
	"Disable offer {offer_id}",
};
AUTODATA(json_command, &disableoffer_command);

/* We do some sanity checks now, since we're looking up prev payment anyway,
 * but our main purpose is to fill in invreq->payer_info tweak. */
static struct command_result *prev_payment(struct command *cmd,
					   const char *label,
					   struct tlv_invoice_request *invreq,
					   u64 **prev_basetime)
{
	const struct wallet_payment **payments;
	bool prev_paid = false;

	assert(!invreq->payer_info);
	payments = wallet_payment_list(cmd, cmd->ld->wallet, NULL, NULL);

	for (size_t i = 0; i < tal_count(payments); i++) {
		const struct tlv_invoice *inv;
		char *fail;

		/* FIXME: Restrict db queries instead */
		if (!payments[i]->label || !streq(label, payments[i]->label))
			continue;

		if (!payments[i]->invstring)
			continue;

		inv = invoice_decode(tmpctx, payments[i]->invstring,
				     strlen(payments[i]->invstring),
				     NULL, chainparams, &fail);
		if (!inv)
			continue;

		/* They can reuse labels across different offers. */
		if (!sha256_eq(inv->offer_id, invreq->offer_id))
			continue;

		/* Be paranoid, in case someone inserts their own
		 * clashing label! */
		if (!inv->recurrence_counter)
			continue;

		/* BOLT-offers-recurrence #12:
		 * - if the offer contained `recurrence_base` with
		 *   `start_any_period` non-zero:
		 *   - MUST include `recurrence_start`
		 *   - MUST set `period_offset` to the period the sender wants
		 *     for the initial request
		 *   - MUST set `period_offset` to the same value on all
		 *     following requests.
		 */
		if (invreq->recurrence_start) {
			if (!inv->recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "unexpected"
						    " recurrence_start");
			if (*inv->recurrence_start != *invreq->recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "recurrence_start was"
						    " previously %u",
						    *inv->recurrence_start);
		} else {
			if (inv->recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "missing"
						    " recurrence_start");
		}

		if (*inv->recurrence_counter == *invreq->recurrence_counter-1) {
			if (payments[i]->status == PAYMENT_COMPLETE)
				prev_paid = true;
		}

		if (inv->payer_info) {
			invreq->payer_info
				= tal_dup_talarr(invreq, u8, inv->payer_info);
			*prev_basetime = tal_dup(cmd, u64,
						 inv->recurrence_basetime);
		}

		if (prev_paid && inv->payer_info)
			break;
	}

	if (!invreq->payer_info)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "No previous payment attempted for this"
				    " label and offer");

	if (!prev_paid)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "previous invoice has not been paid");

	return NULL;
}

static struct command_result *param_b12_invreq(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct tlv_invoice_request **invreq)
{
	char *fail;

	*invreq = invrequest_decode(cmd, buffer + tok->start,
				    tok->end - tok->start,
				    cmd->ld->our_features, chainparams, &fail);
	if (!*invreq)
		return command_fail_badparam(cmd, name, buffer, tok, fail);
	if ((*invreq)->payer_info)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must not have payer_info");
	if ((*invreq)->payer_key)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must not have payer_key");
	return NULL;
}

static bool payer_key(struct lightningd *ld,
		      const u8 *public_tweak, size_t public_tweak_len,
		      struct point32 *key)
{
	struct sha256 tweakhash;
	secp256k1_pubkey tweaked;

	payer_key_tweak(&ld->bolt12_base, public_tweak, public_tweak_len,
			&tweakhash);

	/* Tweaking gives a not-x-only pubkey, must then convert. */
	if (secp256k1_xonly_pubkey_tweak_add(secp256k1_ctx,
					     &tweaked,
					     &ld->bolt12_base.pubkey,
					     tweakhash.u.u8) != 1)
		return false;

	return secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx,
						   &key->pubkey,
						   NULL, &tweaked) == 1;
}

static struct command_result *json_createinvoicerequest(struct command *cmd,
							const char *buffer,
							const jsmntok_t *obj,
							const jsmntok_t *params)
{
	struct tlv_invoice_request *invreq;
	const char *label;
	struct json_stream *response;
	u64 *prev_basetime = NULL;
	struct sha256 merkle;

	if (!param(cmd, buffer, params,
		   p_req("bolt12", param_b12_invreq, &invreq),
		   p_opt("recurrence_label", param_escaped_string, &label),
		   NULL))
		return command_param_failed();

	if (invreq->recurrence_counter) {
		if (!label)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Need payment label for recurring payments");

		if (*invreq->recurrence_counter != 0) {
			struct command_result *err
				= prev_payment(cmd, label, invreq,
					       &prev_basetime);
			if (err)
				return err;
		}
	}

	if (!invreq->payer_info) {
		/* BOLT-offers #12:
		 * `payer_info` might typically contain information about the
		 * derivation of the `payer_key`.  This should not leak any
		 * information (such as using a simple BIP-32 derivation
		 * path); a valid system might be for a node to maintain a
		 * base payer key, and encode a 128-bit tweak here.  The
		 * payer_key would be derived by tweaking the base key with
		 * SHA256(payer_base_pubkey || tweak).
		 */
		invreq->payer_info = tal_arr(invreq, u8, 16);
		randombytes_buf(invreq->payer_info,
				tal_bytelen(invreq->payer_info));
	}

	invreq->payer_key = tal(invreq, struct point32);
	if (!payer_key(cmd->ld,
		       invreq->payer_info, tal_bytelen(invreq->payer_info),
		       invreq->payer_key)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid tweak");
	}

	/* BOLT-offers #12:
	 *  - MUST set `signature` `sig` as detailed in
	 *  [Signature Calculation](#signature-calculation) using the `payer_key`.
	 */
	/* This populates the ->fields from our entries */
	invreq->fields = tlv_make_fields(invreq, tlv_invoice_request);
	merkle_tlv(invreq->fields, &merkle);
	invreq->signature = tal(invreq, struct bip340sig);
	if (deprecated_apis)
		hsm_sign_b12(cmd->ld, "invoice_request", "payer_signature",
			     &merkle, invreq->payer_info, invreq->payer_key,
			     invreq->signature);
	else
		hsm_sign_b12(cmd->ld, "invoice_request", "signature",
			     &merkle, invreq->payer_info, invreq->payer_key,
			     invreq->signature);

	response = json_stream_success(cmd);
	json_add_string(response, "bolt12", invrequest_encode(tmpctx, invreq));
	if (label)
		json_add_escaped_string(response, "recurrence_label",
					take(json_escape(NULL, label)));
	if (prev_basetime)
		json_add_u64(response, "previous_basetime", *prev_basetime);
	return command_success(cmd, response);
}

static const struct json_command createinvreq_command = {
	"createinvoicerequest",
	"payment",
	json_createinvoicerequest,
	"Create and sign an invoice_request {bolt12}, with {recurrence_label} if recurring, filling in payer_info and payer_key."
};
AUTODATA(json_command, &createinvreq_command);

static struct command_result *json_payersign(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	struct sha256 *merkle;
	u8 *tweak;
	struct bip340sig sig;
	const char *messagename, *fieldname;
	struct point32 key;

	if (!param(cmd, buffer, params,
		   p_req("messagename", param_string, &messagename),
		   p_req("fieldname", param_string, &fieldname),
		   p_req("merkle", param_sha256, &merkle),
		   p_req("tweak", param_bin_from_hex, &tweak),
		   NULL))
		return command_param_failed();

	payer_key(cmd->ld, tweak, tal_bytelen(tweak), &key);
	hsm_sign_b12(cmd->ld, messagename, fieldname, merkle,
		     tweak, &key, &sig);

	response = json_stream_success(cmd);
	json_add_string(response, "signature", fmt_bip340sig(tmpctx, &sig));
	return command_success(cmd, response);
}

static const struct json_command payersign_command = {
	"payersign",
	"payment",
	json_payersign,
	"Sign {messagename} {fieldname} {merkle} (a 32-byte hex string) using public {tweak}",
};
AUTODATA(json_command, &payersign_command);
