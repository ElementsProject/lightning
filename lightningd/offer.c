#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/take/take.h>
#include <common/bolt12_merkle.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <secp256k1_schnorrsig.h>
#include <sodium/randombytes.h>

static void json_populate_offer(struct json_stream *response,
				const struct sha256 *offer_id,
				const char *b12,
				const struct json_escape *label,
				enum offer_status status)
{
	json_add_sha256(response, "offer_id", offer_id);
	json_add_bool(response, "active", offer_status_active(status));
	json_add_bool(response, "single_use", offer_status_single(status));
	json_add_string(response, "bolt12", b12);
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
	return NULL;
}

static void hsm_sign_b12(struct lightningd *ld,
			 const char *messagename,
			 const char *fieldname,
			 const struct sha256 *merkle,
			 const u8 *publictweak,
			 const struct pubkey *key,
			 struct bip340sig *sig)
{
	const u8 *msg;
	struct sha256 sighash;

	msg = towire_hsmd_sign_bolt12(NULL, messagename, fieldname, merkle,
				      publictweak);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
        if (!fromwire_hsmd_sign_bolt12_reply(msg, sig))
		fatal("HSM gave bad sign_offer_reply %s",
		      tal_hex(msg, msg));

	/* Now we sanity-check! */
	sighash_from_merkle(messagename, fieldname, merkle, &sighash);
	if (!check_schnorr_sig(&sighash, &key->pubkey, sig))
		fatal("HSM gave bad signature %s for pubkey %s",
		      fmt_bip340sig(tmpctx, sig),
		      fmt_pubkey(tmpctx, key));
}

static struct command_result *json_createoffer(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct json_stream *response;
	struct json_escape *label;
	struct tlv_offer *offer;
	struct sha256 offer_id;
	const char *b12str;
	bool *single_use;
	enum offer_status status;
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
	b12str = offer_encode(cmd, offer);
	offer_offer_id(offer, &offer_id);

	/* If it already exists, we use that one instead (and then
	 * the offer plugin will complain if it's inactive or expired) */
	if (!wallet_offer_create(cmd->ld->wallet, &offer_id,
				 b12str, label, status)) {
		if (!wallet_offer_find(cmd, cmd->ld->wallet, &offer_id,
				       cast_const2(const struct json_escape **,
						   &label),
				       &status)) {
			return command_fail(cmd, LIGHTNINGD,
					    "Could not create, nor find offer");
		}
		created = false;
	} else
		created = true;

	response = json_stream_success(cmd);
	json_populate_offer(response, &offer_id, b12str, label, status);
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

	if (!param_check(cmd, buffer, params,
			 p_req("offer_id", param_sha256, &offer_id),
			 NULL))
		return command_param_failed();

	b12 = wallet_offer_find(tmpctx, wallet, offer_id, &label, &status);
	if (!b12)
		return command_fail(cmd, LIGHTNINGD, "Unknown offer");

	if (!offer_status_active(status))
		return command_fail(cmd, OFFER_ALREADY_DISABLED,
				    "offer is not active");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	status = wallet_offer_disable(wallet, offer_id, status);

	response = json_stream_success(cmd);
	json_populate_offer(response, offer_id, b12, label, status);
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
 * but our main purpose is to fill in invreq->invreq_metadata tweak. */
static struct command_result *prev_payment(struct command *cmd,
					   const struct json_escape *label,
					   struct tlv_invoice_request *invreq,
					   u64 **prev_basetime)
{
	bool prev_paid = false;
	struct sha256 invreq_oid;

	invreq_offer_id(invreq, &invreq_oid);
	assert(!invreq->invreq_metadata);

	for (struct db_stmt *stmt = payments_by_label(cmd->ld->wallet, label);
	     stmt;
	     stmt = payments_next(cmd->ld->wallet, stmt)) {
		const struct wallet_payment *payment;
		const struct tlv_invoice *inv;
		char *fail;
		struct sha256 inv_oid;

		payment = payment_get_details(tmpctx, stmt);
		if (!payment->invstring)
			continue;

		inv = invoice_decode(tmpctx, payment->invstring,
				     strlen(payment->invstring),
				     NULL, chainparams, &fail);
		if (!inv)
			continue;

		/* They can reuse labels across different offers. */
		invoice_offer_id(inv, &inv_oid);
		if (!sha256_eq(&inv_oid, &invreq_oid))
			continue;

		/* Be paranoid, in case someone inserts their own
		 * clashing label! */
		if (!inv->invreq_recurrence_counter)
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
		if (invreq->invreq_recurrence_start) {
			if (!inv->invreq_recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "unexpected"
						    " recurrence_start");
			if (*inv->invreq_recurrence_start != *invreq->invreq_recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "recurrence_start was"
						    " previously %u",
						    *inv->invreq_recurrence_start);
		} else {
			if (inv->invreq_recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "missing"
						    " recurrence_start");
		}

		if (*inv->invreq_recurrence_counter == *invreq->invreq_recurrence_counter-1) {
			if (payment->status == PAYMENT_COMPLETE)
				prev_paid = true;
		}

		if (inv->invreq_metadata) {
			invreq->invreq_metadata
				= tal_dup_talarr(invreq, u8, inv->invreq_metadata);
			*prev_basetime = tal_dup(cmd, u64,
						 inv->invoice_recurrence_basetime);
		}

		if (prev_paid && inv->invreq_metadata) {
			tal_free(stmt);
			break;
		}
	}

	if (!invreq->invreq_metadata)
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

	/* We use this for testing with known payer_info */
	if ((*invreq)->invreq_metadata && !cmd->ld->developer)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must not have invreq_metadata");

	if ((*invreq)->invreq_payer_id)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must not have invreq_payer_id");
	return NULL;
}

static bool payer_key(struct lightningd *ld,
		      const u8 *public_tweak, size_t public_tweak_len,
		      struct pubkey *key)
{
	struct sha256 tweakhash;

	payer_key_tweak(&ld->bolt12_base, public_tweak, public_tweak_len,
			&tweakhash);

	*key = ld->bolt12_base;
	return secp256k1_ec_pubkey_tweak_add(secp256k1_ctx,
					     &key->pubkey,
					     tweakhash.u.u8) == 1;
}

static void json_populate_invreq(struct json_stream *response,
				 const struct sha256 *invreq_id,
				 const char *b12,
				 const struct json_escape *label,
				 enum offer_status status)
{
	json_add_sha256(response, "invreq_id", invreq_id);
	json_add_bool(response, "active", offer_status_active(status));
	json_add_bool(response, "single_use", offer_status_single(status));
	json_add_string(response, "bolt12", b12);
	json_add_bool(response, "used", offer_status_used(status));
	if (label)
		json_add_escaped_string(response, "label", label);
}

static struct command_result *json_createinvoicerequest(struct command *cmd,
							const char *buffer,
							const jsmntok_t *obj,
							const jsmntok_t *params)
{
	struct tlv_invoice_request *invreq;
	struct json_escape *label;
	struct json_stream *response;
	u64 *prev_basetime = NULL;
	struct sha256 merkle;
	bool *save, *single_use, *exposeid;
	enum offer_status status;
	struct sha256 invreq_id;
	const char *b12str;

	if (!param_check(cmd, buffer, params,
			 p_req("bolt12", param_b12_invreq, &invreq),
			 p_req("savetodb", param_bool, &save),
			 p_opt_def("exposeid", param_bool, &exposeid, false),
			 p_opt("recurrence_label", param_label, &label),
			 p_opt_def("single_use", param_bool, &single_use, true),
			 NULL))
		return command_param_failed();

	if (*single_use)
		status = OFFER_SINGLE_USE_UNUSED;
	else
		status = OFFER_MULTIPLE_USE_UNUSED;

	/* If it's a recurring payment, we look for previous to copy
	 * invreq_metadata, basetime */
	if (invreq->invreq_recurrence_counter) {
		if (!label)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Need payment label for recurring payments");

		if (*invreq->invreq_recurrence_counter != 0) {
			struct command_result *err
				= prev_payment(cmd, label, invreq,
					       &prev_basetime);
			if (err)
				return err;
		}
	}

	if (!invreq->invreq_metadata) {
		/* BOLT-offers #12:
		 *
		 * `invreq_metadata` might typically contain information about
		 * the derivation of the `invreq_payer_id`.  This should not
		 * leak any information (such as using a simple BIP-32
		 * derivation path); a valid system might be for a node to
		 * maintain a base payer key and encode a 128-bit tweak here.
		 * The payer_id would be derived by tweaking the base key with
		 * SHA256(payer_base_pubkey || tweak).  It's also the first
		 * entry (if present), ensuring an unpredictable nonce for
		 * hashing.
		 */
		invreq->invreq_metadata = tal_arr(invreq, u8, 16);
		randombytes_buf(invreq->invreq_metadata,
				tal_bytelen(invreq->invreq_metadata));
	}

	invreq->invreq_payer_id = tal(invreq, struct pubkey);
	if (*exposeid) {
		if (!pubkey_from_node_id(invreq->invreq_payer_id,
					 &cmd->ld->id))
			fatal("Our ID is invalid?");
	} else if (!payer_key(cmd->ld,
			      invreq->invreq_metadata,
			      tal_bytelen(invreq->invreq_metadata),
			      invreq->invreq_payer_id)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid tweak");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* BOLT-offers #12:
	 *  - MUST set `signature`.`sig` as detailed in
	 *  [Signature Calculation](#signature-calculation) using the `invreq_payer_id`.
	 */
	/* This populates the ->fields from our entries */
	invreq->fields = tlv_make_fields(invreq, tlv_invoice_request);
	merkle_tlv(invreq->fields, &merkle);
	invreq->signature = tal(invreq, struct bip340sig);
	hsm_sign_b12(cmd->ld, "invoice_request", "signature",
		     &merkle, *exposeid ? NULL : invreq->invreq_metadata,
		     invreq->invreq_payer_id, invreq->signature);

	b12str = invrequest_encode(cmd, invreq);

	invreq_invreq_id(invreq, &invreq_id);
	if (*save && !wallet_invoice_request_create(cmd->ld->wallet, &invreq_id,
						    b12str, label, status)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not create invoice_request!");
	}

	response = json_stream_success(cmd);
	json_populate_invreq(response, &invreq_id,
			     b12str,
			     label,
			     status);
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
	struct pubkey key;

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

static struct command_result *json_derivepayerid(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	u8 *invreq_metadata;
	struct pubkey key;

	if (!param(cmd, buffer, params,
		   p_req("metadata", param_bin_from_hex, &invreq_metadata),
		   NULL))
		return command_param_failed();

	payer_key(cmd->ld, invreq_metadata, tal_bytelen(invreq_metadata), &key);

	response = json_stream_success(cmd);
	json_add_pubkey(response, "payer_id", &key);
	return command_success(cmd, response);
}

static const struct json_command derivepayerid_command = {
	"derivepayerid",
	"payment",
	json_derivepayerid,
	"Derive the Payer Id from the {invreq_metadata} {merkle}",
};
AUTODATA(json_command, &derivepayerid_command);


static struct command_result *json_listinvoicerequests(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	struct sha256 *invreq_id;
	struct json_stream *response;
	struct wallet *wallet = cmd->ld->wallet;
	const char *b12;
	const struct json_escape *label;
	bool *active_only;
	enum offer_status status;

	if (!param(cmd, buffer, params,
		   p_opt("invreq_id", param_sha256, &invreq_id),
		   p_opt_def("active_only", param_bool, &active_only, false),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "invoicerequests");
	if (invreq_id) {
		b12 = wallet_invoice_request_find(tmpctx, wallet,
						  invreq_id, &label,
						  &status);
		if (b12 && offer_status_active(status) >= *active_only) {
			json_object_start(response, NULL);
			json_populate_invreq(response,
					    invreq_id, b12,
					    label, status);
			json_object_end(response);
		}
	} else {
		struct db_stmt *stmt;
		struct sha256 id;

		for (stmt = wallet_invreq_id_first(cmd->ld->wallet, &id);
		     stmt;
		     stmt = wallet_invreq_id_next(cmd->ld->wallet, stmt, &id)) {
			b12 = wallet_invoice_request_find(tmpctx, wallet, &id,
						&label, &status);
			if (offer_status_active(status) >= *active_only) {
				json_object_start(response, NULL);
				json_populate_invreq(response,
						    &id, b12,
						    label, status);
				json_object_end(response);
			}
		}
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listinvoicerequests_command = {
	"listinvoicerequests",
	"payment",
	json_listinvoicerequests,
	"If {invreq_id} is set, show that."
	" Otherwise, if {showdisabled} is true, list all, otherwise just non-disabled ones."
};
AUTODATA(json_command, &listinvoicerequests_command);

static struct command_result *json_disableinvoicerequest(struct command *cmd,
							 const char *buffer,
							 const jsmntok_t *obj UNNEEDED,
							 const jsmntok_t *params)
{
	struct json_stream *response;
	struct sha256 *invreq_id;
	struct wallet *wallet = cmd->ld->wallet;
	const char *b12;
	const struct json_escape *label;
	enum offer_status status;

	if (!param_check(cmd, buffer, params,
			 p_req("invreq_id", param_sha256, &invreq_id),
			 NULL))
		return command_param_failed();

	b12 = wallet_invoice_request_find(tmpctx, wallet, invreq_id,
					  &label, &status);
	if (!b12)
		return command_fail(cmd, LIGHTNINGD, "Unknown invoice_request");

	if (!offer_status_active(status))
		return command_fail(cmd, OFFER_ALREADY_DISABLED,
				    "invoice_request is not active");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	status = wallet_invoice_request_disable(wallet, invreq_id, status);

	response = json_stream_success(cmd);
	json_populate_invreq(response, invreq_id, b12, label, status);
	return command_success(cmd, response);
}

static const struct json_command disableinvoicerequest_command = {
	"disableinvoicerequest",
	"payment",
	json_disableinvoicerequest,
	"Disable invoice_request {invreq_id}",
};
AUTODATA(json_command, &disableinvoicerequest_command);

