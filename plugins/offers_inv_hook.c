#include "config.h"
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12_id.h>
#include <common/bolt12_merkle.h>
#include <common/json_stream.h>
#include <plugins/offers.h>
#include <plugins/offers_inv_hook.h>
#include <secp256k1_schnorrsig.h>

/* We need to keep the reply path around so we can reply if error */
struct inv {
	struct tlv_invoice *inv;
	struct sha256 invreq_id;

	/* May be NULL */
	struct blinded_path *reply_path;

	/* The invreq, once we've looked it up. */
	struct tlv_invoice_request *invreq;
};

static struct command_result *WARN_UNUSED_RESULT
fail_inv_level(struct command *cmd,
	       const struct inv *inv,
	       enum log_level l,
	       const char *fmt, va_list ap)
{
	char *full_fmt, *msg;
	struct tlv_onionmsg_tlv *payload;
	struct tlv_invoice_error *err;

	full_fmt = tal_fmt(tmpctx, "Failed invoice");
	if (inv->inv) {
		tal_append_fmt(&full_fmt, " %s",
			       invoice_encode(tmpctx, inv->inv));
	}
	tal_append_fmt(&full_fmt, ": %s", fmt);

	msg = tal_vfmt(tmpctx, full_fmt, ap);
	plugin_log(cmd->plugin, l, "%s", msg);

	/* Only reply if they gave us a path */
	if (!inv->reply_path)
		return command_hook_success(cmd);

	/* Don't send back internal error details. */
	if (l == LOG_BROKEN)
		msg = "Internal error";

	/* Get path (maybe connect) to send reply */
	err = tlv_invoice_error_new(cmd);
	/* Remove NUL terminator */
	err->error = tal_dup_arr(err, char, msg, strlen(msg), 0);
	/* FIXME: Add suggested_value / erroneous_field! */

	payload = tlv_onionmsg_tlv_new(NULL);
	payload->invoice_error = tal_arr(payload, u8, 0);
	towire_tlv_invoice_error(&payload->invoice_error, err);
	return send_onion_reply(cmd, inv->reply_path, payload);
}

static struct command_result *WARN_UNUSED_RESULT
fail_inv(struct command *cmd,
	 const struct inv *inv,
	 const char *fmt, ...)
{
	va_list ap;
	struct command_result *ret;

	va_start(ap, fmt);
	ret = fail_inv_level(cmd, inv, LOG_DBG, fmt, ap);
	va_end(ap);

	return ret;
}

static struct command_result *WARN_UNUSED_RESULT
fail_internalerr(struct command *cmd,
		 const struct inv *inv,
		 const char *fmt, ...)
{
	va_list ap;
	struct command_result *ret;

	va_start(ap, fmt);
	ret = fail_inv_level(cmd, inv, LOG_BROKEN, fmt, ap);
	va_end(ap);

	return ret;
}

static struct command_result *pay_done(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       struct inv *inv)
{
	struct amount_msat msat = amount_msat(*inv->inv->invoice_amount);

	plugin_log(cmd->plugin, LOG_INFORM,
		   "Payed out %s for invreq %s: %.*s",
		   fmt_amount_msat(tmpctx, msat),
		   fmt_sha256(tmpctx, &inv->invreq_id),
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
	return command_hook_success(cmd);
}

static struct command_result *pay_error(struct command *cmd,
					const char *buf,
					const jsmntok_t *error,
					struct inv *inv)
{
	const jsmntok_t *msgtok = json_get_member(buf, error, "message");

	return fail_inv(cmd, inv, "pay attempt failed: %.*s",
			json_tok_full_len(msgtok),
			json_tok_full(buf, msgtok));
}

static struct command_result *listinvreqs_done(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *result,
					       struct inv *inv)
{
	const jsmntok_t *arr = json_get_member(buf, result, "invoicerequests");
	const jsmntok_t *activetok;
	bool active;
	struct amount_msat amt;
	struct out_req *req;
	struct sha256 merkle, sighash;

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *...
	 *   - if the invoice is a response to an `invoice_request`:
	 *     - MUST reject the invoice if all fields in ranges 0 to 159 and 1000000000 to 2999999999 (inclusive) do not exactly match the `invoice_request`.
	 *     - if `offer_issuer_id` is present (invoice_request for an offer):
	 *       - MUST reject the invoice if `invoice_node_id` is not equal to `offer_issuer_id`
	 *     - otherwise, if `offer_paths` is present (invoice_request for an offer without id):
	 *      - MUST reject the invoice if `invoice_node_id` is not equal to the final `blinded_node_id` it sent the `invoice_request` to.
	 *     - otherwise (invoice_request without an offer):
	 *       - MAY reject the invoice if it cannot confirm that `invoice_node_id` is correct, out-of-band.
	 */

	/* Since the invreq_id hashes all fields in those ranges, we know it matches */
	if (arr->size == 0)
		return fail_inv(cmd, inv, "Unknown invoice_request %s",
				fmt_sha256(tmpctx, &inv->invreq_id));

	activetok = json_get_member(buf, arr + 1, "active");
	if (!activetok) {
		return fail_internalerr(cmd, inv,
					"Missing active: %.*s",
					json_tok_full_len(arr),
					json_tok_full(buf, arr));
	}
	json_to_bool(buf, activetok, &active);
	if (!active)
		return fail_inv(cmd, inv, "invoice_request no longer available");

	/* We only save ones without offers to the db! */
	assert(!inv->inv->offer_issuer_id && !inv->inv->offer_paths);

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `signature` is not a valid signature
         *     using `invoice_node_id` as described in [Signature
         *     Calculation](#signature-calculation).
	 */
	if (!inv->inv->signature)
		return fail_inv(cmd, inv, "invoice missing signature");

	merkle_tlv(inv->inv->fields, &merkle);
	sighash_from_merkle("invoice", "signature", &merkle, &sighash);
	if (!check_schnorr_sig(&sighash, &inv->inv->invoice_node_id->pubkey, inv->inv->signature))
		return fail_inv(cmd, inv, "invalid invoice signature");

	/* BOLT-offers #12:
	 * - SHOULD confirm authorization if `invoice_amount`.`msat` is not
	 *   within the amount range authorized.
	 */
	/* Because there's no offer, we had to set invreq_amount */
	if (*inv->inv->invoice_amount > *inv->inv->invreq_amount)
		return fail_inv(cmd, inv, "invoice amount is too large");

	/* FIXME: Create a hook for validating the invoice_node_id! */
	amt = amount_msat(*inv->inv->invoice_amount);
	plugin_log(cmd->plugin, LOG_INFORM,
		   "Attempting payment of %s for invoice_request %s",
		   fmt_amount_msat(tmpctx, amt),
		   fmt_sha256(tmpctx, &inv->invreq_id));

	req = jsonrpc_request_start(cmd, "pay",
				    pay_done, pay_error, inv);
	json_add_string(req->js, "bolt11", invoice_encode(tmpctx, inv->inv));
	json_add_sha256(req->js, "localinvreqid", &inv->invreq_id);
	return send_outreq(req);
}

static struct command_result *listinvreqs_error(struct command *cmd,
						const char *buf,
						const jsmntok_t *err,
						struct inv *inv)
{
	return fail_internalerr(cmd, inv,
				"listinvoicerequests gave JSON error: %.*s",
				json_tok_full_len(err),
				json_tok_full(buf, err));
}

struct command_result *handle_invoice(struct command *cmd,
				      const u8 *invbin,
				      struct blinded_path *reply_path STEALS,
				      const struct secret *secret)
{
	size_t len = tal_count(invbin);
	struct inv *inv = tal(cmd, struct inv);
	struct out_req *req;
	int bad_feature;
	u64 invexpiry;

	inv->reply_path = tal_steal(inv, reply_path);

	inv->inv = fromwire_tlv_invoice(cmd, &invbin, &len);
	if (!inv->inv) {
		return fail_inv(cmd, inv,
				"Invalid invoice %s",
				tal_hex(tmpctx, invbin));
	}

	if (secret) {
		const u8 *path_secret;
		struct blinded_path **invreq_paths = inv->inv->invreq_paths;
		struct sha256 invreq_id_nopath;

		/* Necessarily, path_id is taken without the invreq_paths. */
		inv->inv->invreq_paths = NULL;
		invoice_invreq_id(inv->inv, &invreq_id_nopath);
		inv->inv->invreq_paths = invreq_paths;

		path_secret = bolt12_path_id(tmpctx, &offerblinding_base, &invreq_id_nopath);
		if (!memeq(path_secret, tal_count(path_secret),
			   secret, sizeof(*secret))) {
			if (command_dev_apis(cmd))
				return fail_inv(cmd, inv, "Wrong blinded path (invreq_id_nopath = %s, path_secret = %s, secret = %s)",
						fmt_sha256(tmpctx, &invreq_id_nopath),
						tal_hex(tmpctx, path_secret),
						fmt_secret(tmpctx, secret));
			/* Normally, "I don't know what you're talking about!" */
			return fail_inv(cmd, inv, "Unknown invoice_request %s",
					fmt_sha256(tmpctx, &inv->invreq_id));
		}
	} else {
		/* Didn't use path.  Was it supposed to? */
		if (inv->inv->invreq_paths) {
			if (command_dev_apis(cmd))
				return fail_inv(cmd, inv, "Expected to use invreq_path!");
			/* Normally, "I don't know what you're talking about!" */
			return fail_inv(cmd, inv, "Unknown invoice_request %s",
					fmt_sha256(tmpctx, &inv->invreq_id));
		}
	}

	invoice_invreq_id(inv->inv, &inv->invreq_id);

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *  - MUST reject the invoice if `invoice_amount` is not present.
	 *  - MUST reject the invoice if `invoice_created_at` is not present.
	 *  - MUST reject the invoice if `invoice_payment_hash` is not present.
	 *  - MUST reject the invoice if `invoice_node_id` is not present.
	 */
	if (!inv->inv->invoice_amount)
		return fail_inv(cmd, inv, "Missing invoice_amount");
	if (!inv->inv->invoice_created_at)
		return fail_inv(cmd, inv, "Missing invoice_created_at");
	if (!inv->inv->invoice_payment_hash)
		return fail_inv(cmd, inv, "Missing invoice_payment_hash");
	if (!inv->inv->invoice_node_id)
		return fail_inv(cmd, inv, "Missing invoice_node_id");

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *...
	 *  - if `invoice_features` contains unknown _odd_ bits that are non-zero:
	 *    - MUST ignore the bit.
	 *  - if `invoice_features` contains unknown _even_ bits that are non-zero:
	 *    - MUST reject the invoice.
	 */
	bad_feature = features_unsupported(plugin_feature_set(cmd->plugin),
					   inv->inv->invoice_features,
					   BOLT12_INVOICE_FEATURE);
	if (bad_feature != -1) {
		return fail_inv(cmd, inv,
				"Unsupported invoice feature %i",
				bad_feature);
	}

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *...
	 *  - if `invoice_relative_expiry` is present:
	 *    - MUST reject the invoice if the current time since 1970-01-01 UTC is greater than `invoice_created_at` plus `seconds_from_creation`.
	 *  - otherwise:
	 *    - MUST reject the invoice if the current time since 1970-01-01 UTC is greater than `invoice_created_at` plus 7200.
	 */
	if (inv->inv->invoice_relative_expiry)
		invexpiry = *inv->inv->invoice_created_at + *inv->inv->invoice_relative_expiry;
	else
		invexpiry = *inv->inv->invoice_created_at + BOLT12_DEFAULT_REL_EXPIRY;
	if (time_now().ts.tv_sec > invexpiry)
		return fail_inv(cmd, inv, "Expired invoice");

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *...
	 *  - MUST reject the invoice if `invoice_paths` is not present or is empty.
	 *  - MUST reject the invoice if `num_hops` is 0 in any `blinded_path` in `invoice_paths`.
	 *  - MUST reject the invoice if `invoice_blindedpay` is not present.
	 *  - MUST reject the invoice if `invoice_blindedpay` does not contain exactly one `blinded_payinfo` per `invoice_paths`.`blinded_path`.
	 */
	if (!inv->inv->invoice_paths)
		return fail_inv(cmd, inv, "Missing invoice_paths");
	for (size_t i = 0; i < tal_count(inv->inv->invoice_paths); i++) {
		if (tal_count(inv->inv->invoice_paths[i]->path) == 0)
			return fail_inv(cmd, inv, "Empty path in invoice_paths");
	}
	if (!inv->inv->invoice_blindedpay)
		return fail_inv(cmd, inv, "Missing invoice_blindedpay");
	if (tal_count(inv->inv->invoice_blindedpay)
	    != tal_count(inv->inv->invoice_paths))
		return fail_inv(cmd, inv,
				"Mismatch between invoice_blindedpay and invoice_paths");

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *...
	 *  - For each `invoice_blindedpay`.`payinfo`:
	 *     - MUST NOT use the corresponding `invoice_paths`.`path` if
	 *       `payinfo`.`features` has any unknown even bits set.
	 *     - MUST reject the invoice if this leaves no usable paths.
	 */
	for (size_t i = 0; i < tal_count(inv->inv->invoice_blindedpay); i++) {
		bad_feature = features_unsupported(plugin_feature_set(cmd->plugin),
						   inv->inv->invoice_blindedpay[i]->features,
						   /* FIXME: Technically a different feature set? */
						   BOLT12_INVOICE_FEATURE);
		if (bad_feature == -1)
			continue;

		tal_arr_remove(&inv->inv->invoice_paths, i);
		tal_arr_remove(&inv->inv->invoice_blindedpay, i);
		i--;
	}
	if (tal_count(inv->inv->invoice_paths) == 0) {
		return fail_inv(cmd, inv,
				"Unsupported feature for all paths (%i)",
				bad_feature);
	}

	/* Now find the invoice_request. */
	req = jsonrpc_request_start(cmd, "listinvoicerequests",
				    listinvreqs_done, listinvreqs_error, inv);
	json_add_sha256(req->js, "invreq_id", &inv->invreq_id);
	return send_outreq(req);
}

