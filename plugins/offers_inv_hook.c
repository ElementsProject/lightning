#include "config.h"
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12_merkle.h>
#include <common/type_to_string.h>
#include <plugins/offers.h>
#include <plugins/offers_inv_hook.h>
#include <secp256k1_schnorrsig.h>

/* We need to keep the reply path around so we can reply if error */
struct inv {
	struct tlv_invoice *inv;

	/* May be NULL */
	struct tlv_obs2_onionmsg_payload_reply_path *obs2_reply_path;
	struct tlv_onionmsg_payload_reply_path *reply_path;

	/* The offer, once we've looked it up. */
	struct tlv_offer *offer;
};

static struct command_result *WARN_UNUSED_RESULT
fail_inv_level(struct command *cmd,
	       const struct inv *inv,
	       enum log_level l,
	       const char *fmt, va_list ap)
{
	char *full_fmt, *msg;
	struct tlv_invoice_error *err;
	u8 *errdata;

	full_fmt = tal_fmt(tmpctx, "Failed invoice %s",
			   invoice_encode(tmpctx, inv->inv));
	if (inv->inv->offer_id)
		tal_append_fmt(&full_fmt, " for offer %s",
			       type_to_string(tmpctx, struct sha256,
					      inv->inv->offer_id));
	tal_append_fmt(&full_fmt, ": %s", fmt);

	msg = tal_vfmt(tmpctx, full_fmt, ap);
	plugin_log(cmd->plugin, l, "%s", msg);

	/* Only reply if they gave us a path */
	if (!inv->reply_path && !inv->obs2_reply_path)
		return command_hook_success(cmd);

	/* Don't send back internal error details. */
	if (l == LOG_BROKEN)
		msg = "Internal error";

	err = tlv_invoice_error_new(cmd);
	/* Remove NUL terminator */
	err->error = tal_dup_arr(err, char, msg, strlen(msg), 0);
	/* FIXME: Add suggested_value / erroneous_field! */

	errdata = tal_arr(cmd, u8, 0);
	towire_invoice_error(&errdata, err);
	return send_onion_reply(cmd, inv->reply_path, inv->obs2_reply_path,
				"invoice_error", errdata);
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

#define inv_must_have(cmd_, i_, fld_)				\
	test_field(cmd_, i_, i_->inv->fld_ != NULL, #fld_, "missing")
#define inv_must_not_have(cmd_, i_, fld_)				\
	test_field(cmd_, i_, i_->inv->fld_ == NULL, #fld_, "unexpected")
#define inv_must_equal_offer(cmd_, i_, fld_)				\
	test_field_eq(cmd_, i_, i_->inv->fld_, i_->offer->fld_, #fld_)

static struct command_result *
test_field(struct command *cmd,
	   const struct inv *inv,
	   bool test, const char *fieldname, const char *what)
{
	if (!test)
		return fail_inv(cmd, inv, "%s %s", what, fieldname);
	return NULL;
}

static struct command_result *
test_field_eq(struct command *cmd,
	      const struct inv *inv,
	      const tal_t *invfield,
	      const tal_t *offerfield,
	      const char *fieldname)
{
	if (invfield && !offerfield)
		return fail_inv(cmd, inv, "Unexpected %s", fieldname);
	if (!invfield && offerfield)
		return fail_inv(cmd, inv, "Expected %s", fieldname);
	if (!memeq(invfield, tal_bytelen(invfield),
		   offerfield, tal_bytelen(offerfield)))
		return fail_inv(cmd, inv, "Different %s", fieldname);
	return NULL;
}

static struct command_result *pay_done(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       struct inv *inv)
{
	struct amount_msat msat = amount_msat(*inv->inv->amount);

	plugin_log(cmd->plugin, LOG_INFORM,
		   "Payed out %s for offer %s%s: %.*s",
		   type_to_string(tmpctx, struct amount_msat, &msat),
		   type_to_string(tmpctx, struct sha256, inv->inv->offer_id),
		   inv->offer->refund_for ? " (refund)": "",
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

static struct command_result *listoffers_done(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct inv *inv)
{
	const jsmntok_t *arr = json_get_member(buf, result, "offers");
	const jsmntok_t *offertok, *activetok, *b12tok;
	bool active;
	struct amount_msat amt;
	char *fail;
	struct out_req *req;
	struct command_result *err;

	/* BOLT-offers #12:
	 * - otherwise if `offer_id` is set:
	 *   - MUST reject the invoice if the `offer_id` does not refer an
	 *     unexpired offer with `send_invoice`
	 */
	if (arr->size == 0)
		return fail_inv(cmd, inv, "Unknown offer");

	plugin_log(cmd->plugin, LOG_INFORM,
		   "Attempting payment of offer %.*s",
		   json_tok_full_len(result),
		   json_tok_full(buf, result));

	offertok = arr + 1;
	activetok = json_get_member(buf, offertok, "active");
	if (!activetok) {
		return fail_internalerr(cmd, inv,
					"Missing active: %.*s",
					json_tok_full_len(offertok),
					json_tok_full(buf, offertok));
	}
	json_to_bool(buf, activetok, &active);
	if (!active)
		return fail_inv(cmd, inv, "Offer no longer available");

	b12tok = json_get_member(buf, offertok, "bolt12");
	if (!b12tok) {
		return fail_internalerr(cmd, inv,
					"Missing bolt12: %.*s",
					json_tok_full_len(offertok),
					json_tok_full(buf, offertok));
	}
	inv->offer = offer_decode(inv,
				 buf + b12tok->start,
				 b12tok->end - b12tok->start,
				 plugin_feature_set(cmd->plugin),
				 chainparams, &fail);
	if (!inv->offer) {
		return fail_internalerr(cmd, inv,
					"Invalid offer: %s (%.*s)",
					fail,
					json_tok_full_len(offertok),
					json_tok_full(buf, offertok));
	}

	if (inv->offer->absolute_expiry
	    && time_now().ts.tv_sec >= *inv->offer->absolute_expiry) {
		/* FIXME: do deloffer to disable it */
		return fail_inv(cmd, inv, "Offer expired");
	}

	if (!inv->offer->send_invoice) {
		return fail_inv(cmd, inv, "Offer did not expect invoice");
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice unless the following fields are equal
	 *   or unset exactly as they are in the `offer`:
	 *   - `refund_for`
	 *   - `description`
	 */
	err = inv_must_equal_offer(cmd, inv, refund_for);
	if (err)
		return err;
	err = inv_must_equal_offer(cmd, inv, description);
	if (err)
		return err;

	/* BOLT-offers #12:
	 * - if the offer had a `quantity_min` or `quantity_max` field:
	 *   - MUST fail the request if there is no `quantity` field.
	 *   - MUST fail the request if there is `quantity` is not within
	 *     that (inclusive) range.
	 * - otherwise:
	 *   - MUST fail the request if there is a `quantity` field.
	 */
	if (inv->offer->quantity_min || inv->offer->quantity_max) {
		err = inv_must_have(cmd, inv, quantity);
		if (err)
			return err;

		if (inv->offer->quantity_min &&
		    *inv->inv->quantity < *inv->offer->quantity_min) {
			return fail_inv(cmd, inv,
					"quantity %"PRIu64 " < %"PRIu64,
					*inv->inv->quantity,
					*inv->offer->quantity_min);
		}

		if (inv->offer->quantity_max &&
		    *inv->inv->quantity > *inv->offer->quantity_max) {
			return fail_inv(cmd, inv,
					"quantity %"PRIu64" > %"PRIu64,
					*inv->inv->quantity,
					*inv->offer->quantity_max);
		}
	} else {
		err = inv_must_not_have(cmd, inv, quantity);
		if (err)
			return err;
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `msat` is not present.
	 */
	err = inv_must_have(cmd, inv, amount);
	if (err)
		return err;

	/* FIXME: Handle alternate currency conversion here! */
	if (inv->offer->currency)
		return fail_inv(cmd, inv, "FIXME: support currency");

	amt = amount_msat(*inv->inv->amount);
	/* If you send an offer without an amount, you want to give away
	 * unlimited money.  Err, ok? */
	if (inv->offer->amount) {
		struct amount_msat expected = amount_msat(*inv->offer->amount);

		/* We could allow invoices for less, I suppose. */
		if (!amount_msat_eq(expected, amt))
			return fail_inv(cmd, inv, "Expected invoice for %s",
					fmt_amount_msat(tmpctx, expected));
	}

	plugin_log(cmd->plugin, LOG_INFORM,
		   "Attempting payment of %s for offer %s%s",
		   type_to_string(tmpctx, struct amount_msat, &amt),
		   type_to_string(tmpctx, struct sha256, inv->inv->offer_id),
		   inv->offer->refund_for ? " (refund)": "");

	req = jsonrpc_request_start(cmd->plugin, cmd, "pay",
				    pay_done, pay_error, inv);
	json_add_string(req->js, "bolt11", invoice_encode(tmpctx, inv->inv));
	json_add_sha256(req->js, "localofferid", inv->inv->offer_id);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *listoffers_error(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *err,
					       struct inv *inv)
{
	return fail_internalerr(cmd, inv,
				"listoffers gave JSON error: %.*s",
				json_tok_full_len(err),
				json_tok_full(buf, err));
}

struct command_result *handle_invoice(struct command *cmd,
				      const u8 *invbin,
				      struct tlv_onionmsg_payload_reply_path *reply_path STEALS,
				      struct tlv_obs2_onionmsg_payload_reply_path *obs2_reply_path STEALS)
{
	size_t len = tal_count(invbin);
	struct inv *inv = tal(cmd, struct inv);
	struct out_req *req;
	struct command_result *err;
	int bad_feature;
	struct sha256 m, shash;

	inv->obs2_reply_path = tal_steal(inv, obs2_reply_path);
	inv->reply_path = tal_steal(inv, reply_path);

	inv->inv = tlv_invoice_new(cmd);
	if (!fromwire_invoice(&invbin, &len, inv->inv)) {
		return fail_inv(cmd, inv,
				"Invalid invoice %s",
				tal_hex(tmpctx, invbin));
	}

	/* BOLT-offers #12:
	 *
	 * The reader of an invoice_request:
	 *...
	 *   - MUST fail the request if `features` contains unknown even bits.
	 */
	bad_feature = features_unsupported(plugin_feature_set(cmd->plugin),
					   inv->inv->features,
					   BOLT11_FEATURE);
	if (bad_feature != -1) {
		return fail_inv(cmd, inv,
				"Unsupported inv feature %i",
				bad_feature);
	}

	/* BOLT-offers #12:
	 *
	 * The reader of an invoice_request:
	 *...
	 *   - if `chain` is not present:
	 *     - MUST fail the request if bitcoin is not a supported chain.
	 *   - otherwise:
	 *     - MUST fail the request if `chain` is not a supported chain.
	 */
	if (!bolt12_chain_matches(inv->inv->chain, chainparams)) {
		return fail_inv(cmd, inv,
				"Wrong chain %s",
				tal_hex(tmpctx, inv->inv->chain));
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `signature` is not a valid signature
	 *   using `node_id` as described in
	 *   [Signature Calculation](#signature-calculation).
	 */
	err = inv_must_have(cmd, inv, node_id);
	if (err)
		return err;

	err = inv_must_have(cmd, inv, signature);
	if (err)
		return err;

	merkle_tlv(inv->inv->fields, &m);
	sighash_from_merkle("invoice", "signature", &m, &shash);
	if (secp256k1_schnorrsig_verify(secp256k1_ctx,
					inv->inv->signature->u8,
					shash.u.u8,
					&inv->inv->node_id->pubkey) != 1) {
		return fail_inv(cmd, inv, "Bad signature");
	}

	/* We don't pay random invoices off the internet, sorry. */
	err = inv_must_have(cmd, inv, offer_id);
	if (err)
		return err;

	/* Now find the offer. */
	req = jsonrpc_request_start(cmd->plugin, cmd, "listoffers",
				    listoffers_done, listoffers_error, inv);
	json_add_sha256(req->js, "offer_id", inv->inv->offer_id);
	return send_outreq(cmd->plugin, req);
}

