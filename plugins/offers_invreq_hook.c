#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <ccan/tal/str/str.h>
#include <common/bech32_util.h>
#include <common/bolt12_merkle.h>
#include <common/iso4217.h>
#include <common/json_stream.h>
#include <common/overflows.h>
#include <common/type_to_string.h>
#include <plugins/offers.h>
#include <plugins/offers_invreq_hook.h>
#include <secp256k1_schnorrsig.h>
#include <sodium.h>

/* We need to keep the reply path around so we can reply with invoice */
struct invreq {
	struct tlv_invoice_request *invreq;
	struct tlv_onionmsg_payload_reply_path *reply_path;
	struct tlv_obs2_onionmsg_payload_reply_path *obs2_reply_path;

	/* The offer, once we've looked it up. */
	struct tlv_offer *offer;

	/* The invoice we're preparing (can require additional lookups) */
	struct tlv_invoice *inv;

	/* The preimage for the invoice. */
	struct preimage preimage;
};

static struct command_result *WARN_UNUSED_RESULT
fail_invreq_level(struct command *cmd,
		  const struct invreq *invreq,
		  enum log_level l,
		  const char *fmt, va_list ap)
{
	char *full_fmt, *msg;
	struct tlv_invoice_error *err;
	u8 *errdata;

	full_fmt = tal_fmt(tmpctx, "Failed invoice_request %s",
			   invrequest_encode(tmpctx, invreq->invreq));
	if (invreq->invreq->offer_id)
		tal_append_fmt(&full_fmt, " for offer %s",
			       type_to_string(tmpctx, struct sha256,
					      invreq->invreq->offer_id));
	tal_append_fmt(&full_fmt, ": %s", fmt);

	msg = tal_vfmt(tmpctx, full_fmt, ap);
	plugin_log(cmd->plugin, l, "%s", msg);

	/* Don't send back internal error details. */
	if (l == LOG_BROKEN)
		msg = "Internal error";

	err = tlv_invoice_error_new(cmd);
	/* Remove NUL terminator */
	err->error = tal_dup_arr(err, char, msg, strlen(msg), 0);
	/* FIXME: Add suggested_value / erroneous_field! */

	errdata = tal_arr(cmd, u8, 0);
	towire_invoice_error(&errdata, err);
	return send_onion_reply(cmd, invreq->reply_path, invreq->obs2_reply_path,
				"invoice_error", errdata);
}

static struct command_result *WARN_UNUSED_RESULT PRINTF_FMT(3,4)
fail_invreq(struct command *cmd,
	    const struct invreq *invreq,
	    const char *fmt, ...)
{
	va_list ap;
	struct command_result *ret;

	va_start(ap, fmt);
	ret = fail_invreq_level(cmd, invreq, LOG_DBG, fmt, ap);
	va_end(ap);

	return ret;
}

static struct command_result *WARN_UNUSED_RESULT
fail_internalerr(struct command *cmd,
		 const struct invreq *invreq,
		 const char *fmt, ...)
{
	va_list ap;
	struct command_result *ret;

	va_start(ap, fmt);
	ret = fail_invreq_level(cmd, invreq, LOG_BROKEN, fmt, ap);
	va_end(ap);

	return ret;
}

#define invreq_must_have(cmd_, ir_, fld_)				\
	test_field(cmd_, ir_, ir_->invreq->fld_ != NULL, #fld_, "missing")
#define invreq_must_not_have(cmd_, ir_, fld_)				\
	test_field(cmd_, ir_, ir_->invreq->fld_ == NULL, #fld_, "unexpected")

static struct command_result *
test_field(struct command *cmd,
	   const struct invreq *invreq,
	   bool test, const char *fieldname, const char *what)
{
	if (!test)
		return fail_invreq(cmd, invreq, "%s %s", what, fieldname);
	return NULL;
}

/* BOLT-offers-recurrence #12:
 * - if the invoice corresponds to an offer with `recurrence`:
 * ...
 *   - if it sets `relative_expiry`:
 *     - MUST NOT set `relative_expiry` `seconds_from_creation` more than the
 *       number of seconds after `created_at` that payment for this period will
 *       be accepted.
 */
static void set_recurring_inv_expiry(struct tlv_invoice *inv, u64 last_pay)
{
	inv->relative_expiry = tal(inv, u32);

	/* Don't give them a 0 second invoice, even if it's true. */
	if (last_pay <= *inv->created_at)
		*inv->relative_expiry = 1;
	else
		*inv->relative_expiry = last_pay - *inv->created_at;

	/* FIXME: Shorten expiry if we're doing currency conversion! */
}

/* We rely on label forms for uniqueness. */
static void json_add_label(struct json_stream *js,
			   const struct sha256 *offer_id,
			   const struct point32 *payer_key,
			   const u32 counter)
{
	char *label;

	label = tal_fmt(tmpctx, "%s-%s-%u",
			type_to_string(tmpctx, struct sha256, offer_id),
			type_to_string(tmpctx, struct point32,
				       payer_key),
			counter);
	json_add_string(js, "label", label);
}

/* Note: this can actually happen if a single-use offer is already
 * used at the same time between the check and now.
 */
static struct command_result *error(struct command *cmd,
				    const char *buf,
				    const jsmntok_t *err,
				    struct invreq *ir)
{
	return fail_internalerr(cmd, ir,
				"Got JSON error: %.*s",
				json_tok_full_len(err),
				json_tok_full(buf, err));
}

/* We can fail to create the invoice if we've already done so. */
static struct command_result *createinvoice_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct invreq *ir)
{
	char *hrp;
	u8 *rawinv;
	const jsmntok_t *t;

	/* We have a signed invoice, use it as a reply. */
	t = json_get_member(buf, result, "bolt12");
	if (!from_bech32_charset(tmpctx, buf + t->start, t->end - t->start,
				 &hrp, &rawinv)) {
		return fail_internalerr(cmd, ir,
					"Bad creatinvoice bolt12 string %.*s",
					json_tok_full_len(t),
					json_tok_full(buf, t));
	}

	return send_onion_reply(cmd, ir->reply_path, ir->obs2_reply_path,
				"invoice", rawinv);
}

static struct command_result *createinvoice_error(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *err,
						  struct invreq *ir)
{
	u32 code;

	/* If it already exists, we can reuse its bolt12 directly. */
	if (json_scan(tmpctx, buf, err,
		      "{code:%}", JSON_SCAN(json_to_u32, &code)) == NULL
	    && code == INVOICE_LABEL_ALREADY_EXISTS) {
		return createinvoice_done(cmd, buf,
					  json_get_member(buf, err, "data"), ir);
	}
	return error(cmd, buf, err, ir);
}

static struct command_result *create_invoicereq(struct command *cmd,
						struct invreq *ir)
{
	struct out_req *req;

	/* Now, write invoice to db (returns the signed version) */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoice",
				    createinvoice_done, createinvoice_error, ir);

	json_add_string(req->js, "invstring", invoice_encode(tmpctx, ir->inv));
	json_add_preimage(req->js, "preimage", &ir->preimage);
	json_add_label(req->js, ir->inv->offer_id, ir->inv->payer_key,
		       ir->inv->recurrence_counter
		       ? *ir->inv->recurrence_counter : 0);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *check_period(struct command *cmd,
					   struct invreq *ir,
					   u64 basetime)
{
	u64 period_idx;
	u64 paywindow_start, paywindow_end;
	struct command_result *err;

	/* If we have a recurrence base, that overrides. */
	if (ir->offer->recurrence_base)
		basetime = ir->offer->recurrence_base->basetime;

	/* BOLT-offers-recurrence #12:
	 * - if the invoice corresponds to an offer with `recurrence`:
	 *   - MUST set `recurrence_basetime` to the start of period #0 as
	 *     calculated by [Period Calculation](#offer-period-calculation).
	 */
	ir->inv->recurrence_basetime = tal_dup(ir->inv, u64, &basetime);

	period_idx = *ir->invreq->recurrence_counter;

	/* BOLT-offers-recurrence #12:
	 * - if the offer had `recurrence_base` and `start_any_period`
	 *   was 1:
	 *   - MUST fail the request if there is no `recurrence_start`
	 *     field.
	 *   - MUST consider the period index for this request to be the
	 *     `recurrence_start` field plus the `recurrence_counter`
	 *     `counter` field.
	 */
	if (ir->offer->recurrence_base
	    && ir->offer->recurrence_base->start_any_period) {
		err = invreq_must_have(cmd, ir, recurrence_start);
		if (err)
			return err;
		period_idx += *ir->invreq->recurrence_start;

		/* BOLT-offers-recurrence #12:
		 * - MUST set (or not set) `recurrence_start` exactly as the
		 *   invoice_request did.
		 */
		ir->inv->recurrence_start
			= tal_dup(ir->inv, u32, ir->invreq->recurrence_start);
	} else {
		/* BOLT-offers-recurrence #12:
		 *
		 * - otherwise:
		 *   - MUST fail the request if there is a `recurrence_start`
		 *     field.
		 *   - MUST consider the period index for this request to be the
		 *     `recurrence_counter` `counter` field.
		 */
		err = invreq_must_not_have(cmd, ir, recurrence_start);
		if (err)
			return err;
	}

	/* BOLT-offers-recurrence #12:
	 * - if the offer has a `recurrence_limit`:
	 *   - MUST fail the request if the period index is greater than
	 *     `max_period`.
	 */
	if (ir->offer->recurrence_limit
	    && period_idx > *ir->offer->recurrence_limit) {
		return fail_invreq(cmd, ir,
				   "period_index %"PRIu64" too great",
				   period_idx);
	}

	offer_period_paywindow(ir->offer->recurrence,
			       ir->offer->recurrence_paywindow,
			       ir->offer->recurrence_base,
			       basetime, period_idx,
			       &paywindow_start, &paywindow_end);
	if (*ir->inv->created_at < paywindow_start) {
		return fail_invreq(cmd, ir,
				   "period_index %"PRIu64
				   " too early (start %"PRIu64")",
				   period_idx,
				   paywindow_start);
	}
	if (*ir->inv->created_at > paywindow_end) {
		return fail_invreq(cmd, ir,
				   "period_index %"PRIu64
				   " too late (ended %"PRIu64")",
				   period_idx,
				   paywindow_end);
	}

	set_recurring_inv_expiry(ir->inv, paywindow_end);

	/* BOLT-offers-recurrence #12:
	 *
	 * - if `recurrence_counter` is non-zero:
	 *...
	 *   - if the offer had a `recurrence_paywindow`:
	 *...
	 *     - if `proportional_amount` is 1:
	 *       - MUST adjust the *base invoice amount* proportional to time
	 *         remaining in the period.
	 */
	if (*ir->invreq->recurrence_counter != 0
	    && ir->offer->recurrence_paywindow
	    && ir->offer->recurrence_paywindow->proportional_amount == 1) {
		u64 start = offer_period_start(basetime, period_idx,
					       ir->offer->recurrence);
		u64 end = offer_period_start(basetime, period_idx + 1,
					     ir->offer->recurrence);

		if (*ir->inv->created_at > start) {
			*ir->inv->amount
				*= (double)((*ir->inv->created_at - start)
					    / (end - start));
			/* Round up to make it non-zero if necessary. */
			if (*ir->inv->amount == 0)
				*ir->inv->amount = 1;
		}
	}

	return create_invoicereq(cmd, ir);
}

static struct command_result *prev_invoice_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct invreq *ir)
{
	const jsmntok_t *status, *arr, *b12;
	struct tlv_invoice *previnv;
	char *fail;

	/* Was it created? */
	arr = json_get_member(buf, result, "invoices");
	if (arr->size == 0) {
		return fail_invreq(cmd, ir,
				   "No previous invoice #%u",
				   *ir->inv->recurrence_counter - 1);
	}

	/* Was it paid? */
	status = json_get_member(buf, arr + 1, "status");
	if (!json_tok_streq(buf, status, "paid")) {
		return fail_invreq(cmd, ir,
				   "Previous invoice #%u status %.*s",
				   *ir->inv->recurrence_counter - 1,
				   json_tok_full_len(status),
				   json_tok_full(buf, status));
	}

	/* Decode it */
	b12 = json_get_member(buf, arr + 1, "bolt12");
	if (!b12) {
		return fail_internalerr(cmd, ir,
					"Previous invoice #%u no bolt12 (%.*s)",
					*ir->inv->recurrence_counter - 1,
					json_tok_full_len(arr + 1),
					json_tok_full(buf, arr + 1));
	}
	previnv = invoice_decode(tmpctx, buf + b12->start, b12->end - b12->start,
				 plugin_feature_set(cmd->plugin),
				 chainparams, &fail);
	if (!previnv) {
		return fail_internalerr(cmd, ir,
					"Previous invoice %.*s can't decode?",
					json_tok_full_len(b12),
					json_tok_full(buf, b12));
	}
	if (!previnv->recurrence_basetime) {
		return fail_internalerr(cmd, ir,
			   "Previous invoice %.*s no recurrence_basetime?",
			   json_tok_full_len(b12), json_tok_full(buf, b12));
	}
	return check_period(cmd, ir, *previnv->recurrence_basetime);
}

/* Now, we need to check the previous invoice was paid, and maybe get timebase */
static struct command_result *check_previous_invoice(struct command *cmd,
						     struct invreq *ir)
{
	struct out_req *req;

	/* No previous?  Just pass through */
	if (*ir->invreq->recurrence_counter == 0)
		return check_period(cmd, ir, *ir->inv->created_at);

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "listinvoices",
				    prev_invoice_done,
				    error,
				    ir);
	json_add_label(req->js,
		       ir->invreq->offer_id,
		       ir->invreq->payer_key,
		       *ir->invreq->recurrence_counter - 1);
	return send_outreq(cmd->plugin, req);
}

/* BOLT-offers #12:
 *  - MUST fail the request if `payer_signature` is not correct.
 */
static bool check_payer_sig(const struct tlv_invoice_request *invreq,
			    const struct point32 *payer_key,
			    const struct bip340sig *sig)
{
	struct sha256 merkle, sighash;
	merkle_tlv(invreq->fields, &merkle);
	sighash_from_merkle("invoice_request", "payer_signature",
			    &merkle, &sighash);

	return secp256k1_schnorrsig_verify(secp256k1_ctx,
					   sig->u8,
					   sighash.u.u8, &payer_key->pubkey) == 1;
}

static struct command_result *invreq_amount_by_quantity(struct command *cmd,
							const struct invreq *ir,
							u64 *raw_amt)
{
	assert(ir->offer->amount);

	/* BOLT-offers #12:
	 *     - MUST calculate the *base invoice amount* using the offer `amount`:
	 */
	*raw_amt = *ir->offer->amount;

	/* BOLT-offers #12:
	 * - if request contains `quantity`, multiply by `quantity`.
	 */
	if (ir->invreq->quantity) {
		if (mul_overflows_u64(*ir->invreq->quantity, *raw_amt)) {
			return fail_invreq(cmd, ir,
					   "quantity %"PRIu64
					   " causes overflow",
					   *ir->invreq->quantity);
		}
		*raw_amt *= *ir->invreq->quantity;
	}

	return NULL;
}

/* The non-currency-converting case. */
static struct command_result *invreq_base_amount_simple(struct command *cmd,
							const struct invreq *ir,
							struct amount_msat *amt)
{
	struct command_result *err;

	if (ir->offer->amount) {
		u64 raw_amount;
		assert(!ir->offer->currency);
		err = invreq_amount_by_quantity(cmd, ir, &raw_amount);
		if (err)
			return err;

		*amt = amount_msat(raw_amount);
	} else {
		/* BOLT-offers-recurrence #12:
		 *
		 * - otherwise:
		 * - MUST fail the request if it does not contain `amount`.
		 * - MUST use the request `amount` as the *base invoice amount*.
		 *   (Note: invoice amount can be further modified by recurrence
		 *    below)
		 */
		err = invreq_must_have(cmd, ir, amount);
		if (err)
			return err;

		*amt = amount_msat(*ir->invreq->amount);
	}
	return NULL;
}

static struct command_result *handle_amount_and_recurrence(struct command *cmd,
							   struct invreq *ir,
							   struct amount_msat base_inv_amount)
{
	/* BOLT-offers #12:
	 * - if the offer included `amount`:
	 *...
	 *   - if the request contains `amount`:
	 *     - MUST fail the request if its `amount` is less than the
	 *       *base invoice amount*.
	 */
	if (ir->offer->amount && ir->invreq->amount) {
		if (amount_msat_less(amount_msat(*ir->invreq->amount), base_inv_amount)) {
			return fail_invreq(cmd, ir, "Amount must be at least %s",
					   type_to_string(tmpctx, struct amount_msat,
							  &base_inv_amount));
		}
		/* BOLT-offers #12:
		 * - MAY fail the request if its `amount` is much greater than
		 *   the *base invoice amount*.
		 */
		/* Much == 5? Easier to divide and compare, than multiply. */
		if (amount_msat_greater(amount_msat_div(amount_msat(*ir->invreq->amount), 5),
					base_inv_amount)) {
			return fail_invreq(cmd, ir, "Amount vastly exceeds %s",
					   type_to_string(tmpctx, struct amount_msat,
							  &base_inv_amount));
		}
		/* BOLT-offers #12:
		 * - MUST use the request's `amount` as the *base invoice
		 *   amount*.
		 */
		base_inv_amount = amount_msat(*ir->invreq->amount);
	}

	/* This may be adjusted by recurrence if proportional_amount set */
	ir->inv->amount = tal_dup(ir->inv, u64,
				  &base_inv_amount.millisatoshis); /* Raw: wire protocol */

	/* Last of all, we handle recurrence details, which often requires
	 * further lookups. */

	/* BOLT-offers-recurrence #12:
	 * - MUST set (or not set) `recurrence_counter` exactly as the
	 *   invoice_request did.
	 */
	if (ir->invreq->recurrence_counter) {
		ir->inv->recurrence_counter = ir->invreq->recurrence_counter;
		return check_previous_invoice(cmd, ir);
	}
	/* We're happy with 2 hours timeout (default): they can always
	 * request another. */

	/* FIXME: Fallbacks? */
	return create_invoicereq(cmd, ir);
}

static struct command_result *currency_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct invreq *ir)
{
	const jsmntok_t *msat = json_get_member(buf, result, "msat");
	struct amount_msat amount;

	/* Fail in this case, forwarding warnings. */
	if (!msat)
		return fail_internalerr(cmd, ir,
					"Cannot convert currency %.*s: %.*s",
					(int)tal_bytelen(ir->offer->currency),
					(const char *)ir->offer->currency,
					json_tok_full_len(result),
					json_tok_full(buf, result));

	if (!json_to_msat(buf, msat, &amount))
		return fail_internalerr(cmd, ir,
					"Bad convert for currency %.*s: %.*s",
					(int)tal_bytelen(ir->offer->currency),
					(const char *)ir->offer->currency,
					json_tok_full_len(msat),
					json_tok_full(buf, msat));

	return handle_amount_and_recurrence(cmd, ir, amount);
}

static struct command_result *convert_currency(struct command *cmd,
					       struct invreq *ir)
{
	struct out_req *req;
	u64 raw_amount;
	double double_amount;
	struct command_result *err;
	const struct iso4217_name_and_divisor *iso4217;

	assert(ir->offer->currency);

	/* Multiply by quantity *first*, for best precision */
	err = invreq_amount_by_quantity(cmd, ir, &raw_amount);
	if (err)
		return err;

	/* BOLT-offers #12:
	 * - MUST calculate the *base invoice amount* using the offer
	 *  `amount`:
	 *   - if offer `currency` is not the invoice currency, convert
	 *     to the invoice currency.
	 */
	iso4217 = find_iso4217(ir->offer->currency,
			       tal_bytelen(ir->offer->currency));
	/* We should not create offer with unknown currency! */
	if (!iso4217)
		return fail_internalerr(cmd, ir,
					"Unknown offer currency %.*s",
					(int)tal_bytelen(ir->offer->currency),
					ir->offer->currency);
	double_amount = (double)raw_amount;
	for (size_t i = 0; i < iso4217->minor_unit; i++)
		double_amount /= 10;

	req = jsonrpc_request_start(cmd->plugin, cmd, "currencyconvert",
				    currency_done, error, ir);
	json_add_stringn(req->js, "currency",
			 (const char *)ir->offer->currency,
			 tal_bytelen(ir->offer->currency));
	json_add_member(req->js, "amount", false, "%f", double_amount);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *listoffers_done(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct invreq *ir)
{
	const jsmntok_t *arr = json_get_member(buf, result, "offers");
	const jsmntok_t *offertok, *activetok, *b12tok;
	bool active;
	char *fail;
	struct command_result *err;
	struct amount_msat amt;

	/* BOLT-offers #12:
	 *
	 * - MUST fail the request if the `offer_id` does not refer to an
	 *   unexpired offer.
	 */
	if (arr->size == 0)
		return fail_invreq(cmd, ir, "Unknown offer");

	offertok = arr + 1;

	activetok = json_get_member(buf, offertok, "active");
	if (!activetok) {
		return fail_internalerr(cmd, ir,
					"Missing active: %.*s",
					json_tok_full_len(offertok),
					json_tok_full(buf, offertok));
	}
	json_to_bool(buf, activetok, &active);
	if (!active)
		return fail_invreq(cmd, ir, "Offer no longer available");

	b12tok = json_get_member(buf, offertok, "bolt12");
	if (!b12tok) {
		return fail_internalerr(cmd, ir,
					"Missing bolt12: %.*s",
					json_tok_full_len(offertok),
					json_tok_full(buf, offertok));
	}
	ir->offer = offer_decode(ir,
				 buf + b12tok->start,
				 b12tok->end - b12tok->start,
				 plugin_feature_set(cmd->plugin),
				 chainparams, &fail);
	if (!ir->offer) {
		return fail_internalerr(cmd, ir,
					"Invalid offer: %s (%.*s)",
					fail,
					json_tok_full_len(offertok),
					json_tok_full(buf, offertok));
	}

	if (ir->offer->absolute_expiry
	    && time_now().ts.tv_sec >= *ir->offer->absolute_expiry) {
		/* FIXME: do deloffer to disable it */
		return fail_invreq(cmd, ir, "Offer expired");
	}

	/* BOLT-offers #12:
	 * - if the offer had a `quantity_min` or `quantity_max` field:
	 *   - MUST fail the request if there is no `quantity` field.
	 *   - MUST fail the request if there is `quantity` is not within
	 *     that (inclusive) range.
	 * - otherwise:
	 *   - MUST fail the request if there is a `quantity` field.
	 */
	if (ir->offer->quantity_min || ir->offer->quantity_max) {
		err = invreq_must_have(cmd, ir, quantity);
		if (err)
			return err;

		if (ir->offer->quantity_min &&
		    *ir->invreq->quantity < *ir->offer->quantity_min) {
			return fail_invreq(cmd, ir,
					   "quantity %"PRIu64 " < %"PRIu64,
					   *ir->invreq->quantity,
					   *ir->offer->quantity_min);
		}

		if (ir->offer->quantity_max &&
		    *ir->invreq->quantity > *ir->offer->quantity_max) {
			return fail_invreq(cmd, ir,
					   "quantity %"PRIu64" > %"PRIu64,
					   *ir->invreq->quantity,
					   *ir->offer->quantity_max);
		}
	} else {
		err = invreq_must_not_have(cmd, ir, quantity);
		if (err)
			return err;
	}

	err = invreq_must_have(cmd, ir, payer_signature);
	if (err)
		return err;
	if (!check_payer_sig(ir->invreq,
			     ir->invreq->payer_key,
			     ir->invreq->payer_signature)) {
		return fail_invreq(cmd, ir, "bad payer_signature");
	}

	if (ir->offer->recurrence) {
		/* BOLT-offers-recurrence #12:
		 *
		 * - if the offer had a `recurrence`:
		 *   - MUST fail the request if there is no `recurrence_counter`
		 *     field.
		 */
		err = invreq_must_have(cmd, ir, recurrence_counter);
		if (err)
			return err;
	} else {
		/* BOLT-offers-recurrence #12:
		 * - otherwise (the offer had no `recurrence`):
		 *   - MUST fail the request if there is a `recurrence_counter`
		 *     field.
		 *   - MUST fail the request if there is a `recurrence_start`
		 *     field.
		 */
		err = invreq_must_not_have(cmd, ir, recurrence_counter);
		if (err)
			return err;
		err = invreq_must_not_have(cmd, ir, recurrence_start);
		if (err)
			return err;
	}

	ir->inv = tlv_invoice_new(cmd);
	/* BOLT-offers #12:
	 *   - if the chain for the invoice is not solely bitcoin:
	 *     - MUST specify `chains` the offer is valid for.
	 */
	if (!streq(chainparams->network_name, "bitcoin")) {
		ir->inv->chain = tal_dup(ir->inv, struct bitcoin_blkid,
					 &chainparams->genesis_blockhash);
	}

	/* BOLT-offers #12:
	 *   - MUST set `offer_id` to the id of the offer.
	 */
	/* Which is the same as the invreq */
	ir->inv->offer_id = tal_dup(ir->inv, struct sha256,
				    ir->invreq->offer_id);
	ir->inv->description = tal_dup_talarr(ir->inv, char,
					      ir->offer->description);
	ir->inv->features = tal_dup_talarr(ir->inv, u8,
				       plugin_feature_set(cmd->plugin)
				       ->bits[BOLT11_FEATURE]);
	/* FIXME: Insert paths and payinfo */

	ir->inv->issuer = tal_dup_talarr(ir->inv, char, ir->offer->issuer);
	ir->inv->node_id = tal_dup(ir->inv, struct point32, ir->offer->node_id);
	/* BOLT-offers #12:
	 *  - MUST set (or not set) `quantity` exactly as the invoice_request
	 *    did.
	 */
	if (ir->offer->quantity_min || ir->offer->quantity_max)
		ir->inv->quantity = tal_dup(ir->inv, u64, ir->invreq->quantity);

	/* BOLT-offers #12:
	 *  - MUST set `payer_key` exactly as the invoice_request did.
	 */
	ir->inv->payer_key = tal_dup(ir->inv, struct point32,
				     ir->invreq->payer_key);

	/* BOLT-offers #12:
	 *  - MUST set (or not set) `payer_info` exactly as the invoice_request
	 *    did.
	 */
	ir->inv->payer_info
		= tal_dup_talarr(ir->inv, u8, ir->invreq->payer_info);

	/* BOLT-offers #12:
	 * - MUST set (or not set) `payer_note` exactly as the invoice_request
	 *   did, or MUST not set it.
	 */
	/* i.e. we don't have to do anything, but we do. */
	ir->inv->payer_note
		= tal_dup_talarr(ir->inv, char, ir->invreq->payer_note);

	randombytes_buf(&ir->preimage, sizeof(ir->preimage));
	ir->inv->payment_hash = tal(ir->inv, struct sha256);
	sha256(ir->inv->payment_hash, &ir->preimage, sizeof(ir->preimage));

	ir->inv->cltv = tal_dup(ir->inv, u32, &cltv_final);

	ir->inv->created_at = tal(ir->inv, u64);
	*ir->inv->created_at = time_now().ts.tv_sec;

	/* We may require currency lookup; if so, do it now. */
	if (ir->offer->amount && ir->offer->currency)
		return convert_currency(cmd, ir);

	err = invreq_base_amount_simple(cmd, ir, &amt);
	if (err)
		return err;
	return handle_amount_and_recurrence(cmd, ir, amt);
}

static struct command_result *handle_offerless_request(struct command *cmd,
						       struct invreq *ir)
{
	/* FIXME: shut up and take their money! */
	return fail_internalerr(cmd, ir, "FIXME: handle offerless req!");
}

struct command_result *handle_invoice_request(struct command *cmd,
					      const u8 *invreqbin,
					      struct tlv_onionmsg_payload_reply_path *reply_path,
					      struct tlv_obs2_onionmsg_payload_reply_path *obs2_reply_path)
{
	size_t len = tal_count(invreqbin);
	struct invreq *ir = tal(cmd, struct invreq);
	struct out_req *req;
	int bad_feature;

	ir->obs2_reply_path = tal_steal(ir, obs2_reply_path);
	ir->reply_path = tal_steal(ir, reply_path);

	ir->invreq = tlv_invoice_request_new(cmd);
	if (!fromwire_invoice_request(&invreqbin, &len, ir->invreq)) {
		return fail_invreq(cmd, ir,
				   "Invalid invreq %s",
				   tal_hex(tmpctx, invreqbin));
	}

	/* BOLT-offers #12:
	 *
	 * The reader of an invoice_request:
	 *...
	 *   - MUST fail the request if `features` contains unknown even bits.
	 */
	bad_feature = features_unsupported(plugin_feature_set(cmd->plugin),
					   ir->invreq->features,
					   BOLT11_FEATURE);
	if (bad_feature != -1) {
		return fail_invreq(cmd, ir,
				   "Unsupported invreq feature %i",
				   bad_feature);
	}

	/* BOLT-offers #12:
	 *
	 * The reader of an invoice_request:
	 *...
	 *  - if `chain` is not present:
	 *    - MUST fail the request if bitcoin is not a supported chain.
	 *  - otherwise:
	 *    - MUST fail the request if `chain` is not a supported chain.
	 */
	if (!bolt12_chain_matches(ir->invreq->chain, chainparams)) {
		return fail_invreq(cmd, ir,
				   "Wrong chain %s",
				   tal_hex(tmpctx, ir->invreq->chain));
	}

	/* BOLT-offers #12:
	 *
	 * The reader of an invoice_request:
	 *   - MUST fail the request if `payer_key` is not present.
	 */
	if (!ir->invreq->payer_key)
		return fail_invreq(cmd, ir, "Missing payer key");

	if (!ir->invreq->offer_id)
		return handle_offerless_request(cmd, ir);

	/* Now, look up offer */
	req = jsonrpc_request_start(cmd->plugin, cmd, "listoffers",
				    listoffers_done, error, ir);
	json_add_sha256(req->js, "offer_id", ir->invreq->offer_id);
	return send_outreq(cmd->plugin, req);
}

