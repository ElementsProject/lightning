#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <ccan/cast/cast.h>
#include <common/bech32_util.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/json_stream.h>
#include <common/overflows.h>
#include <common/type_to_string.h>
#include <plugins/offers.h>
#include <plugins/offers_invreq_hook.h>
#include <secp256k1_schnorrsig.h>

/* We need to keep the reply path around so we can reply with invoice */
struct invreq {
	struct tlv_invoice_request *invreq;
	const char *buf;
	const jsmntok_t *replytok;

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
	return send_onion_reply(cmd, invreq->buf, invreq->replytok,
				"invoice_error", errdata);
}

static struct command_result *WARN_UNUSED_RESULT
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

/* BOLT-offers #12:
 * - if the invoice corresponds to an offer with `recurrence`:
 * ...
 *   - if it sets `relative_expiry`:
 *     - MUST NOT set `relative_expiry` `seconds_from_timestamp` more than the
 *       number of seconds after `timestamp` that payment for this period will
 *       be accepted.
 */
static void set_recurring_inv_expiry(struct tlv_invoice *inv, u64 last_pay)
{
	inv->relative_expiry = tal(inv, u32);

	/* Don't give them a 0 second invoice, even if it's true. */
	if (last_pay <= *inv->timestamp)
		*inv->relative_expiry = 1;
	else
		*inv->relative_expiry = last_pay - *inv->timestamp;

	/* FIXME: Shorten expiry if we're doing currency conversion! */
}

/* We rely on label forms for uniqueness. */
static void json_add_label(struct json_stream *js,
			   const struct sha256 *offer_id,
			   const struct pubkey32 *payer_key,
			   const u32 counter)
{
	char *label;

	label = tal_fmt(tmpctx, "%s-%s-%u",
			type_to_string(tmpctx, struct sha256, offer_id),
			type_to_string(tmpctx, struct pubkey32,
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

	return send_onion_reply(cmd, ir->buf, ir->replytok, "invoice", rawinv);
}

static struct command_result *create_invoicereq(struct command *cmd,
						struct invreq *ir)
{
	struct out_req *req;

	/* Now, write invoice to db (returns the signed version) */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoice",
				    createinvoice_done, error, ir);

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

	/* BOLT-offers #12:
	 * - if the invoice corresponds to an offer with `recurrence`:
	 *   - MUST set `recurrence_basetime` to the start of period #0 as
	 *     calculated by [Period Calculation](#offer-period-calculation).
	 */
	ir->inv->recurrence_basetime = tal_dup(ir->inv, u64, &basetime);

	period_idx = *ir->invreq->recurrence_counter;

	/* BOLT-offers #12:
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
	} else {
		/* BOLT-offers #12:
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

	/* BOLT-offers #12:
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
	if (*ir->inv->timestamp < paywindow_start) {
		return fail_invreq(cmd, ir,
				   "period_index %"PRIu64
				   " too early (start %"PRIu64")",
				   period_idx,
				   paywindow_start);
	}
	if (*ir->inv->timestamp > paywindow_end) {
		return fail_invreq(cmd, ir,
				   "period_index %"PRIu64
				   " too late (ended %"PRIu64")",
				   period_idx,
				   paywindow_end);
	}

	set_recurring_inv_expiry(ir->inv, paywindow_end);

	/* BOLT-offers #12:
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

		if (*ir->inv->timestamp > start) {
			*ir->inv->amount
				*= (double)((*ir->inv->timestamp - start)
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
				   "Previous invoice #%u status *.%s",
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
		return check_period(cmd, ir, *ir->inv->timestamp);

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
 *  - MUST fail the request if `recurrence_signature` is not correct.
 */
static bool check_recurrence_sig(const struct tlv_invoice_request *invreq,
				 const struct pubkey32 *payer_key,
				 const struct bip340sig *sig)
{
	struct sha256 merkle, sighash;
	merkle_tlv(invreq->fields, &merkle);
	sighash_from_merkle("invoice_request", "recurrence_signature",
			    &merkle, &sighash);

	return secp256k1_schnorrsig_verify(secp256k1_ctx,
					   sig->u8,
					   sighash.u.u8, &payer_key->pubkey) == 1;
}

static struct command_result *listoffers_done(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct invreq *ir)
{
	const jsmntok_t *arr = json_get_member(buf, result, "offers");
	const jsmntok_t *offertok, *activetok, *b12tok;
	bool active;
	struct amount_msat amt;
	char *fail;
	struct command_result *err;

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

	if (ir->offer->amount) {
		u64 raw_amount;

		/* BOLT-offers #12:
		 *
		 * - if the offer included `amount`:
		 *   - MUST fail the request if it contains `amount`.
		 */
		err = invreq_must_not_have(cmd, ir, amount);
		if (err)
			return err;


		/* BOLT-offers #12:
		 * - MUST calculate the *base invoice amount* using the offer
		 *  `amount`:
		 *   - if offer `currency` is not the invoice currency, convert
		 *     to the invoice currency.
		 */
		if (ir->offer->currency) {
			/* FIXME: Currency conversion! */
			return fail_invreq(cmd, ir,
					   "FIXME: Request for currency %.*s",
					   (int)tal_bytelen(ir->offer->currency),
					   (char *)ir->offer->currency);
		} else
			raw_amount = *ir->offer->amount;

		/* BOLT-offers #12:
		 * - if request contains `quantity`, multiply by `quantity`.
		 */
		if (ir->invreq->quantity) {
			if (mul_overflows_u64(*ir->invreq->quantity, raw_amount)) {
				return fail_invreq(cmd, ir,
						   "quantity %"PRIu64
						   " causes overflow",
						   *ir->invreq->quantity);
			}
			raw_amount *= *ir->invreq->quantity;
		}

		amt = amount_msat(raw_amount);
	} else {
		/* BOLT-offers #12:
		 *
		 * - otherwise:
		 * - MUST fail the request if it does not contain `amount`.
		 * - MUST use the request `amount` as the *base invoice amount*.
		 *   (Note: invoice amount can be further modiifed by recurrence
		 *    below)
		 */
		err = invreq_must_have(cmd, ir, amount);
		if (err)
			return err;

		amt = amount_msat(*ir->invreq->amount);
	}

	if (ir->offer->recurrence) {
		/* BOLT-offers #12:
		 *
		 * - if the offer had a `recurrence`:
		 *   - MUST fail the request if there is no `recurrence_counter`
		 *     field.
		 *   - MUST fail the request if there is no
		 *    `recurrence_signature` field.
		 *   - MUST fail the request if `recurrence_signature` is not
		 *     correct.
		 */
		err = invreq_must_have(cmd, ir, recurrence_counter);
		if (err)
			return err;

		err = invreq_must_have(cmd, ir, recurrence_signature);
		if (err)
			return err;

		if (!check_recurrence_sig(ir->invreq,
					  ir->invreq->payer_key,
					  ir->invreq->recurrence_signature)) {
			return fail_invreq(cmd, ir,
					   "bad recurrence_signature");
		}
	} else {
		/* BOLT-offers #12:
		 * - otherwise (the offer had no `recurrence`):
		 *   - MUST fail the request if there is a `recurrence_counter`
		 *     field.
		 *   - MUST fail the request if there is a `recurrence_signature`
		 *     field.
		 */
		err = invreq_must_not_have(cmd, ir, recurrence_counter);
		if (err)
			return err;
		err = invreq_must_not_have(cmd, ir, recurrence_signature);
		if (err)
			return err;
	}

	ir->inv = tlv_invoice_new(cmd);
	/* BOLT-offers #12:
	 *   - if the chain for the invoice is not solely bitcoin:
	 *     - MUST specify `chains` the offer is valid for.
	 */
	if (!streq(chainparams->network_name, "bitcoin")) {
		ir->inv->chains = tal_arr(ir->inv, struct bitcoin_blkid, 1);
		ir->inv->chains[0] = chainparams->genesis_blockhash;
	}
	/* BOLT-offers #12:
	 *   - MUST set `offer_id` to the id of the offer.
	 */
	/* Which is the same as the invreq */
	ir->inv->offer_id = tal_dup(ir->inv, struct sha256,
				    ir->invreq->offer_id);
	ir->inv->amount = tal_dup(ir->inv, u64,
				  &amt.millisatoshis); /* Raw: wire protocol */
	ir->inv->description = tal_dup_talarr(ir->inv, char,
					      ir->offer->description);
	ir->inv->features = tal_dup_talarr(ir->inv, u8,
				       plugin_feature_set(cmd->plugin)
				       ->bits[BOLT11_FEATURE]);
	/* FIXME: Insert paths and payinfo */

	ir->inv->vendor = tal_dup_talarr(ir->inv, char, ir->offer->vendor);
	ir->inv->node_id = tal_dup(ir->inv, struct pubkey32, ir->offer->node_id);
	/* BOLT-offers #12:
	 *  - MUST set (or not set) `quantity` exactly as the invoice_request
	 *    did.
	 */
	if (ir->offer->quantity_min || ir->offer->quantity_max)
		ir->inv->quantity = tal_dup(ir->inv, u64, ir->invreq->quantity);
	/* BOLT-offers #12:
	 *  - MUST set `payer_key` exactly as the invoice_request did.
	 */
	ir->inv->payer_key = tal_dup(ir->inv, struct pubkey32,
				     ir->invreq->payer_key);

	/* BOLT-offers #12:
	 *  - MUST set (or not set) `payer_info` exactly as the invoice_request
	 *    did.
	 */
	ir->inv->payer_info
		= tal_dup_talarr(ir->inv, u8, ir->invreq->payer_info);

	randombytes_buf(&ir->preimage, sizeof(ir->preimage));
	ir->inv->payment_hash = tal(ir->inv, struct sha256);
	sha256(ir->inv->payment_hash, &ir->preimage, sizeof(ir->preimage));

	ir->inv->cltv = tal_dup(ir->inv, u32, &cltv_final);

	ir->inv->timestamp = tal(ir->inv, u64);
	*ir->inv->timestamp = time_now().ts.tv_sec;

	/* Last of all, we handle recurrence details, which often requires
	 * further lookups. */

	/* BOLT-offers #12:
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
	/* FIXME: refunds? */
	return create_invoicereq(cmd, ir);
}

static struct command_result *handle_offerless_request(struct command *cmd,
						       struct invreq *ir)
{
	/* FIXME: shut up and take their money! */
	return fail_internalerr(cmd, ir, "FIXME: handle offerless req!");
}

struct command_result *handle_invoice_request(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *invreqtok,
					      const jsmntok_t *replytok)
{
	const u8 *invreqbin = json_tok_bin_from_hex(cmd, buf, invreqtok);
	size_t len = tal_count(invreqbin);
	struct invreq *ir = tal(cmd, struct invreq);
	struct out_req *req;
	int bad_feature;

	/* Make a copy of entire buffer, for later. */
	ir->buf = tal_dup_arr(ir, char, buf, replytok->end, 0);
	ir->replytok = replytok;

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
	 *   - MUST fail the request if `chains` does not include (or imply) a
	 *     supported chain.
	 */
	if (!bolt12_chains_match(ir->invreq->chains, chainparams)) {
		return fail_invreq(cmd, ir,
				   "Wrong chains %s",
				   tal_hex(tmpctx, ir->invreq->chains));
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

