#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <ccan/tal/str/str.h>
#include <common/bech32_util.h>
#include <common/blindedpath.h>
#include <common/bolt12_merkle.h>
#include <common/invoice_path_id.h>
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
	struct blinded_path *reply_path;

	/* The offer id */
	struct sha256 offer_id;

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
	struct tlv_onionmsg_tlv *payload;
	struct tlv_invoice_error *err;

	full_fmt = tal_fmt(tmpctx, "Failed invreq");
	if (invreq->invreq) {
		tal_append_fmt(&full_fmt, " %s",
			       invrequest_encode(tmpctx, invreq->invreq));
	}
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

	payload = tlv_onionmsg_tlv_new(tmpctx);
	payload->invoice_error = tal_arr(payload, u8, 0);
	towire_tlv_invoice_error(&payload->invoice_error, err);
	return send_onion_reply(cmd, invreq->reply_path, payload);
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
	inv->invoice_relative_expiry = tal(inv, u32);

	/* Don't give them a 0 second invoice, even if it's true. */
	if (last_pay <= *inv->invoice_created_at)
		*inv->invoice_relative_expiry = 1;
	else
		*inv->invoice_relative_expiry = last_pay - *inv->invoice_created_at;

	/* FIXME: Shorten expiry if we're doing currency conversion! */
}

/* We rely on label forms for uniqueness. */
static void json_add_label(struct json_stream *js,
			   const struct sha256 *offer_id,
			   const struct pubkey *payer_key,
			   const u32 counter)
{
	char *label;

	label = tal_fmt(tmpctx, "%s-%s-%u",
			type_to_string(tmpctx, struct sha256, offer_id),
			type_to_string(tmpctx, struct pubkey, payer_key),
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
	struct tlv_onionmsg_tlv *payload;
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

	payload = tlv_onionmsg_tlv_new(tmpctx);
	payload->invoice = rawinv;
	return send_onion_reply(cmd, ir->reply_path, payload);
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

	/* FIXME: We should add a real blinded path, and we *need to*
	 * if we don't have public channels! */

	/* Now, write invoice to db (returns the signed version) */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoice",
				    createinvoice_done, createinvoice_error, ir);

	json_add_string(req->js, "invstring", invoice_encode(tmpctx, ir->inv));
	json_add_preimage(req->js, "preimage", &ir->preimage);
	json_add_label(req->js, &ir->offer_id, ir->inv->invreq_payer_id,
		       ir->inv->invreq_recurrence_counter
		       ? *ir->inv->invreq_recurrence_counter : 0);
	return send_outreq(cmd->plugin, req);
}

/* Create and encode an enctlv */
static u8 *create_enctlv(const tal_t *ctx,
			 /* in and out */
			 struct privkey *blinding,
			 const struct pubkey *node_id,
			 struct short_channel_id *next_scid,
			 struct tlv_encrypted_data_tlv_payment_relay *payment_relay,
			 struct tlv_encrypted_data_tlv_payment_constraints *payment_constraints,
			 u8 *path_secret,
			 struct pubkey *node_alias)
{
	struct tlv_encrypted_data_tlv *tlv = tlv_encrypted_data_tlv_new(tmpctx);

	tlv->short_channel_id = next_scid;
	tlv->path_id = path_secret;
	tlv->payment_relay = payment_relay;
	tlv->payment_constraints = payment_constraints;
	/* FIXME: Add padding! */

	return encrypt_tlv_encrypted_data(ctx, blinding, node_id, tlv,
					  blinding, node_alias);
}

/* If we only have private channels, we need to add a blinded path to the
 * invoice.  We need to choose a peer who supports blinded payments, too. */
struct chaninfo {
	struct pubkey id;
	struct short_channel_id scid;
	struct amount_msat capacity, htlc_min, htlc_max;
	u32 feebase, feeppm, cltv;
	bool public;
};

/* FIXME: This is naive:
 * - Only creates if we have no public channels.
 * - Always creates a path from direct neighbor.
 * - Doesn't append dummy hops.
 * - Doesn't pad to length.
 */
/* (We only create if we have to, because our code doesn't handle
 * making a payment if the blinded path starts with ourselves!) */
static struct command_result *listincoming_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct invreq *ir)
{
	const jsmntok_t *arr, *t;
	size_t i;
	struct chaninfo *best = NULL;
	bool any_public = false;

	arr = json_get_member(buf, result, "incoming");
	json_for_each_arr(i, t, arr) {
		struct chaninfo ci;
		const jsmntok_t *pftok;
		u8 *features;
		const char *err;
		struct amount_msat feebase;

		err = json_scan(tmpctx, buf, t,
				"{id:%,"
				"incoming_capacity_msat:%,"
				"htlc_min_msat:%,"
				"htlc_max_msat:%,"
				"fee_base_msat:%,"
				"fee_proportional_millionths:%,"
				"cltv_expiry_delta:%,"
				"short_channel_id:%,"
				"public:%}",
				JSON_SCAN(json_to_pubkey, &ci.id),
				JSON_SCAN(json_to_msat, &ci.capacity),
				JSON_SCAN(json_to_msat, &ci.htlc_min),
				JSON_SCAN(json_to_msat, &ci.htlc_max),
				JSON_SCAN(json_to_msat, &feebase),
				JSON_SCAN(json_to_u32, &ci.feeppm),
				JSON_SCAN(json_to_u32, &ci.cltv),
				JSON_SCAN(json_to_short_channel_id, &ci.scid),
				JSON_SCAN(json_to_bool, &ci.public));
		if (err) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Could not parse listincoming: %s",
				   err);
			continue;
		}
		ci.feebase = feebase.millisatoshis; /* Raw: feebase */
		any_public |= ci.public;

		/* Not presented if there's no channel_announcement for peer:
		 * we could use listpeers, but if it's private we probably
		 * don't want to blinded route through it! */
		pftok = json_get_member(buf, t, "peer_features");
		if (!pftok || !ci.public)
			continue;
		features = json_tok_bin_from_hex(tmpctx, buf, pftok);
		if (!feature_offered(features, OPT_ROUTE_BLINDING))
			continue;

		if (amount_msat_less(ci.htlc_max,
				     amount_msat(*ir->inv->invoice_amount)))
			continue;

		/* Only pick a private one if no public candidates. */
		if (!best || (!best->public && ci.public))
			best = tal_dup(tmpctx, struct chaninfo, &ci);
	}

	/* If there are any public channels, don't add. */
	if (any_public)
		goto done;

	/* BOLT-offers #12:
	 * - MUST include `invoice_paths` containing one or more paths to the node.
	 * - MUST specify `invoice_paths` in order of most-preferred to
	 *   least-preferred if it has a preference.
	 * - MUST include `invoice_blindedpay` with exactly one `blinded_payinfo`
	 *   for each `blinded_path` in `paths`, in order.
	 */
	if (!best) {
		/* Note: since we don't make one, createinvoice adds a dummy. */
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "No incoming channel for %s, so no blinded path",
			   fmt_amount_msat(tmpctx,
					   amount_msat(*ir->inv->invoice_amount)));
	} else {
		struct privkey blinding;
		struct tlv_encrypted_data_tlv_payment_relay relay;
		struct tlv_encrypted_data_tlv_payment_constraints constraints;
		struct onionmsg_hop **hops;
		u32 base;

		relay.cltv_expiry_delta = best->cltv;
		relay.fee_base_msat = best->feebase;
		relay.fee_proportional_millionths = best->feeppm;

		/* BOLT-offers #12:
		 * - if the expiry for accepting payment is not 7200 seconds
		 *   after `invoice_created_at`:
		 *     - MUST set `invoice_relative_expiry`
		 */
		/* Give them 6 blocks, plus one per 10 minutes until expiry. */
		if (ir->inv->invoice_relative_expiry)
			base = blockheight + 6 + *ir->inv->invoice_relative_expiry / 600;
		else
			base = blockheight + 6 + 7200 / 600;
		constraints.max_cltv_expiry = base + best->cltv + cltv_final;
		constraints.htlc_minimum_msat = best->htlc_min.millisatoshis; /* Raw: tlv */

		randombytes_buf(&blinding, sizeof(blinding));

		ir->inv->invoice_paths = tal_arr(ir->inv, struct blinded_path *, 1);
		ir->inv->invoice_paths[0] = tal(ir->inv->invoice_paths, struct blinded_path);
		ir->inv->invoice_paths[0]->first_node_id = best->id;
		if (!pubkey_from_privkey(&blinding,
					 &ir->inv->invoice_paths[0]->blinding))
			abort();
		hops = tal_arr(ir->inv->invoice_paths[0], struct onionmsg_hop *, 2);
		ir->inv->invoice_paths[0]->path = hops;

		/* First hop is the peer */
		hops[0] = tal(hops, struct onionmsg_hop);
		hops[0]->encrypted_recipient_data
			= create_enctlv(hops[0],
					&blinding,
					&best->id,
					&best->scid,
					&relay, &constraints,
					NULL,
					&hops[0]->blinded_node_id);
		/* Second hops is us (so we can identify correct use of path) */
		hops[1] = tal(hops, struct onionmsg_hop);
		hops[1]->encrypted_recipient_data
			= create_enctlv(hops[1],
					&blinding,
					&id,
					NULL, NULL, NULL,
					invoice_path_id(tmpctx, &invoicesecret_base,
							ir->inv->invoice_payment_hash),
					&hops[1]->blinded_node_id);

		/* FIXME: This should be a "normal" feerate and range. */
		ir->inv->invoice_blindedpay = tal_arr(ir->inv, struct blinded_payinfo *, 1);
		ir->inv->invoice_blindedpay[0] = tal(ir->inv->invoice_blindedpay, struct blinded_payinfo);
		ir->inv->invoice_blindedpay[0]->fee_base_msat = best->feebase;
		ir->inv->invoice_blindedpay[0]->fee_proportional_millionths = best->feeppm;
		ir->inv->invoice_blindedpay[0]->cltv_expiry_delta = best->cltv;
		ir->inv->invoice_blindedpay[0]->htlc_minimum_msat = best->htlc_min;
		ir->inv->invoice_blindedpay[0]->htlc_maximum_msat = best->htlc_max;
		ir->inv->invoice_blindedpay[0]->features = NULL;
	}

done:
	return create_invoicereq(cmd, ir);
}

static struct command_result *add_blindedpaths(struct command *cmd,
					       struct invreq *ir)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd->plugin, cmd, "listincoming",
				    listincoming_done, listincoming_done, ir);
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
	if (ir->invreq->offer_recurrence_base)
		basetime = ir->invreq->offer_recurrence_base->basetime;

	/* BOLT-offers-recurrence #12:
	 * - if the invoice corresponds to an offer with `recurrence`:
	 *   - MUST set `recurrence_basetime` to the start of period #0 as
	 *     calculated by [Period Calculation](#offer-period-calculation).
	 */
	ir->inv->invoice_recurrence_basetime = tal_dup(ir->inv, u64, &basetime);

	period_idx = *ir->invreq->invreq_recurrence_counter;

	/* BOLT-offers-recurrence #12:
	 * - if the offer had `recurrence_base` and `start_any_period`
	 *   was 1:
	 *   - MUST fail the request if there is no `recurrence_start`
	 *     field.
	 *   - MUST consider the period index for this request to be the
	 *     `recurrence_start` field plus the `recurrence_counter`
	 *     `counter` field.
	 */
	if (ir->invreq->offer_recurrence_base
	    && ir->invreq->offer_recurrence_base->start_any_period) {
		err = invreq_must_have(cmd, ir, invreq_recurrence_start);
		if (err)
			return err;
		period_idx += *ir->invreq->invreq_recurrence_start;

		/* BOLT-offers-recurrence #12:
		 * - MUST set (or not set) `recurrence_start` exactly as the
		 *   invreq did.
		 */
		ir->inv->invreq_recurrence_start
			= tal_dup(ir->inv, u32, ir->invreq->invreq_recurrence_start);
	} else {
		/* BOLT-offers-recurrence #12:
		 *
		 * - otherwise:
		 *   - MUST fail the request if there is a `recurrence_start`
		 *     field.
		 *   - MUST consider the period index for this request to be the
		 *     `recurrence_counter` `counter` field.
		 */
		err = invreq_must_not_have(cmd, ir, invreq_recurrence_start);
		if (err)
			return err;
	}

	/* BOLT-offers-recurrence #12:
	 * - if the offer has a `recurrence_limit`:
	 *   - MUST fail the request if the period index is greater than
	 *     `max_period`.
	 */
	if (ir->invreq->offer_recurrence_limit
	    && period_idx > *ir->invreq->offer_recurrence_limit) {
		return fail_invreq(cmd, ir,
				   "period_index %"PRIu64" too great",
				   period_idx);
	}

	offer_period_paywindow(ir->invreq->offer_recurrence,
			       ir->invreq->offer_recurrence_paywindow,
			       ir->invreq->offer_recurrence_base,
			       basetime, period_idx,
			       &paywindow_start, &paywindow_end);
	if (*ir->inv->invoice_created_at < paywindow_start) {
		return fail_invreq(cmd, ir,
				   "period_index %"PRIu64
				   " too early (start %"PRIu64")",
				   period_idx,
				   paywindow_start);
	}
	if (*ir->inv->invoice_created_at > paywindow_end) {
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
	if (*ir->invreq->invreq_recurrence_counter != 0
	    && ir->invreq->offer_recurrence_paywindow
	    && ir->invreq->offer_recurrence_paywindow->proportional_amount == 1) {
		u64 start = offer_period_start(basetime, period_idx,
					       ir->invreq->offer_recurrence);
		u64 end = offer_period_start(basetime, period_idx + 1,
					     ir->invreq->offer_recurrence);

		if (*ir->inv->invoice_created_at > start) {
			*ir->inv->invoice_amount
				*= (double)((*ir->inv->invoice_created_at - start)
					    / (end - start));
			/* Round up to make it non-zero if necessary. */
			if (*ir->inv->invoice_amount == 0)
				*ir->inv->invoice_amount = 1;
		}
	}

	return add_blindedpaths(cmd, ir);
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
				   *ir->inv->invreq_recurrence_counter - 1);
	}

	/* Was it paid? */
	status = json_get_member(buf, arr + 1, "status");
	if (!json_tok_streq(buf, status, "paid")) {
		return fail_invreq(cmd, ir,
				   "Previous invoice #%u status %.*s",
				   *ir->inv->invreq_recurrence_counter - 1,
				   json_tok_full_len(status),
				   json_tok_full(buf, status));
	}

	/* Decode it */
	b12 = json_get_member(buf, arr + 1, "bolt12");
	if (!b12) {
		return fail_internalerr(cmd, ir,
					"Previous invoice #%u no bolt12 (%.*s)",
					*ir->inv->invreq_recurrence_counter - 1,
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
	if (!previnv->invoice_recurrence_basetime) {
		return fail_internalerr(cmd, ir,
			   "Previous invoice %.*s no recurrence_basetime?",
			   json_tok_full_len(b12), json_tok_full(buf, b12));
	}
	return check_period(cmd, ir, *previnv->invoice_recurrence_basetime);
}

/* Now, we need to check the previous invoice was paid, and maybe get timebase */
static struct command_result *check_previous_invoice(struct command *cmd,
						     struct invreq *ir)
{
	struct out_req *req;

	/* No previous?  Just pass through */
	if (*ir->invreq->invreq_recurrence_counter == 0)
		return check_period(cmd, ir, *ir->inv->invoice_created_at);

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "listinvoices",
				    prev_invoice_done,
				    error,
				    ir);
	json_add_label(req->js,
		       &ir->offer_id,
		       ir->invreq->invreq_payer_id,
		       *ir->invreq->invreq_recurrence_counter - 1);
	return send_outreq(cmd->plugin, req);
}

/* BOLT-offers #12:

 * - MUST fail the request if `signature` is not correct as detailed in
 *   [Signature Calculation](#signature-calculation) using the
 *   `invreq_payer_id`.
 *...
 * - MUST reject the invoice if `signature` is not a valid signature using
 *   `invoice_node_id` as described in [Signature Calculation](#signature-calculation).
 */
static bool check_payer_sig(struct command *cmd,
			    const struct tlv_invoice_request *invreq,
			    const struct pubkey *payer_key,
			    const struct bip340sig *sig)
{
	struct sha256 merkle, sighash;
	merkle_tlv(invreq->fields, &merkle);
	sighash_from_merkle("invoice_request", "signature", &merkle, &sighash);

	return check_schnorr_sig(&sighash, &payer_key->pubkey, sig);
}

static struct command_result *invreq_amount_by_quantity(struct command *cmd,
							const struct invreq *ir,
							u64 *raw_amt)
{
	assert(ir->invreq->offer_amount);

	/* BOLT-offers #12:
	 *     - MUST calculate the *expected amount* using the `offer_amount`:
	 */
	*raw_amt = *ir->invreq->offer_amount;

	/* BOLT-offers #12:
	 * - if `invreq_quantity` is present, multiply by `invreq_quantity`.`quantity`.
	 */
	if (ir->invreq->invreq_quantity) {
		if (mul_overflows_u64(*ir->invreq->invreq_quantity, *raw_amt)) {
			return fail_invreq(cmd, ir,
					   "quantity %"PRIu64
					   " causes overflow",
					   *ir->invreq->invreq_quantity);
		}
		*raw_amt *= *ir->invreq->invreq_quantity;
	}

	return NULL;
}

/* The non-currency-converting case. */
static struct command_result *invreq_base_amount_simple(struct command *cmd,
							const struct invreq *ir,
							struct amount_msat *amt)
{
	struct command_result *err;

	if (ir->invreq->offer_amount) {
		u64 raw_amount;
		assert(!ir->invreq->offer_currency);
		err = invreq_amount_by_quantity(cmd, ir, &raw_amount);
		if (err)
			return err;

		*amt = amount_msat(raw_amount);
	} else {
		/* BOLT-offers #12:
		 *
		 * The reader:
		 *...
		 *    - otherwise (no `offer_amount`):
		 *      - MUST fail the request if it does not contain
		 *       `invreq_amount`.
		 */
		err = invreq_must_have(cmd, ir, invreq_amount);
		if (err)
			return err;

		*amt = amount_msat(*ir->invreq->invreq_amount);
	}
	return NULL;
}

static struct command_result *handle_amount_and_recurrence(struct command *cmd,
							   struct invreq *ir,
							   struct amount_msat base_inv_amount)
{
	/* BOLT-offers #12:
	 * - if `invreq_amount` is present:
	 *    - MUST fail the request if `invreq_amount`.`msat` is less than the
	 *      *expected amount*.
	 */
	if (ir->invreq->offer_amount && ir->invreq->invreq_amount) {
		if (amount_msat_less(amount_msat(*ir->invreq->invreq_amount), base_inv_amount)) {
			return fail_invreq(cmd, ir, "Amount must be at least %s",
					   type_to_string(tmpctx, struct amount_msat,
							  &base_inv_amount));
		}
		/* BOLT-offers #12:
		 *    - MAY fail the request if `invreq_amount`.`msat` greatly exceeds
		 *      the *expected amount*.
		 */
		/* Much == 5? Easier to divide and compare, than multiply. */
		if (amount_msat_greater(amount_msat_div(amount_msat(*ir->invreq->invreq_amount), 5),
					base_inv_amount)) {
			return fail_invreq(cmd, ir, "Amount vastly exceeds %s",
					   type_to_string(tmpctx, struct amount_msat,
							  &base_inv_amount));
		}
		base_inv_amount = amount_msat(*ir->invreq->invreq_amount);
	}

	/* BOLT-offers #12:
	 * - if `invreq_amount` is present:
	 *   - MUST set `invoice_amount` to `invreq_amount`
	 * - otherwise:
	 *   - MUST set `invoice_amount` to the *expected amount*.
	 */
	/* This may be adjusted by recurrence if proportional_amount set */
	ir->inv->invoice_amount = tal_dup(ir->inv, u64,
					  &base_inv_amount.millisatoshis); /* Raw: wire protocol */

	/* Last of all, we handle recurrence details, which often requires
	 * further lookups. */
	if (ir->inv->invreq_recurrence_counter) {
		return check_previous_invoice(cmd, ir);
	}
	/* We're happy with 2 hours timeout (default): they can always
	 * request another. */

	/* FIXME: Fallbacks? */
	return add_blindedpaths(cmd, ir);
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
					(int)tal_bytelen(ir->invreq->offer_currency),
					(const char *)ir->invreq->offer_currency,
					json_tok_full_len(result),
					json_tok_full(buf, result));

	if (!json_to_msat(buf, msat, &amount))
		return fail_internalerr(cmd, ir,
					"Bad convert for currency %.*s: %.*s",
					(int)tal_bytelen(ir->invreq->offer_currency),
					(const char *)ir->invreq->offer_currency,
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

	assert(ir->invreq->offer_currency);

	/* Multiply by quantity *first*, for best precision */
	err = invreq_amount_by_quantity(cmd, ir, &raw_amount);
	if (err)
		return err;

	/* BOLT-offers #12:
	 * - MUST calculate the *expected amount* using the `offer_amount`:
	 *   - if `offer_currency` is not the `invreq_chain` currency, convert to the
	 *     `invreq_chain` currency.
	 */
	iso4217 = find_iso4217(ir->invreq->offer_currency,
			       tal_bytelen(ir->invreq->offer_currency));
	/* We should not create offer with unknown currency! */
	if (!iso4217)
		return fail_internalerr(cmd, ir,
					"Unknown offer currency %.*s",
					(int)tal_bytelen(ir->invreq->offer_currency),
					ir->invreq->offer_currency);
	double_amount = (double)raw_amount;
	for (size_t i = 0; i < iso4217->minor_unit; i++)
		double_amount /= 10;

	req = jsonrpc_request_start(cmd->plugin, cmd, "currencyconvert",
				    currency_done, error, ir);
	json_add_stringn(req->js, "currency",
			 (const char *)ir->invreq->offer_currency,
			 tal_bytelen(ir->invreq->offer_currency));
	json_add_primitive_fmt(req->js, "amount", "%f", double_amount);
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
	struct command_result *err;
	struct amount_msat amt;

	/* BOLT-offers #12:
	 *
	 * - MUST fail the request if the offer fields do not exactly match a
	 *   valid, unexpired offer.
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

	/* Now, since we looked up by hash, we know that the entire offer
	 * is faithfully mirrored in this invreq. */
	b12tok = json_get_member(buf, offertok, "bolt12");
	if (!b12tok) {
		return fail_internalerr(cmd, ir,
					"Missing bolt12: %.*s",
					json_tok_full_len(offertok),
					json_tok_full(buf, offertok));
	}

	if (ir->invreq->offer_absolute_expiry
	    && time_now().ts.tv_sec >= *ir->invreq->offer_absolute_expiry) {
		/* FIXME: do deloffer to disable it */
		return fail_invreq(cmd, ir, "Offer expired");
	}

	/* BOLT-offers #12:
	 * - if `offer_quantity_max` is present:
	 *   - MUST fail the request if there is no `invreq_quantity` field.
	 *   - if `offer_quantity_max` is non-zero:
	 *     - MUST fail the request if `invreq_quantity` is zero, OR greater than
	 *       `offer_quantity_max`.
	 * - otherwise:
	 *   - MUST fail the request if there is an `invreq_quantity` field.
	 */
	if (ir->invreq->offer_quantity_max) {
		err = invreq_must_have(cmd, ir, invreq_quantity);
		if (err)
			return err;

		if (*ir->invreq->invreq_quantity == 0)
			return fail_invreq(cmd, ir,
					   "quantity zero invalid");

		if (*ir->invreq->offer_quantity_max &&
		    *ir->invreq->invreq_quantity > *ir->invreq->offer_quantity_max) {
			return fail_invreq(cmd, ir,
					   "quantity %"PRIu64" > %"PRIu64,
					   *ir->invreq->invreq_quantity,
					   *ir->invreq->offer_quantity_max);
		}
	} else {
		err = invreq_must_not_have(cmd, ir, invreq_quantity);
		if (err)
			return err;
	}

	/* BOLT-offers #12:
	 * - MUST fail the request if `signature` is not correct as
	 *   detailed in [Signature Calculation](#signature-calculation) using
	 *   the `invreq_payer_id`.
	 */
	err = invreq_must_have(cmd, ir, signature);
	if (err)
		return err;
	if (!check_payer_sig(cmd, ir->invreq,
			     ir->invreq->invreq_payer_id,
			     ir->invreq->signature)) {
		return fail_invreq(cmd, ir, "bad signature");
	}

	if (ir->invreq->offer_recurrence) {
		/* BOLT-offers-recurrence #12:
		 *
		 * - if the offer had a `recurrence`:
		 *   - MUST fail the request if there is no `recurrence_counter`
		 *     field.
		 */
		err = invreq_must_have(cmd, ir, invreq_recurrence_counter);
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
		err = invreq_must_not_have(cmd, ir, invreq_recurrence_counter);
		if (err)
			return err;
		err = invreq_must_not_have(cmd, ir, invreq_recurrence_start);
		if (err)
			return err;
	}

	/* BOLT-offers #12:
	 * A writer of an invoice:
	 *...
	 *  - if the invoice is in response to an `invoice_request`:
	 *    - MUST copy all non-signature fields from the `invoice_request` (including
	 *      unknown fields).
	 */
	ir->inv = invoice_for_invreq(cmd, ir->invreq);
	assert(ir->inv->invreq_payer_id);

	/* BOLT-offers #12:
	 *   - if `offer_node_id` is present:
	 *     - MUST set `invoice_node_id` to `offer_node_id`.
	 */
	/* We always provide an offer_node_id! */
	ir->inv->invoice_node_id = ir->inv->offer_node_id;

	/* BOLT-offers #12:
	 * - MUST set `invoice_created_at` to the number of seconds since
	 *   Midnight 1 January 1970, UTC when the invoice was created.
	 */
	ir->inv->invoice_created_at = tal(ir->inv, u64);
	*ir->inv->invoice_created_at = time_now().ts.tv_sec;

	/* BOLT-offers #12:
	 * - MUST set `invoice_payment_hash` to the SHA256 hash of the
	 *   `payment_preimage` that will be given in return for payment.
	 */
	randombytes_buf(&ir->preimage, sizeof(ir->preimage));
	ir->inv->invoice_payment_hash = tal(ir->inv, struct sha256);
	sha256(ir->inv->invoice_payment_hash,
	       &ir->preimage, sizeof(ir->preimage));

	/* BOLT-offers #12:
	 *  - or if it allows multiple parts to pay the invoice:
	 *     - MUST set `invoice_features`.`features` bit `MPP/optional`
	 */
	ir->inv->invoice_features
		= plugin_feature_set(cmd->plugin)->bits[BOLT12_INVOICE_FEATURE];

	/* We may require currency lookup; if so, do it now. */
	if (ir->invreq->offer_amount && ir->invreq->offer_currency)
		return convert_currency(cmd, ir);

	err = invreq_base_amount_simple(cmd, ir, &amt);
	if (err)
		return err;
	return handle_amount_and_recurrence(cmd, ir, amt);
}

struct command_result *handle_invoice_request(struct command *cmd,
					      const u8 *invreqbin,
					      struct blinded_path *reply_path)
{
	size_t len = tal_count(invreqbin);
	const u8 *cursor = invreqbin;
	struct invreq *ir = tal(cmd, struct invreq);
	struct out_req *req;
	int bad_feature;

	ir->reply_path = tal_steal(ir, reply_path);

	ir->invreq = fromwire_tlv_invoice_request(cmd, &cursor, &len);
	if (!ir->invreq) {
		return fail_invreq(cmd, ir,
				   "Invalid invreq %s",
				   tal_hex(tmpctx, invreqbin));
	}

	/* BOLT-offers #12:
	 *
	 * The reader:
	 *  - MUST fail the request if `invreq_payer_id` or `invreq_metadata`
	 *    are not present.
	 */
	if (!ir->invreq->invreq_payer_id)
		return fail_invreq(cmd, ir, "Missing invreq_payer_id");
	if (!ir->invreq->invreq_metadata)
		return fail_invreq(cmd, ir, "Missing invreq_metadata");

	/* BOLT-offers #12:
	 * The reader:
	 * ...
	 *  - MUST fail the request if any non-signature TLV fields greater or
	 *    equal to 160.
	 */
	/* BOLT-offers #12:
	 * Each form is signed using one or more *signature TLV elements*:
	 * TLV types 240 through 1000 (inclusive)
	 */
	if (tlv_span(invreqbin, 0, 159, NULL)
	    + tlv_span(invreqbin, 240, 1000, NULL) != tal_bytelen(invreqbin))
		return fail_invreq(cmd, ir, "Fields beyond 160");

	/* BOLT-offers #12:
	 *
	 * The reader:
	 *...
	 * - if `invreq_features` contains unknown _even_ bits that are non-zero:
	 *   - MUST fail the request.
	 */
	bad_feature = features_unsupported(plugin_feature_set(cmd->plugin),
					   ir->invreq->invreq_features,
					   BOLT12_INVREQ_FEATURE);
	if (bad_feature != -1) {
		return fail_invreq(cmd, ir,
				   "Unsupported invreq feature %i",
				   bad_feature);
	}

	/* BOLT-offers #12:
	 *
	 * The reader:
	 *...
	 * - if `invreq_chain` is not present:
	 *   - MUST fail the request if bitcoin is not a supported chain.
	 * - otherwise:
	 *   - MUST fail the request if `invreq_chain`.`chain` is not a
	 *     supported chain.
	 */
	if (!bolt12_chain_matches(ir->invreq->invreq_chain, chainparams)) {
		return fail_invreq(cmd, ir,
				   "Wrong chain %s",
				   tal_hex(tmpctx, ir->invreq->invreq_chain));
	}

	/* BOLT-offers #12:
	 *
	 * - otherwise (no `offer_node_id`, not a response to our offer):
	 */
	/* FIXME-OFFERS: handle this! */
	if (!ir->invreq->offer_node_id) {
		return fail_invreq(cmd, ir, "Not based on an offer");
	}

	/* BOLT-offers #12:
	 *
	 * - if `offer_node_id` is present (response to an offer):
	 *   - MUST fail the request if the offer fields do not exactly match a
	 *     valid, unexpired offer.
	 */
	invreq_offer_id(ir->invreq, &ir->offer_id);

	/* Now, look up offer */
	req = jsonrpc_request_start(cmd->plugin, cmd, "listoffers",
				    listoffers_done, error, ir);
	json_add_sha256(req->js, "offer_id", &ir->offer_id);
	return send_outreq(cmd->plugin, req);
}

