#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12.h>
#include <common/bolt12_id.h>
#include <common/clock_time.h>
#include <common/hash_str.h>
#include <common/iso4217.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/randbytes.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

enum repeatpay_status {
	REPEATPAY_ONGOING,
	REPEATPAY_ONGOING_MAKING_PAYMENT,
	REPEATPAY_ONGOING_FAILING_AMOUNT,
	REPEATPAY_ONGOING_FAILING_BALANCE,
	REPEATPAY_ONGOING_FAILING_INVOICE,
	REPEATPAY_ONGOING_FAILING_PAYMENT,
	REPEATPAY_COMPLETE_FINISHED,
	REPEATPAY_COMPLETE_CANCELLED,
	REPEATPAY_COMPLETE_CANCEL_PENDING,
	REPEATPAY_COMPLETE_FAILED,
};

struct payment_log {
	enum repeatpay_status status;
	const char *msg;
};

struct payment_max {
	/* Either msat, or if currency set, currency units */
	u64 amount;
	const struct iso4217_name_and_divisor *currency;
};

/* All the repeat payments we're tracking */
struct payment {
	/* How are we doing? */
	enum repeatpay_status status;

	/* What's happened so far? */
	struct payment_log **logs;

	/* BOLT-12 offer */
	const struct tlv_offer *offer;

	/* Maximum amount as specified by user (msat or currency) */
	struct payment_max payment_max;
	/* Converted amount (FIXME: refresh!) */
	struct amount_msat max_amount_msat;

	/* Where are we up to in the sequence? */
	u32 recurrence_counter, recurrence_start;

	/* Raw JSON string, potentially containing escapes */
	struct json_escape *label;

	/* Unique payer id to make these payments: valid if payer_metadata
	 * non-NULL. */
	const u8 *payer_metadata;
	struct pubkey payer_id;

	/* If we're going to do something in future, this is it */
	struct plugin_timer *next;

	/* Base time for period calculation.  Only used if offer
	 * does *not* have offer_recurrence_base. */
	u64 basetime;

	/* When's the deadline for this payment? */
	u64 deadline;
};

static struct json_escape *payment_keyof(const struct payment *payment)
{
	return payment->label;
}

static bool payment_label_eq(const struct payment *payment,
			     const struct json_escape *label)
{
	return json_escape_eq(payment->label, label);
}

static size_t hash_label(const struct json_escape *label)
{
	return hash_str(label->s);
}

HTABLE_DEFINE_NODUPS_TYPE(struct payment,
			  payment_keyof,
			  hash_label,
			  payment_label_eq,
			  payment_hash);

/* For the whole plugin */
struct repeatpay {
	/* All our repeat payments */
	struct payment_hash *payments;

	/* How long before expiry that we try paying */
	u64 gracetime;

	/* Aux command for ongoing payments. */
	struct command *aux_cmd;
};

static struct repeatpay *repeatpay_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct repeatpay);
}

static const char *repeatpay_status_str(enum repeatpay_status status)
{
	switch (status) {
	case REPEATPAY_ONGOING: return "ongoing";
	case REPEATPAY_ONGOING_MAKING_PAYMENT: return "ongoing_making_payment";
	case REPEATPAY_ONGOING_FAILING_AMOUNT: return "ongoing_failing_amount";
	case REPEATPAY_ONGOING_FAILING_BALANCE: return "ongoing_failing_balance";
	case REPEATPAY_ONGOING_FAILING_INVOICE: return "ongoing_failing_invoice";
	case REPEATPAY_ONGOING_FAILING_PAYMENT: return "ongoing_failing_payment";
	case REPEATPAY_COMPLETE_FINISHED: return "complete_finished";
	case REPEATPAY_COMPLETE_CANCELLED: return "complete_cancelled";
	case REPEATPAY_COMPLETE_CANCEL_PENDING: return "complete_cancel_pending";
	case REPEATPAY_COMPLETE_FAILED: return "complete_failed";
	}
	abort();
}

static bool payment_terminated(enum repeatpay_status status)
{
	switch (status) {
	case REPEATPAY_ONGOING:
	case REPEATPAY_ONGOING_MAKING_PAYMENT:
	case REPEATPAY_COMPLETE_CANCEL_PENDING:
	case REPEATPAY_ONGOING_FAILING_AMOUNT:
	case REPEATPAY_ONGOING_FAILING_BALANCE:
	case REPEATPAY_ONGOING_FAILING_INVOICE:
	case REPEATPAY_ONGOING_FAILING_PAYMENT:
		return false;

	case REPEATPAY_COMPLETE_FINISHED:
	case REPEATPAY_COMPLETE_CANCELLED:
	case REPEATPAY_COMPLETE_FAILED:
		return true;
	}
	abort();
}

static void PRINTF_FMT(4, 5)
payment_set_status(struct command *cmd,
		   struct payment *payment,
		   enum repeatpay_status status,
		   const char *fmt, ...)
{
	struct payment_log *log = tal(payment->logs, struct payment_log);

	va_list ap;
	va_start(ap, fmt);
	const char *msg = tal_vfmt(NULL, fmt, ap);
	plugin_log(cmd->plugin, LOG_DBG, "payment %s #%u: status %s->%s: %s",
		   payment->label->s,
		   /* Humans use 1-based counters */
		   payment->recurrence_counter + 1,
		   repeatpay_status_str(payment->status),
		   repeatpay_status_str(status),
		   msg);
	va_end(ap);

	/* No bringing stuff back from the dead! */
	assert(!payment_terminated(payment->status));

	log->msg = tal_steal(log, msg);
	log->status = status;
	tal_arr_expand(&payment->logs, log);
	payment->status = status;
}

/* Recursion.  This starts the next payment (if we're ready). */
static struct command_result *start_next_payment(struct command *aux_cmd,
						 struct payment *payment);

static const char *fmt_amount_for_currency(const tal_t *ctx,
					   const struct payment_max *payment_max)

{
	u64 divisor = 1;

	/* Format string according to minor_units. */
	if (payment_max->currency->minor_unit == 0)
		return tal_fmt(ctx, "%"PRIu64, payment_max->amount);

	for (size_t i = 0; i < payment_max->currency->minor_unit; i++)
		divisor *= 10;
	return tal_fmt(ctx, "%"PRIu64".%0*"PRIu64,
		       payment_max->amount / divisor,
		       (int)payment_max->currency->minor_unit,
		       payment_max->amount % divisor);
}

static struct command_result *fetch_invoice(struct command *cmd,
					    struct payment *payment,
					    struct command_result *(*cb)(struct command *command,
									 const char *methodname,
									 const char *buf,
									 const jsmntok_t *result,
									 struct payment *payment),
					    struct command_result *(*errcb)(struct command *command,
									    const char *methodname,
									    const char *buf,
									    const jsmntok_t *result,
									    struct payment *payment))
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "fetchinvoice", cb, errcb, payment);
	json_add_string(req->js, "offer", offer_encode(tmpctx, payment->offer));
	json_add_u32(req->js, "recurrence_counter", payment->recurrence_counter);
	if (payment->offer->offer_recurrence_base)
		json_add_u32(req->js, "recurrence_start", payment->recurrence_start);
	json_add_escaped_string(req->js, "recurrence_label", payment->label);
	return send_outreq(req);
}

static struct command_result *xpay_done(struct command *aux_cmd,
					const char *methodname,
					const char *buf,
					const jsmntok_t *result,
					struct payment *payment)
{
	const char *err;
	struct amount_msat delivered, sent, fee;

	err = json_scan(tmpctx, buf, result,
			"{amount_msat:%,amount_sent_msat:%}",
			JSON_SCAN(json_to_msat, &delivered),
			JSON_SCAN(json_to_msat, &sent));
	if (err)
		plugin_err(aux_cmd->plugin, "bad xpay response %.*s: %s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result),
			   err);

	if (!amount_msat_sub(&fee, sent, delivered)) {
		plugin_log(aux_cmd->plugin, LOG_BROKEN,
			   "repeatpay %s #%u delivered %s more than sent %s?",
			   offer_encode(tmpctx, payment->offer),
			   payment->recurrence_counter,
			   fmt_amount_msat(tmpctx, delivered),
			   fmt_amount_msat(tmpctx, sent));
		fee = AMOUNT_MSAT(0);
	}
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_ONGOING,
			   "Invoice #%u paid: %s, fee %s",
			   payment->recurrence_counter + 1,
			   fmt_amount_msat(tmpctx, delivered),
			   fmt_amount_msat(tmpctx, fee));
	payment->recurrence_counter++;
	return start_next_payment(aux_cmd, payment);
}

static struct command_result *timer_next_payment(struct command *aux_cmd,
						 struct payment *payment)
{
	return start_next_payment(aux_cmd, payment);
}

static struct command_result *retry_payment_later(struct command *aux_cmd,
						  struct payment *payment)
{
	u64 now = clock_time().ts.tv_sec, to_go;

	/* Late?  Let start_next_payment fail it */
	if (now > payment->deadline)
		return start_next_payment(aux_cmd, payment);

	/* Try in two hours, or halfway to deadline: whatever is less */
	to_go = (payment->deadline - now) / 2;
	if (to_go > 2 * 3600)
		to_go = 2 * 3600;
	/* Don't spam! */
	else if (to_go < 1)
		to_go = 1;

	payment->next = command_timer(aux_cmd,
				      time_from_sec(to_go),
				      timer_next_payment,
				      payment);
	return command_still_pending(aux_cmd);
}

static struct command_result *xpay_error(struct command *aux_cmd,
					 const char *methodname,
					 const char *buf,
					 const jsmntok_t *err,
					 struct payment *payment)
{
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_ONGOING_FAILING_PAYMENT,
			   "Paying invoice #%u failed: %.*s",
			   payment->recurrence_counter + 1,
			   json_tok_full_len(err),
			   json_tok_full(buf, err));
	return retry_payment_later(aux_cmd, payment);
}

static struct command_result *pay_invoice(struct command *aux_cmd,
					  struct payment *payment,
					  const struct tlv_invoice *inv)
{
	struct out_req *req;
	const char *invstr;

	/* BOLT-recurrence #12:
	 *   - if it pays the invoice:
	 *     - MUST have authorization for the payment purpose, recipient and amount.
	 */
	if (amount_msat_greater(amount_msat(*inv->invoice_amount), payment->max_amount_msat)) {
		payment_set_status(aux_cmd, payment,
				   REPEATPAY_ONGOING_FAILING_AMOUNT,
				   "Invoice #%u amount %s exceeds maximum %s",
				   payment->recurrence_counter + 1,
				   fmt_amount_msat(tmpctx, amount_msat(*inv->invoice_amount)),
				   fmt_amount_msat(tmpctx, payment->max_amount_msat));
		return retry_payment_later(aux_cmd, payment);
	}

	invstr = invoice_encode(tmpctx, inv);
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_ONGOING_MAKING_PAYMENT,
			   "Paying #%u %s %s",
			   payment->recurrence_counter + 1,
			   fmt_amount_msat(tmpctx, amount_msat(*inv->invoice_amount)),
			   invstr);

	req = jsonrpc_request_start(aux_cmd, "xpay", xpay_done, xpay_error, payment);
	json_add_string(req->js, "invstring", invstr);
	return send_outreq(req);
}

static struct command_result *fetch_done(struct command *aux_cmd,
					 const char *methodname,
					 const char *buf,
					 const jsmntok_t *result,
					 struct payment *payment)
{
	const jsmntok_t *invtok = json_get_member(buf, result, "invoice");
	struct tlv_invoice *inv;
	const char *err;

	inv = invoice_decode(tmpctx, buf + invtok->start,
			     invtok->end - invtok->start,
			     plugin_feature_set(aux_cmd->plugin),
			     chainparams, &err);
	if (!inv || !inv->invoice_recurrence_basetime || !inv->invoice_amount) {
		payment_set_status(aux_cmd, payment,
				   REPEATPAY_ONGOING_FAILING_INVOICE,
				   "fetchinvoice returned unparsable invoice %.*s: %s",
				   json_tok_full_len(invtok),
				   json_tok_full(buf, invtok),
				   err);
		return retry_payment_later(aux_cmd, payment);
	}

	return pay_invoice(aux_cmd, payment, inv);
}

static struct command_result *fetch_failed(struct command *aux_cmd,
					   const char *methodname,
					   const char *buf,
					   const jsmntok_t *err,
					   struct payment *payment)
{
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_ONGOING_FAILING_INVOICE,
			   "fetchinvoice failed: %.*s",
			   json_tok_full_len(err),
			   json_tok_full(buf, err));
	return retry_payment_later(aux_cmd, payment);
}

static bool offer_recurrence_finished(const struct payment *payment)
{
	u64 period_idx = payment->recurrence_start + payment->recurrence_counter;

	/* BOLT-recurrence #12:
	 * - if `offer_recurrence_limit` is present:
	 * - MUST NOT send an `invoice_request` for a period index greater
         *  than `max_period_index`
	*/
	return (payment->offer->offer_recurrence_limit
		&& period_idx > *payment->offer->offer_recurrence_limit);
}

/* Returns time we should start trying to pay, populates *period_end */
static u64 when_to_pay(const struct repeatpay *rp,
		       const struct payment *payment,
		       u64 *period_end)
{
	u64 period_start, period_idx, paytime;

	period_idx = payment->recurrence_start + payment->recurrence_counter;

	offer_period_paywindow(offer_recurrence(payment->offer),
			       payment->offer->offer_recurrence_paywindow,
			       payment->offer->offer_recurrence_base,
			       payment->basetime,
			       period_idx,
			       &period_start, period_end);

	/* We give ourselves up to 5 days to pay, but we can't pay before
	 * period_start */
	paytime = *period_end - rp->gracetime;
	if (paytime < period_start)
		paytime = period_start;

	return paytime;
}

static const char *fmt_approx_time(const tal_t *ctx, u64 sec)
{
	static const struct {
		const char *name;
		u64 seconds;
	} units[] = {
		{ "second", 1},
		{ "minute", 60},
		{ "hour", 60 * 60},
		{ "day", 24 * 60 * 60},
		{ "week", 7 * 24 * 60 * 60},
		{ "month", 30 * 24 * 60 * 60},
		{ "year", 365 * 24 * 60 * 60},
	};
	for (size_t i = 0; i < ARRAY_SIZE(units); i++) {
		u64 n;
		if (i + 1 < ARRAY_SIZE(units) && sec >= units[i + 1].seconds)
			continue;
		n = (sec + units[i].seconds / 2) / units[i].seconds;
		return tal_fmt(ctx, "%"PRIu64" %s%s",
			       n, units[i].name, n == 1 ? "" : "s");
	}
	abort();
}

static struct command_result *start_next_payment(struct command *aux_cmd,
						 struct payment *payment)
{
	struct repeatpay *rp = repeatpay_of(aux_cmd->plugin);
	u64 paytime, now = clock_time().ts.tv_sec;

	assert(!payment_terminated(payment->status));
	if (offer_recurrence_finished(payment)) {
		payment_set_status(aux_cmd, payment, REPEATPAY_COMPLETE_FINISHED,
				   "Finished paying after %u occurrences",
				   payment->recurrence_counter);
		return command_still_pending(aux_cmd);
	}

	/* When should we pay? */
	paytime = when_to_pay(rp, payment, &payment->deadline);

	/* BOLT-recurrence #12:
	 *  - SHOULD NOT send an `invoice_request` for a period which has
	 *    already passed.
	 */
	if (now > payment->deadline) {
		payment_set_status(aux_cmd, payment, REPEATPAY_COMPLETE_FAILED,
				   "Missed out on payment (deadline %"PRIu64", now it's %"PRIu64")",
				   payment->deadline, now);
		return command_still_pending(aux_cmd);
	}

	if (now < paytime) {
		payment_set_status(aux_cmd, payment, REPEATPAY_ONGOING,
				   "Waiting %s before fetching",
				   fmt_approx_time(tmpctx, paytime - now));
		payment->next = command_timer(aux_cmd,
					      time_from_sec(paytime - now),
					      timer_next_payment,
					      payment);
		return command_still_pending(aux_cmd);
	}

	return fetch_invoice(aux_cmd, payment, fetch_done, fetch_failed);
}

static void json_add_payment(struct json_stream *result,
			     const struct payment *payment)
{
	const struct payment_log *prev;
	size_t num_repeats;

	json_add_string(result, "offer", offer_encode(tmpctx, payment->offer));
	json_add_amount_msat(result, "maxamount_msat", payment->max_amount_msat);
	if (payment->payment_max.currency)
		json_add_string(result, "maxamount_currency",
				fmt_amount_for_currency(tmpctx, &payment->payment_max));
	json_add_escaped_string(result, "label", payment->label);
	/* If we had to wait before sending invoice, this may not be set! */
	if (payment->payer_metadata) {
		json_add_pubkey(result, "payer_id", &payment->payer_id);
		json_add_hex_talarr(result, "payer_metadata",
				    payment->payer_metadata);
	}
	json_add_string(result, "status", repeatpay_status_str(payment->status));
	json_add_u64(result, "payments_made", payment->recurrence_counter);

	json_array_start(result, "log");
	prev = NULL;
	num_repeats = 0;
	for (size_t i = 0; i < tal_count(payment->logs); i++) {
		const struct payment_log *log = payment->logs[i];
		if (prev && log->status != prev->status) {
			/* Flush the completed group using prev's message. */
			if (num_repeats)
				json_add_str_fmt(result, NULL,
						 "%zu times: %s",
						 num_repeats + 1, prev->msg);
			else
				json_add_string(result, NULL, prev->msg);
			num_repeats = 0;
			prev = log;
		} else if (!prev) {
			prev = log;
		} else {
			num_repeats++;
		}
	}

	/* Flush the last group. */
	if (prev) {
		if (num_repeats)
			json_add_str_fmt(result, NULL,
					 "%zu times: %s",
					 num_repeats + 1, prev->msg);
		else
			json_add_string(result, NULL, prev->msg);
	}
	json_array_end(result);
}

/* This returns the first invoice, which has all the fields that the
 * invoice_request has, so we can simply extract those */
static struct command_result *first_fetch_succeeded(struct command *cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *result,
						    struct payment *payment)
{
	struct repeatpay *rp = repeatpay_of(cmd->plugin);
	const jsmntok_t *invtok = json_get_member(buf, result, "invoice");
	struct tlv_invoice *inv;
	struct json_stream *response;
	const char *err;

	inv = invoice_decode(tmpctx, buf + invtok->start,
			     invtok->end - invtok->start,
			     plugin_feature_set(cmd->plugin),
			     chainparams, &err);
	if (!inv || !inv->invoice_recurrence_basetime) {
		return command_fail(cmd, LIGHTNINGD,
				    "fetchinvoice returned unparsable invoice %.*s",
				    json_tok_full_len(invtok),
				    json_tok_full(buf, invtok));
	}

	/* We could have added the same one while we were fetching, so check
	 * again! */
	if (payment_hash_get(rp->payments, payment->label))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Raced with identical repeatpay label!");

	/* Fill in remaining fields: now we have a payment! */
	payment->payer_id = *inv->invreq_payer_id;
	payment->basetime = *inv->invoice_recurrence_basetime;
	payment->payer_metadata = tal_dup_talarr(payment, u8, inv->invreq_metadata);

	tal_steal(rp, payment);
	payment_hash_add(rp->payments, payment);

	/* Set deadline so retry_payment_later works if pay_invoice fails */
	when_to_pay(rp, payment, &payment->deadline);

	/* OK, we can try to pay this right now */
	pay_invoice(rp->aux_cmd, payment, inv);

	response = jsonrpc_stream_success(cmd);
	json_add_payment(response, payment);
	return command_finished(cmd, response);
}

static struct command_result *first_fetch_failed(struct command *cmd,
						 const char *method,
						 const char *buf,
						 const jsmntok_t *result,
						 struct payment *payment)
{
	return forward_error(cmd, method, buf, result, payment);
}

static struct command_result *fetch_first_invoice(struct command *cmd,
						  struct payment *payment)
{
	struct repeatpay *rp = repeatpay_of(cmd->plugin);

	/* If it has a fixed paywindow, we might need to wait! */
	if (payment->offer->offer_recurrence_paywindow) {
		u64 now = clock_time().ts.tv_sec;
		u64 paytime = when_to_pay(rp, payment, &payment->deadline);

		/* BOLT-recurrence #12:
		 *  - SHOULD NOT send an `invoice_request` for a period which has
		 *    already passed.
		 */
		if (now > payment->deadline) {
			return command_fail(cmd, PAY_INVOICE_EXPIRED,
					    "Missed out on first payment deadline %"PRIu64", now it's %"PRIu64"",
					    payment->deadline, now);
		}

		if (now < paytime) {
			struct json_stream *response;

			payment_set_status(rp->aux_cmd, payment,
					   REPEATPAY_ONGOING,
					   "Waiting %s before fetching",
					   fmt_approx_time(tmpctx, paytime - now));
			payment->next = command_timer(rp->aux_cmd,
						      time_from_sec(paytime - now),
						      timer_next_payment,
						      payment);
			/* Make it clear this does not have payer_key yet. */
			payment->payer_metadata = NULL;
			tal_steal(rp, payment);
			payment_hash_add(rp->payments, payment);
			response = jsonrpc_stream_success(cmd);
			json_add_payment(response, payment);
			return command_finished(cmd, response);
		}
	}

	return fetch_invoice(cmd, payment,
			     first_fetch_succeeded, first_fetch_failed);
}

static struct command_result *first_currencyconvert_done(struct command *cmd,
							 const char *method,
							 const char *buf,
							 const jsmntok_t *result,
							 struct payment *payment)
{
	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{msat:%}",
			JSON_SCAN(json_to_msat, &payment->max_amount_msat));
	if (err)
		return command_fail(cmd, LIGHTNINGD,
				    "currencyconvert weird: %.*s (%s)",
				    json_tok_full_len(result),
				    json_tok_full(buf, result),
				    err);

	return fetch_first_invoice(cmd, payment);
}

static struct command_result *param_payment_max(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct payment_max *payment_max)
{
	const char *err;
	u64 *amt;

	err = parse_currency_amount(tmpctx,
				    buffer + tok->start,
				    tok->end - tok->start,
				    &payment_max->currency,
				    &amt);
	if (err)
		return command_fail_badparam(cmd, name, buffer, tok, err);
	/* We don't accept "any" */
	if (!amt)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Must specify amount, not 'any'");
	payment_max->amount = *amt;
	return NULL;
}

static struct command_result *json_repeatpay(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	struct repeatpay *rp = repeatpay_of(cmd->plugin);
	const char *offer;
	struct payment *payment;
	const char *fail;
	u32 *recurrence_start;

	/* We'll steal this into rp, if we succeed */
	payment = tal(cmd, struct payment);

	if (!param_check(cmd, buffer, params,
			 p_req("bolt12", param_string, &offer),
			 p_req("maxamount", param_payment_max, &payment->payment_max),
			 p_req("label", param_label, &payment->label),
			 p_opt("recurrence_start", param_number,
			       &recurrence_start),
			 NULL))
		return command_param_failed();

	/* Validate offer and require recurrence */
	payment->recurrence_counter = 0;
	payment->status = REPEATPAY_ONGOING;
	payment->logs = tal_arr(payment, struct payment_log *, 0);
	tal_steal(payment, payment->label);
	payment->offer = offer_decode(payment, offer, strlen(offer),
				      plugin_feature_set(cmd->plugin),
				      chainparams,
				      &fail);
	if (!payment->offer)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid offer: %s", fail);
	if (!offer_recurrence(payment->offer))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Offer has no recurrence");
	if (!payment->offer->offer_amount)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Offer has no amount specified");
	if (recurrence_start) {
		if (!payment->offer->offer_recurrence_base)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Cannot have recurrence_start except for offers with recurrence_base");
		payment->recurrence_start = *recurrence_start;
	} else
		payment->recurrence_start = 0;

	/* Check label uniqueness */
	if (payment_hash_get(rp->payments, payment->label))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Duplicate label '%s'", payment->label->s);

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Do initial conversion to get max amount in sats */
	if (payment->payment_max.currency) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd, "currencyconvert",
					    first_currencyconvert_done,
					    forward_error,
					    payment);
		json_add_primitive(req->js, "amount",
				   fmt_amount_for_currency(tmpctx, &payment->payment_max));
		json_add_string(req->js, "currency", payment->payment_max.currency->name);
		return send_outreq(req);
	}

	payment->max_amount_msat = amount_msat(payment->payment_max.amount);

	/* Now we do initial fetchinvoice.  This is what the user expects:
	 * check that the invoice basically works.  It also gets us the
	 * payer_id. */
	return fetch_first_invoice(cmd, payment);
}

static struct command_result *json_listrepeatpays(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *params)
{
	struct repeatpay *rp = repeatpay_of(cmd->plugin);
	struct json_escape *label;
	struct json_stream *response;
	struct payment_hash_iter iter;
	struct payment *payment;

	if (!param(cmd, buffer, params,
		   p_opt("label", param_label, &label),
		   NULL))
		return command_param_failed();

	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "repeatpays");
	for (payment = payment_hash_first(rp->payments, &iter);
	     payment;
	     payment = payment_hash_next(rp->payments, &iter)) {
		if (label && !payment_label_eq(payment, label))
			continue;
		json_object_start(response, NULL);
		json_add_payment(response, payment);
		json_object_end(response);
	}
	json_array_end(response);
	return command_finished(cmd, response);
}

static const struct plugin_command commands[] = {
	{
		"repeatpay",
		json_repeatpay,
	},
	{
		"listrepeatpays",
		json_listrepeatpays,
	},
};

static const char *init(struct command *init_cmd,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct repeatpay *rp = repeatpay_of(init_cmd->plugin);
	rp->aux_cmd = aux_command(init_cmd);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct repeatpay *repeatpay;

	setup_locale();
	repeatpay = tal(NULL, struct repeatpay);
	repeatpay->payments = new_htable(repeatpay, payment_hash);
	repeatpay->gracetime = 5 * 24 * 60 * 60; /* 5 days */
	plugin_main(argv, init, take(repeatpay),
		    PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    NULL, 0,
		    NULL, 0,
	            NULL, 0,
		    plugin_option_dev("dev-repeatpay-grace-time",
				      "int",
				      "How long before deadline do we request invoice?",
				      u64_option, u64_jsonfmt,
				      &repeatpay->gracetime),
		    NULL);
}
