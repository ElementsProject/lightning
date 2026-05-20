#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/json_out/json_out.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12.h>
#include <common/bolt12_id.h>
#include <common/clock_time.h>
#include <common/hash_str.h>
#include <common/iso4217.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/mkdatastorekey.h>
#include <common/randbytes.h>
#include <common/utils.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

/* There is an overall "cancel_reason" flag which marks state as complete_cancel_pending */
enum repeatpay_status {
	REPEATPAY_ONGOING,
	REPEATPAY_ONGOING_MAKING_PAYMENT,
	REPEATPAY_ONGOING_FAILING_AMOUNT,
	REPEATPAY_ONGOING_FAILING_BALANCE,
	REPEATPAY_ONGOING_FAILING_INVOICE,
	REPEATPAY_ONGOING_FAILING_PAYMENT,
	REPEATPAY_COMPLETE_FINISHED,
	REPEATPAY_COMPLETE_CANCELLED,
	REPEATPAY_COMPLETE_FAILED,
#define MAX_REPEATPAY_STATUS REPEATPAY_COMPLETE_FAILED
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

	/* Non-NULL if are we trying to cancel.  If non-empty, send this as a note */
	const char *cancel_reason;

	/* What's happened so far? */
	struct payment_log **logs;

	/* BOLT-12 offer */
	const struct tlv_offer *offer;

	/* Maximum amount as specified by user (msat or currency) */
	struct payment_max payment_max;
	/* Converted amount */
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
	case REPEATPAY_COMPLETE_FAILED: return "complete_failed";
	}
	abort();
}

static bool repeatpay_status_from_str(const char *str, size_t len, enum repeatpay_status *status)
{
	for (int i = 0; i <= MAX_REPEATPAY_STATUS; i++) {
		if (memeqstr(str, len, repeatpay_status_str(i))) {
			*status = i;
			return true;
		}
	}
	return false;
}

static bool payment_terminated(enum repeatpay_status status)
{
	switch (status) {
	case REPEATPAY_ONGOING:
	case REPEATPAY_ONGOING_MAKING_PAYMENT:
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

/* Datastore key for a field of a payment. */
static const char **payment_ds_key(const tal_t *ctx,
				    const struct json_escape *label,
				    const char *field)
{
	return mkdatastorekey(ctx, "cln-repeatpay", label->s, field);
}

/* Restore log entries from the serialized form. */
static struct payment_log **parse_payment_log(const tal_t *ctx, const char *buf, const jsmntok_t *hextok)
{
	struct payment_log **logs;
	char **lines, *ourstr;
	size_t len = hextok->end - hextok->start;

	ourstr = tal_arr(tmpctx, char, hex_data_size(len) + 1);
	if (!hex_decode(buf + hextok->start, len, ourstr, hex_data_size(len)))
		return NULL;
	ourstr[hex_data_size(len)] = '\0';

	lines = tal_strsplit(tmpctx, take(ourstr), "\n", STR_NO_EMPTY);
	logs = tal_arr(ctx, struct payment_log *, tal_count(lines) - 1);
	for (size_t i = 0; lines[i]; i++) {
		size_t statuslen = strcspn(lines[i], ":");

		if (lines[i][statuslen] == '\0')
			return tal_free(logs);
		logs[i] = tal(logs, struct payment_log);
		if (!repeatpay_status_from_str(lines[i], statuslen, &logs[i]->status))
			return tal_free(logs);
		logs[i]->msg = tal_strdup(logs[i], lines[i] + statuslen + 1);
	}
	return logs;
}

/* Ignore datastore responses: keep aux_cmd alive (unlike ignore_and_complete). */
static struct command_result *datastore_ok(struct command *cmd,
					   const char *methodname UNUSED,
					   const char *buf UNUSED,
					   const jsmntok_t *result UNUSED,
					   void *arg UNUSED)
{
	return command_still_pending(cmd);
}

/* Append new log entry as "status:msg\n". */
static void save_payment_log(struct command *cmd,
			     const struct payment *payment,
			     enum repeatpay_status status,
			     const char *msg)
{
	const char *newlog = tal_fmt(tmpctx, "%s:%s\n",
				     repeatpay_status_str(status), msg);
	/* If we set this as a string, the "\n" gets mangled! */
	jsonrpc_set_datastore_binary(cmd,
				     payment_ds_key(tmpctx, payment->label, "log"),
				     newlog, strlen(newlog),
				     "create-or-append", datastore_ok, NULL, NULL);
}

static void save_payment_status(struct command *cmd,
				const struct payment *payment)
{
	jsonrpc_set_datastore_string(cmd,
				     payment_ds_key(tmpctx, payment->label, "status"),
				     repeatpay_status_str(payment->status),
				     "create-or-replace", datastore_ok, NULL, NULL);
}

static void save_payment_cancel_reason(struct command *cmd,
				       const struct payment *payment)
{
	if (payment->cancel_reason)
		jsonrpc_set_datastore_string(cmd,
					     payment_ds_key(tmpctx, payment->label, "cancel_reason"),
					     payment->cancel_reason,
					     "create-or-replace", datastore_ok, NULL, NULL);
}

static void PRINTF_FMT(4, 5)
payment_set_status(struct command *cmd,
		   struct payment *payment,
		   enum repeatpay_status status,
		   const char *fmt, ...)
{
	struct repeatpay *rp = repeatpay_of(cmd->plugin);
	struct payment_log *log = tal(payment->logs, struct payment_log);

	va_list ap;
	va_start(ap, fmt);
	const char *msg = tal_vfmt(NULL, fmt, ap);
	plugin_log(cmd->plugin, LOG_DBG, "payment %s #%u: status %s->%s%s: %s",
		   payment->label->s,
		   /* Humans use 1-based counters */
		   payment->recurrence_counter + 1,
		   repeatpay_status_str(payment->status),
		   repeatpay_status_str(status),
		   payment->cancel_reason ? " (cancel pending)" : "",
		   msg);
	va_end(ap);

	/* No bringing stuff back from the dead! */
	assert(!payment_terminated(payment->status));

	log->msg = tal_steal(log, msg);
	log->status = status;
	tal_arr_expand(&payment->logs, log);
	payment->status = status;

	/* If it's saved, write to datastore */
	if (payment_hash_get(rp->payments, payment->label)) {
		save_payment_log(cmd, payment, status, msg);
		save_payment_status(cmd, payment);
		save_payment_cancel_reason(cmd, payment);
	}
}

/* Update recurrence_counter after a successful payment. */
static void save_payment_counter(struct command *aux_cmd,
				  const struct payment *payment)
{
	jsonrpc_set_datastore_string(aux_cmd,
				     payment_ds_key(tmpctx, payment->label,
						    "recurrence_counter"),
				     tal_fmt(tmpctx, "%"PRIu32,
					     payment->recurrence_counter),
				     "create-or-replace", datastore_ok, NULL, NULL);
}

/* Payment should now persist. */
static void save_payment(struct repeatpay *rp, struct payment *payment)
{
	tal_steal(rp, payment);
	payment_hash_add(rp->payments, payment);

	jsonrpc_set_datastore_string(rp->aux_cmd,
				     payment_ds_key(tmpctx, payment->label, "offer"),
				     offer_encode(tmpctx, payment->offer),
				     "create-or-replace", datastore_ok, NULL, NULL);
	jsonrpc_set_datastore_string(rp->aux_cmd,
				     payment_ds_key(tmpctx, payment->label, "max_amount_msat"),
				     tal_fmt(tmpctx, "%"PRIu64,
					     payment->max_amount_msat.millisatoshis), /* Raw: datastore */
				     "create-or-replace", datastore_ok, NULL, NULL);
	jsonrpc_set_datastore_string(rp->aux_cmd,
				     payment_ds_key(tmpctx, payment->label, "payment_max_amount"),
				     tal_fmt(tmpctx, "%"PRIu64, payment->payment_max.amount),
				     "create-or-replace", datastore_ok, NULL, NULL);
	if (payment->payment_max.currency) {
		jsonrpc_set_datastore_string(rp->aux_cmd,
					     payment_ds_key(tmpctx, payment->label, "payment_max_currency"),
					     payment->payment_max.currency->name,
					     "create-or-replace", datastore_ok, NULL, NULL);
	}
	jsonrpc_set_datastore_string(rp->aux_cmd,
				     payment_ds_key(tmpctx, payment->label, "recurrence_start"),
				     tal_fmt(tmpctx, "%"PRIu32,
					     payment->recurrence_start),
				     "create-or-replace", datastore_ok, NULL, NULL);
	jsonrpc_set_datastore_string(rp->aux_cmd,
				     payment_ds_key(tmpctx, payment->label, "basetime"),
				     tal_fmt(tmpctx, "%"PRIu64, payment->basetime),
				     "create-or-replace", datastore_ok, NULL, NULL);
	if (payment->payer_metadata) {
		jsonrpc_set_datastore_string(rp->aux_cmd,
					     payment_ds_key(tmpctx, payment->label, "payer_id"),
					     fmt_pubkey(tmpctx, &payment->payer_id),
					     "create-or-replace", datastore_ok, NULL, NULL);
		jsonrpc_set_datastore_string(rp->aux_cmd,
					     payment_ds_key(tmpctx, payment->label,
							    "payer_metadata"),
					     tal_hexstr(tmpctx,
							payment->payer_metadata,
							tal_count(payment->payer_metadata)),
					     "create-or-replace", datastore_ok, NULL, NULL);
	}

	save_payment_counter(rp->aux_cmd, payment);
	save_payment_status(rp->aux_cmd, payment);
	save_payment_cancel_reason(rp->aux_cmd, payment);
	for (size_t i = 0; i < tal_count(payment->logs); i++)
		save_payment_log(rp->aux_cmd, payment, payment->logs[i]->status, payment->logs[i]->msg);
}

/* forward declaration */
static struct command_result *start_next_payment(struct command *aux_cmd,
						 struct payment *payment);

/* While you were sleeping... */
static void payment_offline_success(struct command *aux_cmd,
				    struct payment *payment)
{
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_ONGOING,
			   "Invoice paid while we were restarting");
	payment->recurrence_counter++;
	save_payment_counter(aux_cmd, payment);
}

static void payment_offline_failure(struct command *aux_cmd,
				    struct payment *payment)
{
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_ONGOING_FAILING_PAYMENT,
			   "Payment attempt failed while we were restarting");
}

struct pending_payment {
	struct payment *payment;
	struct sha256 payment_hash;
	u64 max_changed_idx;
};

static struct command_result *arm_pending_watch(struct command *aux_cmd,
						struct pending_payment *pending);

static struct command_result *pending_listpays_done(struct command *aux_cmd,
						    const char *methodname,
						    const char *buf,
						    const jsmntok_t *result,
						    struct pending_payment *pending)
{
	const jsmntok_t *payments, *t;
	size_t i;

	payments = json_get_member(buf, result, "payments");
	json_for_each_arr(i, t, payments) {
		const jsmntok_t *status;

		status = json_get_member(buf, t, "status");
		/* Pending?  Wait again. */
		if (json_tok_streq(buf, status, "pending"))
			return arm_pending_watch(aux_cmd, pending);

		/* Success?  That one's done, continue. */
		if (json_tok_streq(buf, status, "complete")) {
			payment_offline_success(aux_cmd, pending->payment);
			start_next_payment(aux_cmd, pending->payment);
			tal_free(pending);
			return command_still_pending(aux_cmd);
		}
	}

	/* Failure? Continue. */
	payment_offline_failure(aux_cmd, pending->payment);
	start_next_payment(aux_cmd, pending->payment);
	tal_free(pending);
	return command_still_pending(aux_cmd);
}

static struct command_result *pending_wait_done(struct command *aux_cmd,
						const char *methodname,
						const char *buf,
						const jsmntok_t *result,
						struct pending_payment *pending)
{
	const jsmntok_t *updated, *sendpays, *hash;
	struct out_req *req;

	updated = json_get_member(buf, result, "updated");
	if (!updated
	    || !json_to_u64(buf, updated, &pending->max_changed_idx)) {
		plugin_err(aux_cmd->plugin,
			   "bad updated in wait response %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	}

	/* This isn't present if we've fallen behind: we use it as an
	 * optimization. */
	sendpays = json_get_member(buf, result, "sendpays");
	if (sendpays) {
		hash = json_get_member(buf, sendpays, "payment_hash");
		if (hash) {
			struct sha256 payment_hash;
			if (!json_to_sha256(buf, hash, &payment_hash))
				plugin_err(aux_cmd->plugin,
					   "bad payment_hash in wait %.*s",
					   json_tok_full_len(result),
					   json_tok_full(buf, result));
			/* Wrong hash?  Go back to watching */
			if (!sha256_eq(&payment_hash, &pending->payment_hash))
				return arm_pending_watch(aux_cmd, pending);
		}
	}

	/* Label is not indexed, payment_hash is, so list by that */
	req = jsonrpc_request_start(aux_cmd, "listsendpays",
				    pending_listpays_done, plugin_broken_cb,
				    pending);
	json_add_sha256(req->js, "payment_hash", &pending->payment_hash);
	return send_outreq(req);
}

static struct command_result *arm_pending_watch(struct command *aux_cmd,
						struct pending_payment *pending)
{
	struct out_req *req;

	req = jsonrpc_request_start(aux_cmd, "wait",
				    pending_wait_done, plugin_broken_cb,
				    pending);
	json_add_string(req->js, "subsystem", "sendpays");
	json_add_string(req->js, "indexname", "updated");
	json_add_u64(req->js, "nextvalue", pending->max_changed_idx + 1);
	return send_outreq(req);
}

/* Returns the bolt12 invoice string from the last MAKING_PAYMENT log entry.
 * We logged "Paying <amount> <invstr>" when we called xpay. */
static const char *invstr_from_making_payment_log(const struct payment *payment)
{
	for (ssize_t i = tal_count(payment->logs) - 1; i >= 0; i--) {
		if (payment->logs[i]->status == REPEATPAY_ONGOING_MAKING_PAYMENT) {
			/* "Paying <amount> <invstr>": invstr follows the last space */
			const char *sp = strrchr(payment->logs[i]->msg, ' ');
			if (sp)
				return sp + 1;
		}
	}
	return NULL;
}

/* Returns true if we are still going. */
static bool payment_in_progress(struct command *init_cmd,
				struct repeatpay *rp,
				struct payment *payment,
				const char *label_str UNUSED)
{
	const jsmntok_t *reply, *payments, *t;
	const char *buf, *invstr;
	struct json_out *params;
	struct pending_payment *pending;
	size_t i;

	if (payment->status != REPEATPAY_ONGOING_MAKING_PAYMENT)
		return false;

	/* listsendpays doesn't support label; recover the invoice string from
	 * the log so we can search by bolt11 instead. */
	invstr = invstr_from_making_payment_log(payment);
	if (!invstr) {
		/* Can't identify the in-flight invoice; be conservative. */
		payment_offline_failure(rp->aux_cmd, payment);
		return false;
	}

	params = json_out_new(tmpctx);
	json_out_start(params, NULL, '{');
	json_out_addstr(params, "bolt11", invstr);
	json_out_end(params, '}');
	json_out_finished(params);

	reply = jsonrpc_request_sync(tmpctx, init_cmd, "listsendpays",
				     take(params), &buf);
	payments = json_get_member(buf, reply, "payments");
	pending = NULL;
	json_for_each_arr(i, t, payments) {
		const jsmntok_t *status, *updated;
		u64 idx;

		status = json_get_member(buf, t, "status");

		/* If any part succeeded, everything is good. */
		if (json_tok_streq(buf, status, "complete")) {
			payment_offline_success(rp->aux_cmd, payment);
			return false;
		}
		/* If they all fail, we'll know */
		if (!json_tok_streq(buf, status, "pending"))
			continue;

		/* Still pending.  Grab payment hash if not already */
		if (!pending) {
			const jsmntok_t *hashtok
				= json_get_member(buf, t, "payment_hash");
			pending = tal(payment, struct pending_payment);
			pending->payment = payment;
			pending->max_changed_idx = 0;
			if (!hashtok
			    || !json_to_sha256(buf, hashtok,
					       &pending->payment_hash)) {
				plugin_err(rp->aux_cmd->plugin,
					   "bad payment_hash in %.*s",
					   json_tok_full_len(t),
					   json_tok_full(buf, t));
			}
		}

		updated = json_get_member(buf, t, "updated_index");
		if (updated
		    && json_to_u64(buf, updated, &idx)
		    && idx > pending->max_changed_idx) {
			pending->max_changed_idx = idx;
		}
	}

	/* No parts pending means we failed over restart. */
	if (!pending) {
		payment_offline_failure(rp->aux_cmd, payment);
		return false;
	}

	/* Still going.  We do the simplistic thing: watch and poll. */
	arm_pending_watch(rp->aux_cmd, pending);
	return true;
}

static void restore_payment(struct command *init_cmd,
			     struct repeatpay *rp,
			     const char *label_str)
{
	struct payment *payment = tal(rp, struct payment);
	const jsmntok_t *reply, *ds, *t;
	const char *buf;
	struct json_out *params;
	size_t i;
	/* Required-field flags for scalars (pointers above serve as their own flags) */
	bool have_status = false, have_max_amount = false;
	bool have_counter = false, have_start = false, have_basetime = false;
	bool have_payment_max_amount = false, have_payer_id = false;

	payment->label = json_escape_string_(payment, label_str, strlen(label_str));
	payment->next = NULL;
	payment->deadline = 0;
	payment->offer = NULL;
	payment->logs = NULL;
	/* Optional fields default to absent */
	payment->payment_max.currency = NULL;
	payment->payer_metadata = NULL;
	payment->cancel_reason = NULL;

	/* Fetch all fields for this label in one call. */
	params = json_out_new(tmpctx);
	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "cln-repeatpay");
	json_out_addstr(params, NULL, label_str);
	json_out_end(params, ']');
	json_out_end(params, '}');
	json_out_finished(params);

	reply = jsonrpc_request_sync(tmpctx, init_cmd, "listdatastore",
				     take(params), &buf);
	ds = json_get_member(buf, reply, "datastore");

	json_for_each_arr(i, t, ds) {
		const jsmntok_t *keytok = json_get_member(buf, t, "key");
		const jsmntok_t *strtok = json_get_member(buf, t, "string");
		const char *str;
		size_t len;

		if (!keytok || keytok->size != 3 || !strtok)
			continue;

		str = buf + strtok->start;
		len = strtok->end - strtok->start;
		if (json_tok_streq(buf, keytok + 3, "offer")) {
			const char *fail;
			payment->offer = offer_decode(payment, str, len,
						      plugin_feature_set(init_cmd->plugin),
						      chainparams, &fail);
		} else if (json_tok_streq(buf, keytok + 3, "status")) {
			if (!repeatpay_status_from_str(str, len, &payment->status))
				goto bad;
			have_status = true;
		} else if (json_tok_streq(buf, keytok + 3, "max_amount_msat")) {
			if (!json_to_msat(buf, strtok, &payment->max_amount_msat))
				goto bad;
			have_max_amount = true;
		} else if (json_tok_streq(buf, keytok + 3, "recurrence_counter")) {
			if (!json_to_u32(buf, strtok, &payment->recurrence_counter))
				goto bad;
			have_counter = true;
		} else if (json_tok_streq(buf, keytok + 3, "recurrence_start")) {
			if (!json_to_u32(buf, strtok, &payment->recurrence_start))
				goto bad;
			have_start = true;
		} else if (json_tok_streq(buf, keytok + 3, "basetime")) {
			if (!json_to_u64(buf, strtok, &payment->basetime))
				goto bad;
			have_basetime = true;
		} else if (json_tok_streq(buf, keytok + 3, "log")) {
			payment->logs = parse_payment_log(payment, buf, json_get_member(buf, t, "hex"));
		} else if (json_tok_streq(buf, keytok + 3, "payment_max_currency")) {
			payment->payment_max.currency = find_iso4217(str, len);
			if (!payment->payment_max.currency)
				goto bad;
		} else if (json_tok_streq(buf, keytok + 3, "payment_max_amount")) {
			if (!json_to_u64(buf, strtok, &payment->payment_max.amount))
				goto bad;
			have_payment_max_amount = true;
		} else if (json_tok_streq(buf, keytok + 3, "payer_id")) {
			if (!pubkey_from_hexstr(str, len, &payment->payer_id))
				goto bad;
			have_payer_id = true;
		} else if (json_tok_streq(buf, keytok + 3, "payer_metadata")) {
			payment->payer_metadata = tal_hexdata(payment, str, len);
		} else if (json_tok_streq(buf, keytok + 3, "cancel_reason")) {
			payment->cancel_reason = tal_strndup(payment, str, len);
		} else
			plugin_err(init_cmd->plugin,
				   "Unknown datastore field '%.*s'",
				   json_tok_full_len(keytok + 3),
				   json_tok_full(buf, keytok + 3));
	}

	/* Validate required fields */
	if (!payment->offer
	    || !have_status
	    || !have_max_amount
	    || !have_counter
	    || !have_start
	    || !have_basetime
	    || !have_payment_max_amount
	    || !payment->logs)
		goto bad;

	if (payment->payer_metadata && !have_payer_id)
		goto bad;

	payment_hash_add(rp->payments, payment);

	/* Resume non-terminated payments. */
	if (!payment_terminated(payment->status)) {
		if (!payment_in_progress(init_cmd, rp, payment, label_str)) {
			start_next_payment(rp->aux_cmd, payment);
		}
	}
	return;

bad:
	plugin_log(init_cmd->plugin, LOG_BROKEN,
		   "repeatpay: ignoring malformed datastore entry for '%s'",
		   label_str);
	tal_free(payment);
}

static void restore_payments(struct command *init_cmd, struct repeatpay *rp)
{
	const jsmntok_t *reply, *ds, *t;
	const char *buf;
	struct json_out *params;
	size_t i;

	params = json_out_new(tmpctx);
	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "cln-repeatpay");
	json_out_end(params, ']');
	json_out_end(params, '}');
	json_out_finished(params);

	reply = jsonrpc_request_sync(tmpctx, init_cmd, "listdatastore",
				     take(params), &buf);
	ds = json_get_member(buf, reply, "datastore");

	/* listdatastore returns immediate children only: each entry is
	 * ["cln-repeatpay", "<label>"] with data=NULL (summary node). */
	json_for_each_arr(i, t, ds) {
		const jsmntok_t *keytok = json_get_member(buf, t, "key");
		char *label_str;

		if (!keytok || keytok->size != 2)
			continue;
		if (!json_tok_streq(buf, keytok + 1, "cln-repeatpay"))
			continue;
		label_str = json_strdup(tmpctx, buf, keytok + 2);
		restore_payment(init_cmd, rp, label_str);
	}
}

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
	save_payment_counter(aux_cmd, payment);
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
					 const jsmntok_t *error,
					 struct payment *payment)
{
	const jsmntok_t *msg;
	int code;
	enum repeatpay_status status;

	/* xpay gives nice error messages! */
	msg = json_get_member(buf, error, "message");
	json_to_int(buf, json_get_member(buf, error, "code"), &code);

	/* xpay (well, getroutes!) tells us if we're out of money. */
	if (code == PAY_INSUFFICIENT_FUNDS)
		status = REPEATPAY_ONGOING_FAILING_BALANCE;
	else
		status = REPEATPAY_ONGOING_FAILING_PAYMENT;

	payment_set_status(aux_cmd, payment,
			   status,
			   "Paying invoice #%u failed: %.*s",
			   payment->recurrence_counter + 1,
			   msg->end - msg->start,
			   buf + msg->start);
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

	/* If we cancelled in the meantime, throw that away and try again */
	if (payment->cancel_reason)
		return start_next_payment(aux_cmd, payment);

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

static void currencyconvert_result(struct command *cmd,
				   const char *buf,
				   const jsmntok_t *result,
				   struct amount_msat *msat)
{
	const char *err = json_scan(tmpctx, buf, result,
				    "{msat:%}",
				    JSON_SCAN(json_to_msat, msat));
	/* Shouldn't happen */
	if (err)
		plugin_err(cmd->plugin,
			   "bad currencyconvert response '%.*s'",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
}

static struct command_result *currencyconvert_done(struct command *aux_cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   struct payment *payment)
{
	currencyconvert_result(aux_cmd, buf, result, &payment->max_amount_msat);
	return fetch_invoice(aux_cmd, payment, fetch_done, fetch_failed);
}

static struct command_result *currencyconvert_error(struct command *aux_cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *err,
						    struct payment *payment)
{
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_ONGOING_FAILING_INVOICE,
			   "Bad currencyconvert return for %s%s: '%.*s'",
			   fmt_amount_for_currency(tmpctx,
						   &payment->payment_max),
			   payment->payment_max.currency->name,
			   json_tok_full_len(err),
			   json_tok_full(buf, err));
	return retry_payment_later(aux_cmd, payment);
}

static struct command_result *cancel_done(struct command *aux_cmd,
					  const char *method,
					  const char *buf,
					  const jsmntok_t *err,
					  struct payment *payment)
{
	payment_set_status(aux_cmd, payment,
			   REPEATPAY_COMPLETE_CANCELLED,
			   "Sent a cancel message%s%s",
			   streq(payment->cancel_reason, "") ? "": ": ",
			   payment->cancel_reason);
	return command_still_pending(aux_cmd);
}

static struct command_result *cancel_error(struct command *aux_cmd,
					   const char *method,
					   const char *buf,
					   const jsmntok_t *err,
					   struct payment *payment)
{
	payment_set_status(aux_cmd, payment, payment->status,
			   "Cancel attempt failed, will retry: '%.*s'",
			   json_tok_full_len(err),
			   json_tok_full(buf, err));
	return retry_payment_later(aux_cmd, payment);
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
				   "Waiting %s before %s",
				   fmt_approx_time(tmpctx, paytime - now),
				   payment->cancel_reason ? "cancelling" : "fetching");
		payment->next = command_timer(aux_cmd,
					      time_from_sec(paytime - now),
					      timer_next_payment,
					      payment);
		return command_still_pending(aux_cmd);
	}

	if (payment->cancel_reason) {
		struct out_req *req;

		req = jsonrpc_request_start(aux_cmd, "cancelrecurringinvoice", cancel_done, cancel_error, payment);
		json_add_string(req->js, "offer", offer_encode(tmpctx, payment->offer));
		json_add_u32(req->js, "recurrence_counter", payment->recurrence_counter);
		if (payment->offer->offer_recurrence_base)
			json_add_u32(req->js, "recurrence_start", payment->recurrence_start);
		json_add_escaped_string(req->js, "recurrence_label", payment->label);
		if (!streq(payment->cancel_reason, ""))
			json_add_string(req->js, "payer_note", payment->cancel_reason);
		/* We don't attach bip353 because we don't support recurring invoices from bip353! */
		return send_outreq(req);
	}

	/* Before fetching next invoice, ensure max is updated */
	if (payment->payment_max.currency) {
		struct out_req *req;

		req = jsonrpc_request_start(aux_cmd, "currencyconvert",
					    currencyconvert_done,
					    currencyconvert_error,
					    payment);
		json_add_primitive(req->js, "amount",
				   fmt_amount_for_currency(tmpctx,
							   &payment->payment_max));
		json_add_string(req->js, "currency", payment->payment_max.currency->name);
		return send_outreq(req);
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
	if (payment->cancel_reason && !payment_terminated(payment->status))
		json_add_string(result, "status", "complete_cancel_pending");
	else
		json_add_string(result, "status", repeatpay_status_str(payment->status));
	if (payment->cancel_reason && !streq(payment->cancel_reason, ""))
		json_add_string(result, "cancel_reason", payment->cancel_reason);
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

	save_payment(rp, payment);

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

			/* Make it clear this does not have payer_key yet. */
			payment->payer_metadata = NULL;
			payment->basetime = 0;
			save_payment(rp, payment);

			payment_set_status(rp->aux_cmd, payment,
					   REPEATPAY_ONGOING,
					   "Waiting %s before fetching",
					   fmt_approx_time(tmpctx, paytime - now));
			payment->next = command_timer(rp->aux_cmd,
						      time_from_sec(paytime - now),
						      timer_next_payment,
						      payment);
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
	currencyconvert_result(cmd, buf, result, &payment->max_amount_msat);
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
	payment->basetime = 0;
	payment->payer_metadata = NULL;
	payment->cancel_reason = NULL;
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

static struct command_result *amend_currencyconvert_done(struct command *cmd,
							 const char *method,
							 const char *buf,
							 const jsmntok_t *result,
							 struct payment *payment)
{
	struct json_stream *response;

	currencyconvert_result(cmd, buf, result, &payment->max_amount_msat);

	response = jsonrpc_stream_success(cmd);
	json_add_payment(response, payment);
	return command_finished(cmd, response);
}

static struct command_result *json_amendrepeatpay(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *params)
{
	struct repeatpay *rp = repeatpay_of(cmd->plugin);
	struct json_escape *label;
	struct payment_max max;
	struct json_stream *response;
	struct payment *payment;

	if (!param_check(cmd, buffer, params,
		   p_req("label", param_label, &label),
		   p_req("maxamount", param_payment_max, &max),
		   NULL))
		return command_param_failed();

	payment = payment_hash_get(rp->payments, label);
	if (!payment)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Unknown label '%s'", label->s);
	if (payment_terminated(payment->status))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Payment already finished (%s)",
				    repeatpay_status_str(payment->status));
	if (command_check_only(cmd))
		return command_check_done(cmd);

	payment->payment_max = max;

	/* We could be lazy and update max_amount_msat later, but it's shown
	 * in listrepeatpays, and we really should update it immediately even if
	 * there's a fetch in flight */
	if (max.currency) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd, "currencyconvert",
					    amend_currencyconvert_done,
					    forward_error,
					    payment);
		json_add_primitive(req->js, "amount", fmt_amount_for_currency(tmpctx, &max));
		json_add_string(req->js, "currency", max.currency->name);
		return send_outreq(req);
	}
	payment->max_amount_msat = amount_msat(payment->payment_max.amount);

	response = jsonrpc_stream_success(cmd);
	json_add_payment(response, payment);
	return command_finished(cmd, response);
}

static struct command_result *json_cancelrepeatpay(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *params)
{
	struct repeatpay *rp = repeatpay_of(cmd->plugin);
	struct json_escape *label;
	struct json_stream *response;
	struct payment *payment;
	const char *reason;

	if (!param_check(cmd, buffer, params,
		   p_req("label", param_label, &label),
		   p_opt("reason", param_string, &reason),
		   NULL))
		return command_param_failed();

	payment = payment_hash_get(rp->payments, label);
	if (!payment)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Unknown label '%s'", label->s);
	if (payment_terminated(payment->status))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Payment already finished (%s)",
				    repeatpay_status_str(payment->status));
	if (payment->cancel_reason)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Payment already being cancelled (currently %s)",
				    repeatpay_status_str(payment->status));
	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (reason)
		payment->cancel_reason = tal_steal(payment, reason);
	else
		payment->cancel_reason = "";

	/* Don't actually change status here, just add a log */
	payment_set_status(cmd, payment, payment->status,
			   "Cancel pending by command %s%s%s",
			   cmd->idstr,
			   streq(payment->cancel_reason, "") ? "": ": ",
			   payment->cancel_reason);

	response = jsonrpc_stream_success(cmd);
	json_add_payment(response, payment);
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
	{
		"amendrepeatpay",
		json_amendrepeatpay,
	},
	{
		"cancelrepeatpay",
		json_cancelrepeatpay,
	},
};

static const char *init(struct command *init_cmd,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct repeatpay *rp = repeatpay_of(init_cmd->plugin);
	rp->aux_cmd = aux_command(init_cmd);
	restore_payments(init_cmd, rp);
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
