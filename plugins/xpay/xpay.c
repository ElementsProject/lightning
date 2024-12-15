#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/bolt12.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/onion_encode.h>
#include <common/onionreply.h>
#include <common/pseudorand.h>
#include <common/route.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <stdarg.h>

/* For the whole plugin */
struct xpay {
	struct pubkey local_id;
	/* Access via get_gossmap() */
	struct gossmap *global_gossmap;
	/* Creates unique layer names */
	size_t counter;
	/* Can-never-exist fake key for blinded paths */
	struct pubkey fakenode;
	/* We need to know current block height */
	u32 blockheight;
	/* Do we take over "pay" commands? */
	bool take_over_pay;
};

static struct xpay *xpay_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct xpay);
}

/* This refreshes the gossmap. */
static struct gossmap *get_gossmap(struct xpay *xpay)
{
	gossmap_refresh(xpay->global_gossmap, NULL);
	return xpay->global_gossmap;
}

/* The unifies bolt11 and bolt12 handling */
struct payment {
	struct plugin *plugin;
	/* Stop sending new payments after this */
	struct timemono deadline;
	/* This is the command which is expecting the success/fail.  When
	 * it's NULL, that means we're just cleaning up */
	struct command *cmd;
	/* Unique id */
	u64 unique_id;
	/* For logging, and for sendpays */
	const char *invstring;
	/* Explicit layers they told us to include */
	const char **layers;
	/* Where we're trying to pay */
	struct pubkey destination;
	/* Hash we want the preimage for */
	struct sha256 payment_hash;
	/* Amount we're trying to pay */
	struct amount_msat amount;
	/* Fullamount of invoice (usually the same as above) */
	struct amount_msat full_amount;
	/* Maximum fee we're prepare to pay */
	struct amount_msat maxfee;
	/* BOLT11 payment secret (NULL for BOLT12, it uses blinded paths) */
	const struct secret *payment_secret;
	/* BOLT11 payment metadata (NULL for BOLT12, it uses blinded paths) */
	const u8 *payment_metadata;
	/* Final CLTV value */
	u32 final_cltv;
	/* Group id for this payment */
	uint64_t group_id;
	/* Counter for partids (also, total attempts) */
	uint64_t total_num_attempts;
	/* How many parts failed? */
	uint64_t num_failures;

	/* Name of our temporary additional layer */
	const char *private_layer;

	/* For bolt11 we have route hints */
	struct route_info **route_hints;

	/* For bolt12 we have blinded paths */
	struct blinded_path **paths;
	struct blinded_payinfo **payinfos;

	/* Current attempts, waiting for injectpaymentonion. */
	struct list_head current_attempts;

	/* We keep these around, since they may still be cleaning up. */
	struct list_head past_attempts;

	/* Amount we just asked getroutes for (0 means no getroutes
	 * call outstanding). */
	struct amount_msat amount_being_routed;

	/* Useful information from prior attempts if any. */
	char *prior_results;

	/* Requests currently outstanding */
	struct out_req **requests;

	/* Are we pretending to be "pay"? */
	bool pay_compat;
	/* When did we start? */
	struct timeabs start_time;
};

/* One step in a path. */
struct hop {
	/* Node this hop leads to. */
	struct pubkey next_node;
	/* Via this channel */
	struct short_channel_id_dir scidd;
	/* This is amount the node needs (including fees) */
	struct amount_msat amount_in;
	/* ... to send this amount */
	struct amount_msat amount_out;
	/* This is the delay, including delay across node */
	u32 cltv_value_in;
	/* This is the delay, out from node. */
	u32 cltv_value_out;
};

/* Each actual payment attempt */
struct attempt {
	/* Inside payment->attempts */
	struct list_node list;
	u64 partid;

	struct payment *payment;
	struct amount_msat delivers;

	/* Path we tried, so we can unreserve, and tell askrene the results */
	const struct hop *hops;

	/* Secrets, so we can decrypt error onions */
	struct secret *shared_secrets;
};

/* Wrapper for pending commands (ignores return) */
static void was_pending(const struct command_result *res)
{
	assert(res);
}

/* Recursion, so declare now */
static struct command_result *getroutes_for(struct command *cmd,
					    struct payment *payment,
					    struct amount_msat deliver);

/* Pretty printing paths */
static const char *fmt_path(const tal_t *ctx,
			    const struct attempt *attempt)
{
	char *s = tal_strdup(ctx, "");
	for (size_t i = 0; i < tal_count(attempt->hops); i++) {
		tal_append_fmt(&s, "->%s",
			       fmt_pubkey(tmpctx, &attempt->hops[i].next_node));
	}
	return s;
}

static void payment_log(struct payment *payment,
			enum log_level level,
			const char *fmt,
			...)
	PRINTF_FMT(3,4);

/* Logging: both to the command itself and the log file */
static void payment_log(struct payment *payment,
			enum log_level level,
			const char *fmt,
			...)
{
	va_list args;
	const char *msg;

	va_start(args, fmt);
	msg = tal_vfmt(tmpctx, fmt, args);
	va_end(args);

	if (payment->cmd)
		plugin_notify_message(payment->cmd, level, "%s", msg);
	plugin_log(payment->plugin, level, "%"PRIu64": %s",
		   payment->unique_id, msg);
}

static void attempt_log(struct attempt *attempt,
			enum log_level level,
			const char *fmt,
			...)
	PRINTF_FMT(3,4);

static void attempt_log(struct attempt *attempt,
			enum log_level level,
			const char *fmt,
			...)
{
	va_list args;
	const char *msg, *path;

	va_start(args, fmt);
	msg = tal_vfmt(tmpctx, fmt, args);
	va_end(args);
	path = fmt_path(tmpctx, attempt);

	payment_log(attempt->payment, level, "%s: %s", path, msg);
}

#define attempt_unusual(attempt, fmt, ...) \
	attempt_log((attempt), LOG_UNUSUAL, (fmt), __VA_ARGS__)
#define attempt_info(attempt, fmt, ...) \
	attempt_log((attempt), LOG_INFORM, (fmt), __VA_ARGS__)
#define attempt_debug(attempt, fmt, ...) \
	attempt_log((attempt), LOG_DBG, (fmt), __VA_ARGS__)

static struct command_result *ignore_result(struct command *aux_cmd,
					    const char *method,
					    const char *buf,
					    const jsmntok_t *result,
					    void *arg)
{
	return command_still_pending(aux_cmd);
}

static struct command_result *ignore_result_error(struct command *aux_cmd,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *result,
						  struct attempt *attempt)
{
	attempt_unusual(attempt, "%s failed: '%.*s'",
			method,
			json_tok_full_len(result),
			json_tok_full(buf, result));
	return ignore_result(aux_cmd, method, buf, result, attempt);
}

/* A request, but we don't care about result.  Submit with send_payment_req */
static struct out_req *payment_ignored_req(struct command *aux_cmd,
					   struct attempt *attempt,
					   const char *method)
{
	return jsonrpc_request_start(aux_cmd, method,
				     ignore_result, ignore_result_error, attempt);
}

static struct command_result *cleanup_finished(struct command *aux_cmd,
					       const char *method,
					       const char *buf,
					       const jsmntok_t *result,
					       struct payment *payment)
{
	/* payment is a child of aux_cmd, so freed now */
	return aux_command_done(aux_cmd);
}

/* Last of all we destroy the private layer */
static struct command_result *cleanup(struct command *aux_cmd,
				      struct payment *payment)
{
	struct out_req *req;

	req = jsonrpc_request_start(aux_cmd,
				    "askrene-remove-layer",
				    cleanup_finished,
				    cleanup_finished,
				    payment);
	json_add_string(req->js, "layer", payment->private_layer);
	return send_outreq(req);
}

/* Last request finished after xpay command is done gets to clean up */
static void destroy_payment_request(struct out_req *req,
				    struct payment *payment)
{
	for (size_t i = 0; i < tal_count(payment->requests); i++) {
		if (payment->requests[i] == req) {
			tal_arr_remove(&payment->requests, i);
			if (tal_count(payment->requests) == 0 && payment->cmd == NULL) {
				cleanup(req->cmd, payment);
			}
			return;
		}
	}
	abort();
}

static struct command_result *
send_payment_req(struct command *aux_cmd,
		 struct payment *payment, struct out_req *req)
{
	tal_arr_expand(&payment->requests, req);
	tal_add_destructor2(req, destroy_payment_request, payment);
	return send_outreq(req);
}

static void payment_failed(struct command *aux_cmd,
			   struct payment *payment,
			   enum jsonrpc_errcode code,
			   const char *fmt,
			   ...)
	PRINTF_FMT(4,5);

static void payment_failed(struct command *aux_cmd,
			   struct payment *payment,
			   enum jsonrpc_errcode code,
			   const char *fmt,
			   ...)
{
	va_list args;
	const char *msg;

	va_start(args, fmt);
	msg = tal_vfmt(tmpctx, fmt, args);
	va_end(args);

	/* Only fail once */
	if (payment->cmd) {
		was_pending(command_fail(payment->cmd, code, "%s", msg));
		payment->cmd = NULL;
	}

	/* If no commands outstanding, we can now clean up */
	if (tal_count(payment->requests) == 0)
		cleanup(aux_cmd, payment);
}

/* For self-pay, we don't have hops. */
static struct amount_msat initial_sent(const struct attempt *attempt)
{
	if (tal_count(attempt->hops) == 0)
		return attempt->delivers;
	return attempt->hops[0].amount_in;
}

static u32 initial_cltv_delta(const struct attempt *attempt)
{
	if (tal_count(attempt->hops) == 0)
		return attempt->payment->final_cltv;
	return attempt->hops[0].cltv_value_in;
}

/* The current attempt is the first to succeed: we assume all the ones
 * in progress will succeed too */
static struct amount_msat total_sent(const struct payment *payment,
				     const struct attempt *attempt)
{
	struct amount_msat total = initial_sent(attempt);
	const struct attempt *i;

	list_for_each(&payment->current_attempts, i, list) {
		if (!amount_msat_accumulate(&total, initial_sent(i)))
			abort();
	}
	return total;
}

static void payment_succeeded(struct payment *payment,
			      const struct preimage *preimage,
			      const struct attempt *attempt)
{
	struct json_stream *js;

	/* Only succeed once */
	if (payment->cmd) {
		js = jsonrpc_stream_success(payment->cmd);
		json_add_preimage(js, "payment_preimage", preimage);
		json_add_amount_msat(js, "amount_msat", payment->amount);
		json_add_amount_msat(js, "amount_sent_msat", total_sent(payment, attempt));
		/* Pay's schema expects these fields */
		if (payment->pay_compat) {
			json_add_u64(js, "parts", payment->total_num_attempts);
			json_add_sha256(js, "payment_hash", &payment->payment_hash);
			json_add_string(js, "status", "complete");
			json_add_u64(js, "created_at", (u64)payment->start_time.ts.tv_sec);
		} else {
			json_add_u64(js, "failed_parts", payment->num_failures);
			json_add_u64(js, "successful_parts",
				     payment->total_num_attempts - payment->num_failures);
		}
		was_pending(command_finished(payment->cmd, js));
		payment->cmd = NULL;
	}
}

/* We usually add things we learned to the global layer, but not
 * if it's a fake channel */
static const char *layer_of(const struct payment *payment,
			    const struct short_channel_id_dir *scidd)
{
	struct gossmap *gossmap = get_gossmap(xpay_of(payment->plugin));

	if (gossmap_find_chan(gossmap, &scidd->scid))
		return "xpay";
	return payment->private_layer;
}

static void add_result_summary(struct attempt *attempt,
			       enum log_level level,
			       const char *fmt, ...)
	PRINTF_FMT(3,4);

static void add_result_summary(struct attempt *attempt,
			       enum log_level level,
			       const char *fmt, ...)
{
	va_list args;
	const char *msg;

	va_start(args, fmt);
	msg = tal_vfmt(tmpctx, fmt, args);
	va_end(args);

	tal_append_fmt(&attempt->payment->prior_results, "%s. ", msg);
	attempt_log(attempt, level, "%s", msg);
}

static const char *describe_scidd(struct attempt *attempt, size_t index)
{
	struct short_channel_id_dir scidd = attempt->hops[index].scidd;
	struct payment *payment = attempt->payment;

	assert(index < tal_count(attempt->hops));

	/* Blinded paths? */
	if (scidd.scid.u64 < tal_count(payment->paths)) {
		if (tal_count(payment->paths) == 1)
			return tal_fmt(tmpctx, "the invoice's blinded path (%s)",
				       fmt_short_channel_id_dir(tmpctx, &scidd));
		return tal_fmt(tmpctx, "the invoice's blinded path %s (%"PRIu64" of %zu)",
			       fmt_short_channel_id_dir(tmpctx, &scidd),
			       scidd.scid.u64 + 1,
			       tal_count(payment->paths));
	}

	/* Routehint?  Often they are a single hop. */
	if (tal_count(payment->route_hints) == 1
	    && tal_count(payment->route_hints[0]) == 1)
		return tal_fmt(tmpctx, "the invoice's route hint (%s)",
			       fmt_short_channel_id_dir(tmpctx, &scidd));

	for (size_t i = 0; i < tal_count(payment->route_hints); i++) {
		for (size_t j = 0; j < tal_count(payment->route_hints[i]); j++) {
			if (short_channel_id_eq(scidd.scid,
						payment->route_hints[i][j].short_channel_id)) {
				return tal_fmt(tmpctx, "%s inside invoice's route hint%s",
					       fmt_short_channel_id_dir(tmpctx, &scidd),
					       tal_count(payment->route_hints) == 1 ? "" : "s");
			}
		}
	}

	/* Just use normal names otherwise (may be public, may be local) */
	return fmt_short_channel_id_dir(tmpctx, &scidd);
}

static void update_knowledge_from_error(struct command *aux_cmd,
					const char *buf,
					const jsmntok_t *error,
					struct attempt *attempt)
{
	const jsmntok_t *tok;
	struct onionreply *reply;
	struct out_req *req;
	const u8 *replymsg;
	int index;
	enum onion_wire failcode;
	bool from_final;
	const char *failcode_name, *errmsg;
	enum jsonrpc_errcode ecode;

	tok = json_get_member(buf, error, "code");
	if (!tok || !json_to_jsonrpc_errcode(buf, tok, &ecode))
		plugin_err(aux_cmd->plugin, "Invalid injectpaymentonion result '%.*s'",
			   json_tok_full_len(error), json_tok_full(buf, error));

	if (ecode == PAY_INJECTPAYMENTONION_ALREADY_PAID) {
		payment_failed(aux_cmd, attempt->payment,
			       PAY_INJECTPAYMENTONION_FAILED,
			       "Already paid this invoice successfully");
		return;
	}
	if (ecode != PAY_INJECTPAYMENTONION_FAILED) {
		payment_failed(aux_cmd, attempt->payment,
			       PLUGIN_ERROR,
			       "Unexpected injectpaymentonion error %i: %.*s",
			       ecode,
			       json_tok_full_len(error),
			       json_tok_full(buf, error));
		return;
	}

	tok = json_get_member(buf, error, "data");
	if (!tok)
		plugin_err(aux_cmd->plugin, "Invalid injectpaymentonion result '%.*s'",
			   json_tok_full_len(error), json_tok_full(buf, error));
	tok = json_get_member(buf, tok, "onionreply");
	if (!tok)
		plugin_err(aux_cmd->plugin, "Invalid injectpaymentonion result '%.*s'",
			   json_tok_full_len(error), json_tok_full(buf, error));
	reply = new_onionreply(tmpctx, take(json_tok_bin_from_hex(NULL, buf, tok)));

	replymsg = unwrap_onionreply(tmpctx,
				     attempt->shared_secrets,
				     tal_count(attempt->shared_secrets),
				     reply,
				     &index);

	/* Garbled?  Blame random hop. */
	if (!replymsg) {
		index = pseudorand(tal_count(attempt->hops));
		add_result_summary(attempt, LOG_UNUSUAL,
				   "We got a garbled error message, and chose to (randomly) to disable %s for this payment",
				   describe_scidd(attempt, index));
		goto disable_channel;
	}

	/* We learned something about prior nodes */
	for (size_t i = 0; i < index; i++) {
		req = payment_ignored_req(aux_cmd, attempt, "askrene-inform-channel");
		json_add_string(req->js, "layer",
				layer_of(attempt->payment, &attempt->hops[i].scidd));
		json_add_short_channel_id_dir(req->js,
					      "short_channel_id_dir",
					      attempt->hops[i].scidd);
		json_add_amount_msat(req->js, "amount_msat",
				     attempt->hops[i].amount_out);
		json_add_string(req->js, "inform", "unconstrained");
		send_payment_req(aux_cmd, attempt->payment, req);
	}

	from_final = (index == tal_count(attempt->hops));
	failcode = fromwire_peektype(replymsg);
	failcode_name = onion_wire_name(failcode);
	if (strstarts(failcode_name, "WIRE_"))
		failcode_name = str_lowering(tmpctx,
					     failcode_name
					     + strlen("WIRE_"));

	/* For local errors, error message is informative. */
	if (index == 0) {
		tok = json_get_member(buf, error, "message");
		errmsg = json_strdup(tmpctx, buf, tok);
	} else
		errmsg = failcode_name;

	attempt_debug(attempt,
		      "Error %s for path %s, from %s",
		      errmsg,
		      fmt_path(tmpctx, attempt),
		      from_final ? "destination"
		      : index == 0 ? "local node"
		      : fmt_pubkey(tmpctx, &attempt->hops[index-1].next_node));

	/* Final node sent an error */
	if (from_final) {
		switch (failcode) {
		/* These two are deprecated */
		case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:

		/* These ones are weird any time (did we encode wrongly?) */
		case WIRE_INVALID_ONION_VERSION:
		case WIRE_INVALID_ONION_HMAC:
		case WIRE_INVALID_ONION_KEY:
		case WIRE_INVALID_ONION_PAYLOAD:

		/* These should not be sent by final node */
		case WIRE_TEMPORARY_CHANNEL_FAILURE:
		case WIRE_PERMANENT_CHANNEL_FAILURE:
		case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		case WIRE_UNKNOWN_NEXT_PEER:
		case WIRE_AMOUNT_BELOW_MINIMUM:
		case WIRE_FEE_INSUFFICIENT:
		case WIRE_INCORRECT_CLTV_EXPIRY:
		case WIRE_EXPIRY_TOO_FAR:
		case WIRE_EXPIRY_TOO_SOON:
		case WIRE_CHANNEL_DISABLED:
		case WIRE_PERMANENT_NODE_FAILURE:
		case WIRE_TEMPORARY_NODE_FAILURE:
		case WIRE_REQUIRED_NODE_FEATURE_MISSING:
		case WIRE_INVALID_ONION_BLINDING:
			/* Blame hop *leading to* final node */
			index--;
			goto strange_error;

		case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
			/* FIXME: Maybe this was actually a height
			 * disagreement, so check height */
			payment_failed(aux_cmd, attempt->payment,
				       PAY_DESTINATION_PERM_FAIL,
				       "Destination said it doesn't know invoice: %s",
				       errmsg);
			return;

		case WIRE_MPP_TIMEOUT:
			/* Not actually an error at all, nothing to do. */
			add_result_summary(attempt, LOG_DBG,
					   "Payment of %s reached destination,"
					   " but timed out before the rest arrived.",
					   fmt_amount_msat(tmpctx, attempt->delivers));
			return;
		}
	} else {
		/* Non-final node */
		switch (failcode) {
		/* These ones are weird any time (did we encode wrongly?) */
		case WIRE_INVALID_ONION_VERSION:
		case WIRE_INVALID_ONION_HMAC:
		case WIRE_INVALID_ONION_KEY:
		case WIRE_INVALID_ONION_PAYLOAD:
		/* These should not be sent by non-final node */
		case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
		case WIRE_MPP_TIMEOUT:
			goto strange_error;

		case WIRE_TEMPORARY_CHANNEL_FAILURE:
			add_result_summary(attempt, LOG_DBG,
					   "We got %s for %s, assuming it can't carry %s",
					   errmsg,
					   describe_scidd(attempt, index),
					   fmt_amount_msat(tmpctx, attempt->hops[index].amount_out));
			goto channel_capacity;

		case WIRE_PERMANENT_CHANNEL_FAILURE:
		case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		case WIRE_UNKNOWN_NEXT_PEER:
		case WIRE_AMOUNT_BELOW_MINIMUM:
		case WIRE_FEE_INSUFFICIENT:
		case WIRE_INCORRECT_CLTV_EXPIRY:
		case WIRE_EXPIRY_TOO_FAR:
		case WIRE_EXPIRY_TOO_SOON:
		case WIRE_CHANNEL_DISABLED:
		case WIRE_PERMANENT_NODE_FAILURE:
		case WIRE_TEMPORARY_NODE_FAILURE:
		case WIRE_REQUIRED_NODE_FEATURE_MISSING:
			add_result_summary(attempt, LOG_DBG,
					   "We got a weird error (%s) for %s: disabling it for this payment",
					   errmsg,
					   describe_scidd(attempt, index));
			goto disable_channel;

		case WIRE_INVALID_ONION_BLINDING:
			/* FIXME: This could be an MPP_TIMEOUT! */
			add_result_summary(attempt, LOG_DBG,
					   "We got an error from inside the blinded path %s:"
					   " we assume it means insufficient capacity",
					   fmt_short_channel_id_dir(tmpctx,
								    &attempt->hops[index].scidd));
			goto channel_capacity;
		}
	}

strange_error:
	/* We disable the erroneous channel for this */
	add_result_summary(attempt, LOG_UNUSUAL,
			   "Unexpected error (%s) from %s node: disabling %s for this payment",
			   errmsg,
			   from_final ? "final" : "intermediate",
			   describe_scidd(attempt, index));

disable_channel:
	/* We only do this for the current payment */
	req = payment_ignored_req(aux_cmd, attempt, "askrene-update-channel");
	json_add_string(req->js, "layer", attempt->payment->private_layer);
	json_add_short_channel_id_dir(req->js,
				      "short_channel_id_dir",
				      attempt->hops[index].scidd);
	json_add_bool(req->js, "enabled", false);
	send_payment_req(aux_cmd, attempt->payment, req);
	return;

channel_capacity:
	req = payment_ignored_req(aux_cmd, attempt, "askrene-inform-channel");
	json_add_string(req->js, "layer",
			layer_of(attempt->payment, &attempt->hops[index].scidd));
	json_add_short_channel_id_dir(req->js,
				      "short_channel_id_dir",
				      attempt->hops[index].scidd);
	json_add_amount_msat(req->js, "amount_msat", attempt->hops[index].amount_out);
	json_add_string(req->js, "inform", "constrained");
	send_payment_req(aux_cmd, attempt->payment, req);
}

static struct command_result *unreserve_path(struct command *aux_cmd,
					     struct attempt *attempt)
{
	struct out_req *req;

	req = payment_ignored_req(aux_cmd, attempt, "askrene-unreserve");
	json_array_start(req->js, "path");
	for (size_t i = 0; i < tal_count(attempt->hops); i++) {
		const struct hop *hop = &attempt->hops[i];
		json_object_start(req->js, NULL);
		json_add_short_channel_id_dir(req->js, "short_channel_id_dir", hop->scidd);
		json_add_amount_msat(req->js, "amount_msat", hop->amount_out);
		json_object_end(req->js);
	}
	json_array_end(req->js);
	return send_payment_req(aux_cmd, attempt->payment, req);
}

static struct command_result *injectpaymentonion_failed(struct command *aux_cmd,
							const char *method,
							const char *buf,
							const jsmntok_t *error,
							struct attempt *attempt)
{
	struct payment *payment = attempt->payment;
	struct amount_msat delivers = attempt->delivers;

	payment->num_failures++;

	/* Move from current_attempts to past_attempts */
	list_del_from(&payment->current_attempts, &attempt->list);
	list_add(&payment->past_attempts, &attempt->list);

	/* We're no longer using this path: submit request to release it */
	unreserve_path(aux_cmd, attempt);

	/* Once reserve is removed, we can tell lightningd what we
	 * learned.  Might fail payment! */
	update_knowledge_from_error(aux_cmd, buf, error, attempt);

	/* If xpay is done, return now */
	if (!payment->cmd)
		return command_still_pending(aux_cmd);

	/* If we're not waiting for getroutes, kick one off */
	if (amount_msat_is_zero(payment->amount_being_routed))
		return getroutes_for(aux_cmd, payment, delivers);

	/* Wait for getroutes to finish */
	return command_still_pending(aux_cmd);
}

static struct amount_msat total_being_sent(const struct payment *payment)
{
	struct attempt *attempt;
	struct amount_msat sum = AMOUNT_MSAT(0);

	list_for_each(&payment->current_attempts, attempt, list) {
		if (!amount_msat_accumulate(&sum, attempt->delivers))
			abort();
	}
	return sum;
}

static struct amount_msat total_fees_being_sent(const struct payment *payment)
{
	struct attempt *attempt;
	struct amount_msat sum = AMOUNT_MSAT(0);

	list_for_each(&payment->current_attempts, attempt, list) {
		struct amount_msat fee;
		if (tal_count(attempt->hops) == 0)
			continue;
		if (!amount_msat_sub(&fee,
				     attempt->hops[0].amount_in,
				     attempt->delivers))
			abort();
		if (!amount_msat_accumulate(&sum, fee))
			abort();
	}
	return sum;
}

static struct command_result *injectpaymentonion_succeeded(struct command *aux_cmd,
							   const char *method,
							   const char *buf,
							   const jsmntok_t *result,
							   struct attempt *attempt)
{
	struct preimage preimage;
	struct payment *payment = attempt->payment;

	if (!json_to_preimage(buf,
			      json_get_member(buf, result, "payment_preimage"),
			      &preimage))
		plugin_err(aux_cmd->plugin, "Invalid injectpaymentonion result '%.*s'",
			   json_tok_full_len(result), json_tok_full(buf, result));

	/* Move from current_attempts to past_attempts */
	list_del_from(&payment->current_attempts, &attempt->list);
	list_add(&payment->past_attempts, &attempt->list);

	attempt_info(attempt, "Success: preimage=%s", fmt_preimage(tmpctx, &preimage));
	payment_succeeded(payment, &preimage, attempt);

	/* And we're no longer using the path. */
	return unreserve_path(aux_cmd, attempt);
}

static void append_blinded_payloads(struct sphinx_path *sp,
				    const struct attempt *attempt,
				    u32 effective_bheight,
				    size_t path_num)
{
	const struct blinded_path *path = attempt->payment->paths[path_num];
	u32 final_cltv = attempt->payment->final_cltv + effective_bheight;

	for (size_t i = 0; i < tal_count(path->path); i++) {
		bool first = (i == 0);
		bool final = (i == tal_count(path->path) - 1);
		const u8 *payload;

		/* BOLT #4:
		 * - For every node inside a blinded route:
		 *   - MUST include the `encrypted_recipient_data` provided by the
		 *     recipient
		 *   - For the first node in the blinded route:
		 *     - MUST include the `path_key` provided by the
		 *       recipient in `current_path_key`
		 *   - If it is the final node:
		 *     - MUST include `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
		 *...
		 *   - MUST NOT include any other tlv field.
		 */
		payload = onion_blinded_hop(NULL,
					    final ? &attempt->delivers : NULL,
					    final ? &attempt->payment->full_amount : NULL,
					    final ? &final_cltv : NULL,
					    path->path[i]->encrypted_recipient_data,
					    first ? &path->first_path_key : NULL);
		sphinx_add_hop_has_length(sp,
					  first ? &path->first_node_id.pubkey
					  : &path->path[i]->blinded_node_id,
					  take(payload));
	}
}

static const u8 *create_onion(const tal_t *ctx,
			      struct attempt *attempt,
			      u32 effective_bheight)
{
	struct xpay *xpay = xpay_of(attempt->payment->plugin);
	bool blinded_path = false;
	struct onionpacket *packet;
	struct sphinx_path *sp;
	const u8 *payload, *ret;
	const struct pubkey *node;

	sp = sphinx_path_new(ctx, attempt->payment->payment_hash.u.u8,
			     sizeof(attempt->payment->payment_hash.u.u8));

	/* First hop is to the local node */
	node = &xpay->local_id;

	for (size_t i = 0; i < tal_count(attempt->hops); i++) {
		const struct hop *hop = &attempt->hops[i];

		if (pubkey_eq(&hop->next_node, &xpay->fakenode)
		    && hop->scidd.scid.u64 < tal_count(attempt->payment->paths)) {
			blinded_path = true;
			append_blinded_payloads(sp, attempt, effective_bheight,
						hop->scidd.scid.u64);
			/* This must be at the end, unless they put the fake nodeid
			 * in a layer, in which case it doesn't matter what we put
			 * in the rest of the onion. */
			break;
		}
		/* We tell it how much to send *out* */
		payload = onion_nonfinal_hop(NULL, &hop->scidd.scid, hop->amount_out,
					     hop->cltv_value_out + effective_bheight);
		sphinx_add_hop_has_length(sp, node, take(payload));
		node = &hop->next_node;
	}

	/* If we use a blinded path, final has to be special, so
	 * that's done in append_blinded_payloads. */
	if (!blinded_path) {
		sphinx_add_hop_has_length(sp, node,
					  take(onion_final_hop(NULL,
							       attempt->delivers,
							       attempt->payment->final_cltv + effective_bheight,
							       attempt->payment->full_amount,
							       attempt->payment->payment_secret,
							       attempt->payment->payment_metadata)));
	}

	/* Fails if would be too long */
	packet = create_onionpacket(attempt, sp, ROUTING_INFO_SIZE,
				    &attempt->shared_secrets);
	if (!packet)
		return NULL;

	ret = serialize_onionpacket(ctx, packet);
	tal_free(packet);
	return ret;
}

static struct command_result *do_inject(struct command *aux_cmd,
					struct attempt *attempt)
{
	struct out_req *req;
	const u8 *onion;
	struct xpay *xpay = xpay_of(attempt->payment->plugin);
	/* In case a block comes in, we give CLTVs an extra 1. */
	u32 effective_bheight = xpay->blockheight + 1;

	onion = create_onion(tmpctx, attempt, effective_bheight);
	/* FIXME: Handle this better! */
	if (!onion) {
		payment_failed(aux_cmd, attempt->payment, PAY_UNSPECIFIED_ERROR,
			       "Could not create payment onion: path too long!");
		return command_still_pending(aux_cmd);
	}

	req = jsonrpc_request_start(aux_cmd,
				    "injectpaymentonion",
				    injectpaymentonion_succeeded,
				    injectpaymentonion_failed,
				    attempt);
	json_add_hex_talarr(req->js, "onion", onion);
	json_add_sha256(req->js, "payment_hash", &attempt->payment->payment_hash);
	/* If no route, its the same as delivery (self-pay) */
	json_add_amount_msat(req->js, "amount_msat", initial_sent(attempt));
	json_add_u32(req->js, "cltv_expiry", initial_cltv_delta(attempt) + effective_bheight);
	json_add_u64(req->js, "partid", attempt->partid);
	json_add_u64(req->js, "groupid", attempt->payment->group_id);
	json_add_string(req->js, "invstring", attempt->payment->invstring);
	json_add_amount_msat(req->js, "destination_msat", attempt->delivers);
	return send_payment_req(aux_cmd, attempt->payment, req);
}

static struct command_result *reserve_done(struct command *aux_cmd,
					   const char *method,
					   const char *buf,
					   const jsmntok_t *result,
					   struct attempt *attempt)
{
	attempt_debug(attempt, "%s", "Reserve done!");

	return do_inject(aux_cmd, attempt);
}

static struct command_result *reserve_done_err(struct command *aux_cmd,
					       const char *method,
					       const char *buf,
					       const jsmntok_t *result,
					       struct attempt *attempt)
{
	payment_failed(aux_cmd, attempt->payment, PAY_UNSPECIFIED_ERROR,
		       "Reservation failed: '%.*s'",
		       json_tok_full_len(result),
		       json_tok_full(buf, result));
	return command_still_pending(aux_cmd);
}

/* Does not set shared_secrets */
static struct attempt *new_attempt(struct payment *payment,
				   struct amount_msat delivers,
				   const struct hop *hops TAKES)
{
	struct attempt *attempt = tal(payment, struct attempt);

	attempt->payment = payment;
	attempt->delivers = delivers;
	attempt->partid = ++payment->total_num_attempts;
	attempt->hops = tal_dup_talarr(attempt, struct hop, hops);
	list_add_tail(&payment->current_attempts, &attempt->list);

	return attempt;
}

static struct command_result *getroutes_done(struct command *aux_cmd,
					     const char *method,
					     const char *buf,
					     const jsmntok_t *result,
					     struct payment *payment)
{
	const jsmntok_t *t, *routes;
	size_t i;
	struct amount_msat needs_routing, was_routing;

	payment_log(payment, LOG_DBG, "getroutes_done: %s",
		    payment->cmd ? "continuing" : "ignoring");

	/* If we're finished, ignore. */
	if (!payment->cmd)
		return command_still_pending(aux_cmd);

	/* Do we have more that needs routing?  If so, re-ask */
	if (!amount_msat_sub(&needs_routing,
			     payment->amount,
			     total_being_sent(payment)))
		abort();

	was_routing = payment->amount_being_routed;
	payment->amount_being_routed = AMOUNT_MSAT(0);

	if (!amount_msat_eq(needs_routing, was_routing)) {
		payment_log(payment, LOG_DBG,
			    "getroutes_done: need more (was_routing %s, needs_routing %s)",
			    fmt_amount_msat(tmpctx, was_routing),
			    fmt_amount_msat(tmpctx, needs_routing));
		return getroutes_for(aux_cmd, payment, needs_routing);
	}

	/* Even if we're amazingly slow, we should make one attempt. */
	if (payment->total_num_attempts > 0
	    && time_greater_(time_mono().ts, payment->deadline.ts)) {
		payment_failed(aux_cmd, payment, PAY_UNSPECIFIED_ERROR,
			       "Timed out after after %"PRIu64" attempts. %s",
			       payment->total_num_attempts,
			       payment->prior_results);
		return command_still_pending(aux_cmd);
	}

	routes = json_get_member(buf, result, "routes");
	payment_log(payment, LOG_DBG, "routes for %s = %.*s",
		    fmt_amount_msat(tmpctx, was_routing),
		    json_tok_full_len(result), json_tok_full(buf, result));
	json_for_each_arr(i, t, routes) {
		size_t j;
		const jsmntok_t *hoptok, *path;
		struct out_req *req;
		struct amount_msat delivers;
		struct hop *hops;
		struct attempt *attempt;

		json_to_msat(buf, json_get_member(buf, t, "amount_msat"),
			     &delivers);
		path = json_get_member(buf, t, "path");
		hops = tal_arr(NULL, struct hop, path->size);
		json_for_each_arr(j, hoptok, path) {
			const char *err;
			struct hop *hop = &hops[j];
			err = json_scan(tmpctx, buf, hoptok,
					"{short_channel_id_dir:%"
					",amount_msat:%"
					",next_node_id:%"
					",delay:%}",
					JSON_SCAN(json_to_short_channel_id_dir,
						  &hop->scidd),
					JSON_SCAN(json_to_msat, &hop->amount_in),
					JSON_SCAN(json_to_pubkey, &hop->next_node),
					JSON_SCAN(json_to_u32, &hop->cltv_value_in));
			if (err)
				plugin_err(aux_cmd->plugin, "Malformed routes: %s",
					   err);
			if (j > 0) {
				hops[j-1].amount_out = hop->amount_in;
				hops[j-1].cltv_value_out = hop->cltv_value_in;
			}
		}
		hops[j-1].amount_out = delivers;
		hops[j-1].cltv_value_out = payment->final_cltv;
		attempt = new_attempt(payment, delivers, take(hops));

		/* Reserve this route */
		attempt_debug(attempt, "%s", "doing askrene-reserve");

		req = jsonrpc_request_start(aux_cmd,
					    "askrene-reserve",
					    reserve_done,
					    reserve_done_err,
					    attempt);
		json_array_start(req->js, "path");
		for (j = 0; j < tal_count(attempt->hops); j++) {
			const struct hop *hop = &attempt->hops[j];
			json_object_start(req->js, NULL);
			json_add_short_channel_id_dir(req->js, "short_channel_id_dir",
						      hop->scidd);
			json_add_amount_msat(req->js, "amount_msat", hop->amount_out);
			json_object_end(req->js);
		}
		json_array_end(req->js);
		send_payment_req(aux_cmd, attempt->payment, req);
	}

	payment_log(payment, LOG_DBG, "waiting...");
	return command_still_pending(aux_cmd);
}

static struct command_result *getroutes_done_err(struct command *aux_cmd,
						 const char *method,
						 const char *buf,
						 const jsmntok_t *error,
						 struct payment *payment)
{
	int code;
	const char *msg, *complaint;

	/* getroutes gives nice error messages: we may need to annotate though. */
	msg = json_strdup(tmpctx, buf, json_get_member(buf, error, "message"));
	json_to_int(buf, json_get_member(buf, error, "code"), &code);

	/* Simple case: failed immediately. */
	if (payment->total_num_attempts == 0) {
		payment_failed(aux_cmd, payment, code, "Failed: %s", msg);
		return command_still_pending(aux_cmd);
	}

	/* FIXME: If we fail due to exceeding maxfee, we *could* try waiting for
	 * any outstanding payments to fail and then try again? */

	/* More elaborate explanation. */
	if (amount_msat_eq(payment->amount_being_routed, payment->amount))
		complaint = "Then routing failed";
	else
		complaint = tal_fmt(tmpctx, "Then routing for remaining %s failed",
				    fmt_amount_msat(tmpctx, payment->amount_being_routed));
	payment_failed(aux_cmd, payment, PAY_UNSPECIFIED_ERROR,
		       "Failed after %"PRIu64" attempts. %s%s: %s",
		       payment->total_num_attempts,
		       payment->prior_results,
		       complaint,
		       msg);
	return command_still_pending(aux_cmd);
}

static struct command_result *getroutes_for(struct command *aux_cmd,
					    struct payment *payment,
					    struct amount_msat deliver)
{
	struct xpay *xpay = xpay_of(aux_cmd->plugin);
	struct out_req *req;
	const struct pubkey *dst;
	struct amount_msat maxfee;

	/* If we get injectpaymentonion responses, they can wait */
	payment->amount_being_routed = deliver;

	if (payment->paths)
		dst = &xpay->fakenode;
	else
		dst = &payment->destination;

	/* Self-pay?  Shortcut all this */
	if (pubkey_eq(&xpay->local_id, dst)) {
		struct attempt *attempt = new_attempt(payment, deliver, NULL);
		return do_inject(aux_cmd, attempt);
	}

	if (!amount_msat_sub(&maxfee, payment->maxfee, total_fees_being_sent(payment))) {
		payment_log(payment, LOG_BROKEN, "more fees (%s) in flight than allowed (%s)!",
			    fmt_amount_msat(tmpctx, total_fees_being_sent(payment)),
			    fmt_amount_msat(tmpctx, payment->maxfee));
		maxfee = AMOUNT_MSAT(0);
	}

	req = jsonrpc_request_start(aux_cmd, "getroutes",
				    getroutes_done,
				    getroutes_done_err,
				    payment);

	json_add_pubkey(req->js, "source", &xpay->local_id);
	json_add_pubkey(req->js, "destination", dst);

	payment_log(payment, LOG_DBG, "getroutes from %s to %s",
		    fmt_pubkey(tmpctx, &xpay->local_id),
		    payment->paths
		    ? fmt_pubkey(tmpctx, &xpay->fakenode)
		    : fmt_pubkey(tmpctx, &payment->destination));
	json_add_amount_msat(req->js, "amount_msat", deliver);
	json_array_start(req->js, "layers");
	/* Add local channels */
	json_add_string(req->js, NULL, "auto.localchans");
	/* We don't pay fees for ourselves */
	json_add_string(req->js, NULL, "auto.sourcefree");
	/* Add xpay global channel */
	json_add_string(req->js, NULL, "xpay");
	/* Add private layer */
	json_add_string(req->js, NULL, payment->private_layer);
	/* Add user-specified layers */
	for (size_t i = 0; i < tal_count(payment->layers); i++)
		json_add_string(req->js, NULL, payment->layers[i]);
	json_array_end(req->js);
	json_add_amount_msat(req->js, "maxfee_msat", maxfee);
	json_add_u32(req->js, "final_cltv", payment->final_cltv);

	return send_payment_req(aux_cmd, payment, req);
}

/* First time, we ask getroutes for the entire payment */
static struct command_result *start_getroutes(struct command *aux_cmd,
					      struct payment *payment)
{
	return getroutes_for(aux_cmd, payment, payment->amount);
}

/* Helper to create a fake channel in temporary layer */
static void add_fake_channel(struct command *aux_cmd,
			     struct request_batch *batch,
			     struct payment *payment,
			     const struct node_id *src,
			     const struct node_id *dst,
			     struct short_channel_id scid,
			     struct amount_msat capacity,
			     struct amount_msat htlc_min,
			     struct amount_msat htlc_max,
			     struct amount_msat fee_base_msat,
			     u32 fee_proportional_millionths,
			     u16 cltv_expiry_delta)
{
	struct out_req *req;
	struct short_channel_id_dir scidd;

	scidd.scid = scid;
	scidd.dir = node_id_idx(src, dst);
	payment_log(payment, LOG_DBG,
		    "Invoice gave route %s->%s (%s)",
		    fmt_node_id(tmpctx, src),
		    fmt_node_id(tmpctx, dst),
		    fmt_short_channel_id_dir(tmpctx, &scidd));
	req = add_to_batch(aux_cmd, batch, "askrene-create-channel");
	json_add_string(req->js, "layer", payment->private_layer);
	json_add_node_id(req->js, "source", src);
	json_add_node_id(req->js, "destination", dst);
	json_add_short_channel_id(req->js, "short_channel_id", scid);
	json_add_amount_msat(req->js, "capacity_msat", capacity);
	send_payment_req(aux_cmd, payment, req);

	req = add_to_batch(aux_cmd, batch, "askrene-update-channel");
	json_add_string(req->js, "layer", payment->private_layer);
	json_add_short_channel_id_dir(req->js, "short_channel_id_dir", scidd);
	json_add_bool(req->js, "enabled", true);
	json_add_amount_msat(req->js, "htlc_minimum_msat", htlc_min);
	json_add_amount_msat(req->js, "htlc_maximum_msat", htlc_max);
	json_add_amount_msat(req->js, "fee_base_msat", fee_base_msat);
	json_add_u32(req->js, "fee_proportional_millionths",
		     fee_proportional_millionths);
	json_add_u32(req->js, "cltv_expiry_delta", cltv_expiry_delta);
	send_payment_req(aux_cmd, payment, req);
}

static void add_routehint(struct request_batch *batch,
			  struct command *aux_cmd,
			  struct payment *payment,
			  const struct route_info *route)
{
	struct xpay *xpay = xpay_of(payment->plugin);
	struct amount_msat big_cap;
	struct node_id me;

	node_id_from_pubkey(&me, &xpay->local_id);

	/* We add these channels to our private layer.  We start with assuming
	 * they have 100x the capacity we need (including fees!): we'll figure
	 * it out quickly if we're wrong, but this gives a success probability
	 * of 99%. */
	if (!amount_msat_add(&big_cap, payment->amount, payment->maxfee)
	    || !amount_msat_mul(&big_cap, big_cap, 100))
		big_cap = payment->amount; /* Going to fail route anyway! */

	for (size_t i = 0; i < tal_count(route); i++) {
		struct node_id next;

		if (i + 1 < tal_count(route)) {
			next = route[i+1].pubkey;
		} else {
			node_id_from_pubkey(&next, &payment->destination);
		}

		/* Don't add hints from ourselves, since we know all those,
		 * and the error from this would be confusing! */
		if (node_id_eq(&route[i].pubkey, &me))
			continue;

		add_fake_channel(aux_cmd, batch, payment,
				 &route[i].pubkey, &next,
				 route[i].short_channel_id,
				 big_cap,
				 /* We don't know htlc_min/max */
				 AMOUNT_MSAT(0), big_cap,
				 amount_msat(route[i].fee_base_msat),
				 route[i].fee_proportional_millionths,
				 route[i].cltv_expiry_delta);
	}
}

/* If it fails, returns error, otherwise NULL */
static char *add_blindedpath(const tal_t *ctx,
			     struct request_batch *batch,
			     struct command *aux_cmd,
			     struct payment *payment,
			     size_t blindedpath_num,
			     const struct blinded_path *path,
			     const struct blinded_payinfo *payinfo)
{
	struct xpay *xpay = xpay_of(payment->plugin);
	struct amount_msat big_cap, per_route_reduction;
	int badf;
	struct short_channel_id scid;
	struct node_id src, dst;

	/* BOLT-offers #12:
	 *   - SHOULD prefer to use earlier `invoice_paths` over later ones if
	 *     it has no other reason for preference.
	 */
	/* We do this by telling askrene that the first one is the largest
	 * capacity channel. */

	/* We add these channels to our private layer.  We start with assuming
	 * they have 100x the capacity we need (including fees!): we'll figure
	 * it out quickly if we're wrong, but this gives a success probability
	 * of 99%. */
	if (!amount_msat_add(&per_route_reduction,
			     payment->amount, payment->maxfee)
	    || !amount_msat_mul(&big_cap,
				per_route_reduction,
				100 + (tal_count(payment->paths) - blindedpath_num))) {
		/* Going to fail route anyway! */
		per_route_reduction = AMOUNT_MSAT(0);
		big_cap = payment->amount;
	}

	assert(path->first_node_id.is_pubkey);

	/* BOLT-offers #12:
	 *   - For each `invoice_blindedpay`.`payinfo`:
	 *     - MUST NOT use the corresponding `invoice_paths`.`path`
	 *       if `payinfo`.`features` has any unknown even bits set.
	 *     - MUST reject the invoice if this leaves no usable paths.
	 */
	badf = features_unsupported(plugin_feature_set(payment->plugin),
				    payinfo->features,
				    BOLT12_INVOICE_FEATURE);
	if (badf != -1)
		return tal_fmt(ctx, "unknown feature %i", badf);

	node_id_from_pubkey(&src, &path->first_node_id.pubkey);
	node_id_from_pubkey(&dst, &xpay->fakenode);
	/* We make the "scid" for the blinded path block 0, which is impossible */
	scid.u64 = blindedpath_num;

	add_fake_channel(aux_cmd, batch, payment,
			 &src, &dst, scid, big_cap,
			 payinfo->htlc_minimum_msat,
			 payinfo->htlc_maximum_msat,
			 amount_msat(payinfo->fee_base_msat),
			 payinfo->fee_proportional_millionths,
			 payinfo->cltv_expiry_delta);
	return NULL;
}

static struct command_result *log_payment_err(struct command *aux_cmd,
					      const char *methodname,
					      const char *buf,
					      const jsmntok_t *result,
					      struct payment *payment)
{
	payment_log(payment, LOG_UNUSUAL,
		    "%s failed: '%.*s'",
		    methodname,
		    json_tok_full_len(result),
		    json_tok_full(buf, result));
	return command_still_pending(aux_cmd);
}

/* Create a layer with our payment-specific topology information */
static struct command_result *populate_private_layer(struct command *cmd,
						     struct payment *payment)
{
	struct request_batch *batch;
	bool all_failed;
	char *errors = NULL;
	struct out_req *req;
	struct command *aux_cmd;

	/* Everything else is parented to a separate command, which
	 * can outlive the one we respond to. */
	aux_cmd = aux_command(cmd);
	tal_steal(aux_cmd, payment);
	batch = request_batch_new(aux_cmd, NULL, log_payment_err, start_getroutes,
				  payment);
	req = add_to_batch(aux_cmd, batch, "askrene-create-layer");
	json_add_string(req->js, "layer", payment->private_layer);
	send_payment_req(aux_cmd, payment, req);

	for (size_t i = 0; i < tal_count(payment->route_hints); i++)
		add_routehint(batch, aux_cmd, payment, payment->route_hints[i]);

	all_failed = tal_count(payment->paths) ? true : false;
	for (size_t i = 0; i < tal_count(payment->paths); i++) {
		char *err = add_blindedpath(tmpctx, batch,
					    aux_cmd, payment, i,
					    payment->paths[i],
					    payment->payinfos[i]);
		if (!err) {
			all_failed = false;
			continue;
		}
		if (!errors)
			errors = err;
		else
			tal_append_fmt(&errors, ", %s", err);
	}

	/* Nothing actually created yet, so this is the last point we don't use
	 * "payment_failed" */
	if (all_failed)
		return command_fail(aux_cmd, PAY_ROUTE_NOT_FOUND,
				    "No usable blinded paths: %s", errors);

	return batch_done(aux_cmd, batch);
}

static struct command_result *param_string_array(struct command *cmd, const char *name,
						 const char *buffer, const jsmntok_t *tok,
						 const char ***arr)
{
	size_t i;
	const jsmntok_t *s;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be an array");
	*arr = tal_arr(cmd, const char *, tok->size);
	json_for_each_arr(i, s, tok)
		(*arr)[i] = json_strdup(*arr, buffer, s);
	return NULL;
}

static struct command_result *
preapproveinvoice_succeed(struct command *cmd,
			  const char *method,
			  const char *buf,
			  const jsmntok_t *result,
			  struct payment *payment)
{
	struct xpay *xpay = xpay_of(cmd->plugin);

	/* Now we can conclude `check` command */
	if (command_check_only(cmd)) {
		return command_check_done(cmd);
	}

	payment->unique_id = xpay->counter++;
	payment->private_layer = tal_fmt(payment,
					 "xpay-%"PRIu64, payment->unique_id);
	return populate_private_layer(cmd, payment);
}

static struct command_result *json_xpay_core(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params,
					     bool as_pay)
{
	struct xpay *xpay = xpay_of(cmd->plugin);
	struct amount_msat *msat, *maxfee, *partial;
	struct payment *payment = tal(cmd, struct payment);
	unsigned int *retryfor;
	struct out_req *req;
	u64 now, invexpiry;
	char *err;

	if (!param_check(cmd, buffer, params,
			 p_req("invstring", param_invstring, &payment->invstring),
			 p_opt("amount_msat", param_msat, &msat),
			 p_opt("maxfee", param_msat, &maxfee),
			 p_opt("layers", param_string_array, &payment->layers),
			 p_opt_def("retry_for", param_number, &retryfor, 60),
			 p_opt("partial_msat", param_msat, &partial),
			 NULL))
		return command_param_failed();

	list_head_init(&payment->current_attempts);
	list_head_init(&payment->past_attempts);
	payment->plugin = cmd->plugin;
	payment->cmd = cmd;
	payment->amount_being_routed = AMOUNT_MSAT(0);
	payment->group_id = pseudorand(INT64_MAX);
	payment->total_num_attempts = payment->num_failures = 0;
	payment->requests = tal_arr(payment, struct out_req *, 0);
	payment->prior_results = tal_strdup(payment, "");
	payment->deadline = timemono_add(time_mono(), time_from_sec(*retryfor));
	payment->start_time = time_now();
	payment->pay_compat = as_pay;

	if (bolt12_has_prefix(payment->invstring)) {
		struct gossmap *gossmap = get_gossmap(xpay);
		struct tlv_invoice *b12inv
			= invoice_decode(tmpctx, payment->invstring,
					 strlen(payment->invstring),
					 plugin_feature_set(cmd->plugin),
					 chainparams, &err);
		if (!b12inv)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt12 invoice: %s", err);

		invexpiry = invoice_expiry(b12inv);
		payment->full_amount = amount_msat(*b12inv->invoice_amount);
		if (msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Cannot override amount for bolt12 invoices");
		payment->route_hints = NULL;
		payment->payment_secret = NULL;
		payment->payment_metadata = NULL;
		payment->paths = tal_steal(payment, b12inv->invoice_paths);
		payment->payinfos = tal_steal(payment, b12inv->invoice_blindedpay);
		payment->payment_hash = *b12inv->invoice_payment_hash;
		payment->destination = *b12inv->invoice_node_id;
		/* Resolve introduction points if possible */
		for (size_t i = 0; i < tal_count(payment->paths); i++) {
			if (!gossmap_scidd_pubkey(gossmap, &payment->paths[i]->first_node_id)) {
				payment_log(payment, LOG_UNUSUAL,
					    "Could not resolve blinded path start %s: discarding",
					    fmt_sciddir_or_pubkey(tmpctx,
								  &payment->paths[i]->first_node_id));
				tal_arr_remove(&payment->paths, i);
				tal_arr_remove(&payment->payinfos, i);
				i--;
			}
		}
		/* In case we remove them all! */
		if (tal_count(payment->paths) == 0) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not resolve any paths: unknown short_channel_id");
		}

		/* Use worst-case CLTV. */
		payment->final_cltv = 0;
		for (size_t i = 0; i < tal_count(payment->payinfos); i++) {
			if (payment->payinfos[i]->cltv_expiry_delta > payment->final_cltv)
				payment->final_cltv = payment->payinfos[i]->cltv_expiry_delta;
		}
	} else {
		struct bolt11 *b11
			= bolt11_decode(tmpctx, payment->invstring,
					plugin_feature_set(cmd->plugin),
					NULL,
					chainparams, &err);
		if (!b11)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt11 invoice: %s", err);
		payment->route_hints = tal_steal(payment, b11->routes);
		payment->paths = NULL;
		payment->payinfos = NULL;
		if (!pubkey_from_node_id(&payment->destination, &b11->receiver_id))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid destination id %s",
					    fmt_node_id(tmpctx, &b11->receiver_id));

		payment->final_cltv = b11->min_final_cltv_expiry;
		payment->payment_hash = b11->payment_hash;
		payment->payment_secret = tal_steal(payment, b11->payment_secret);
		if (!b11->payment_secret)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "need payment_secret");
		payment->payment_metadata = tal_steal(payment, b11->metadata);
		if (!b11->msat && !msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "amount_msat required");
		if (b11->msat && msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "amount_msat unnecessary");
		if (b11->msat)
			payment->full_amount = *b11->msat;
		else
			payment->full_amount = *msat;

		invexpiry = b11->timestamp + b11->expiry;
	}

	now = time_now().ts.tv_sec;
	if (now > invexpiry)
		return command_fail(cmd, PAY_INVOICE_EXPIRED,
				    "Invoice expired %"PRIu64" seconds ago",
				    now - invexpiry);

	if (partial) {
		payment->amount = *partial;
		if (amount_msat_greater(payment->amount, payment->full_amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "partial_msat must be less or equal to total amount %s",
					    fmt_amount_msat(tmpctx, payment->full_amount));
	} else {
		payment->amount = payment->full_amount;
	}

	/* Default is 5sats, or 1%, whatever is greater */
	if (!maxfee) {
		if (!amount_msat_fee(&payment->maxfee, payment->amount, 0, 1000000 / 100))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid amount: fee overflows");
		payment->maxfee = amount_msat_max(payment->maxfee,
						  AMOUNT_MSAT(5000));
	} else
		payment->maxfee = *maxfee;

	/* Now preapprove, then start payment. */
	if (command_check_only(cmd)) {
		req = jsonrpc_request_start(cmd, "check",
					    &preapproveinvoice_succeed,
					    &forward_error, payment);
		json_add_string(req->js, "command_to_check", "preapproveinvoice");
	} else {
		req = jsonrpc_request_start(cmd, "preapproveinvoice",
					    &preapproveinvoice_succeed,
					    &forward_error, payment);
	}
	json_add_string(req->js, "bolt11", payment->invstring);
	return send_outreq(req);
}

static struct command_result *json_xpay(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params)
{
	return json_xpay_core(cmd, buffer, params, false);
}

static struct command_result *json_xpay_as_pay(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *params)
{
	return json_xpay_core(cmd, buffer, params, true);
}

static struct command_result *getchaininfo_done(struct command *aux_cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						void *unused)
{
	struct xpay *xpay = xpay_of(aux_cmd->plugin);

	/* We use headercount from the backend, in case we're still syncing */
	if (!json_to_u32(buf, json_get_member(buf, result, "headercount"),
			 &xpay->blockheight)) {
		plugin_err(aux_cmd->plugin, "Bad getchaininfo '%.*s'",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	}
	return aux_command_done(aux_cmd);
}

static struct command_result *getinfo_done(struct command *aux_cmd,
					   const char *method,
					   const char *buf,
					   const jsmntok_t *result,
					   void *unused)
{
	struct xpay *xpay = xpay_of(aux_cmd->plugin);
	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{id:%}", JSON_SCAN(json_to_pubkey, &xpay->local_id));
	if (err) {
		plugin_err(aux_cmd->plugin, "Bad getinfo '%.*s': %s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result),
			   err);
	}
	return aux_command_done(aux_cmd);
}

/* Recursion */
static void start_aging_timer(struct plugin *plugin);

static struct command_result *age_done(struct command *timer_cmd,
				       const char *method,
				       const char *buf,
				       const jsmntok_t *result,
				       void *unused)
{
	start_aging_timer(timer_cmd->plugin);
	return timer_complete(timer_cmd);
}

static struct command_result *age_layer(struct command *timer_cmd, void *unused)
{
	struct out_req *req;
	req = jsonrpc_request_start(timer_cmd, "askrene-age",
				    age_done,
				    plugin_broken_cb,
				    NULL);
	json_add_string(req->js, "layer", "xpay");
	json_add_u64(req->js, "cutoff", time_now().ts.tv_sec - 3600);
	return send_outreq(req);
}

static void start_aging_timer(struct plugin *plugin)
{
	notleak(global_timer(plugin, time_from_sec(60), age_layer, NULL));
}

static struct command_result *xpay_layer_created(struct command *aux_cmd,
						 const char *method,
						 const char *buf,
						 const jsmntok_t *result,
						 void *unused)
{
	start_aging_timer(aux_cmd->plugin);
	return aux_command_done(aux_cmd);
}

static const char *init(struct command *init_cmd,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct plugin *plugin = init_cmd->plugin;
	struct xpay *xpay = xpay_of(plugin);
	size_t num_cupdates_rejected;
	struct out_req *req;

	xpay->global_gossmap = gossmap_load(xpay,
					    GOSSIP_STORE_FILENAME,
				      &num_cupdates_rejected);
	if (!xpay->global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));

	if (num_cupdates_rejected)
		plugin_log(plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_cupdates_rejected);

	xpay->counter = 0;
	if (!pubkey_from_hexstr("02" "0000000000000000000000000000000000000000000000000000000000000001", 66, &xpay->fakenode))
		abort();

	/* Cannot use rpc_scan, as we intercept rpc_command: would block. */
	req = jsonrpc_request_start(aux_command(init_cmd), "getchaininfo",
				    getchaininfo_done,
				    plugin_broken_cb,
				    "getchaininfo");
	json_add_u32(req->js, "last_height", 0);
	send_outreq(req);

	req = jsonrpc_request_start(aux_command(init_cmd), "getinfo",
				    getinfo_done,
				    plugin_broken_cb,
				    "getinfo");
	send_outreq(req);

	req = jsonrpc_request_start(aux_command(init_cmd), "askrene-create-layer",
				    xpay_layer_created,
				    plugin_broken_cb,
				    "askrene-create-layer");
	json_add_string(req->js, "layer", "xpay");
	json_add_bool(req->js, "persistent", true);
	send_outreq(req);

	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"xpay",
		json_xpay,
	},
	{
		"xpay-as-pay",
		json_xpay_as_pay,
	},
};

static struct command_result *handle_block_added(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	struct xpay *xpay = xpay_of(cmd->plugin);
	u32 blockheight;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{block_added:{height:%}}",
			JSON_SCAN(json_to_u32, &blockheight));
	if (err)
		plugin_err(cmd->plugin, "Bad block_added notification: %s",
			   err);

	/* If we were using header height, we might not have passed it yet */
	if (blockheight > xpay->blockheight)
		xpay->blockheight = blockheight;

	return notification_handled(cmd);
}

static const struct plugin_notification notifications[] = {
	{
		"block_added",
		handle_block_added,
	},
};

/* xpay doesn't have maxfeepercent or exemptfee, so we convert them to
 * an absolute restriction here.  If we can't, fail and let pay handle
 * it. */
static bool calc_maxfee(struct command *cmd,
			const char **maxfeestr,
			const char *buf,
			const jsmntok_t *invstringtok,
			const jsmntok_t *amount_msattok,
			const jsmntok_t *exemptfeetok,
			const jsmntok_t *maxfeepercenttok)
{
	u64 maxfeepercent_ppm;
	struct amount_msat amount, maxfee, exemptfee;

	if (!exemptfeetok && !maxfeepercenttok)
		return true;

	/* Can't have both */
	if (*maxfeestr)
		return false;

	/* If they specify amount easy, otherwise take from invoice */
	if (amount_msattok) {
		if (!parse_amount_msat(&amount, buf + amount_msattok->start,
				       amount_msattok->end - amount_msattok->start))
			return false;
	} else {
		const struct bolt11 *b11;
		char *fail;
		const char *invstr;

		/* We need to know total amount to calc fee */
		if (!invstringtok)
			return false;

		invstr = json_strdup(tmpctx, buf, invstringtok);
		b11 = bolt11_decode(tmpctx, invstr, NULL, NULL, NULL, &fail);
		if (b11 != NULL) {
			if (b11->msat == NULL)
				return false;
			amount = *b11->msat;
		} else {
			const struct tlv_invoice *b12;
			b12 = invoice_decode(tmpctx, invstr, strlen(invstr),
					     NULL, NULL, &fail);
			if (b12 == NULL || b12->invoice_amount == NULL)
				return false;
			amount = amount_msat(*b12->invoice_amount);
		}
	}

	if (maxfeepercenttok) {
		if (!json_to_millionths(buf,
					maxfeepercenttok,
					&maxfeepercent_ppm))
			return false;
	} else
		maxfeepercent_ppm = 500000;

	if (!amount_msat_fee(&maxfee, amount, 0, maxfeepercent_ppm / 100))
		return false;

	if (exemptfeetok) {
		if (!parse_amount_msat(&exemptfee, buf + exemptfeetok->start,
				       exemptfeetok->end - exemptfeetok->start))
			return false;
	} else
		exemptfee = AMOUNT_MSAT(5000);

	if (amount_msat_less(maxfee, exemptfee))
		maxfee = exemptfee;

	*maxfeestr = fmt_amount_msat(cmd, maxfee);
	plugin_log(cmd->plugin, LOG_DBG,
		   "Converted maxfeepercent=%.*s, exemptfee=%.*s to maxfee %s",
		   maxfeepercenttok ? json_tok_full_len(maxfeepercenttok) : 5,
		   maxfeepercenttok ? json_tok_full(buf, maxfeepercenttok) : "UNSET",
		   exemptfeetok ? json_tok_full_len(exemptfeetok) : 5,
		   exemptfeetok ? json_tok_full(buf, exemptfeetok) : "UNSET",
		   *maxfeestr);

	return true;
}

static struct command_result *handle_rpc_command(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	struct xpay *xpay = xpay_of(cmd->plugin);
	const jsmntok_t *rpc_tok, *method_tok, *params_tok, *id_tok,
		*bolt11 = NULL, *amount_msat = NULL,
		*partial_msat = NULL, *retry_for = NULL;
	const char *maxfee = NULL;
	struct json_stream *response;

	if (!xpay->take_over_pay)
		goto dont_redirect;

	rpc_tok = json_get_member(buf, params, "rpc_command");
	method_tok = json_get_member(buf, rpc_tok, "method");
	params_tok = json_get_member(buf, rpc_tok, "params");
	id_tok = json_get_member(buf, rpc_tok, "id");
	plugin_log(cmd->plugin, LOG_DBG, "Got command %s",
		   json_strdup(tmpctx, buf, method_tok));

	if (!json_tok_streq(buf, method_tok, "pay"))
		goto dont_redirect;

	/* Array params?  Only handle up to two args (bolt11, msat) */
	if (params_tok->type == JSMN_ARRAY) {
		if (params_tok->size != 1 && params_tok->size != 2) {
			plugin_log(cmd->plugin, LOG_INFORM,
				   "Not redirecting pay (only handle 1 or 2 args): %.*s",
				   json_tok_full_len(params),
				   json_tok_full(buf, params));
			goto dont_redirect;
		}

		bolt11 = params_tok + 1;
		if (params_tok->size == 2)
			amount_msat = json_next(bolt11);
	} else if (params_tok->type == JSMN_OBJECT) {
		const jsmntok_t *t, *maxfeepercent = NULL, *exemptfee = NULL;
		size_t i;

		json_for_each_obj(i, t, params_tok) {
			if (json_tok_streq(buf, t, "bolt11"))
				bolt11 = t + 1;
			else if (json_tok_streq(buf, t, "amount_msat"))
				amount_msat = t + 1;
			else if (json_tok_streq(buf, t, "retry_for"))
				retry_for = t + 1;
			else if (json_tok_streq(buf, t, "maxfee"))
				maxfee = json_strdup(cmd, buf, t + 1);
			else if (json_tok_streq(buf, t, "partial_msat"))
				partial_msat = t + 1;
			else if (json_tok_streq(buf, t, "maxfeepercent"))
				maxfeepercent = t + 1;
			else if (json_tok_streq(buf, t, "exemptfee"))
				exemptfee = t + 1;
			else {
				plugin_log(cmd->plugin, LOG_INFORM,
					   "Not redirecting pay (unknown arg %.*s)",
					   json_tok_full_len(t),
					   json_tok_full(buf, t));
				goto dont_redirect;
			}
		}
		if (!bolt11) {
			plugin_log(cmd->plugin, LOG_INFORM,
				   "Not redirecting pay (missing bolt11 parameter)");
			goto dont_redirect;
		}
		/* If this returns NULL, we let pay handle the weird case */
		if (!calc_maxfee(cmd, &maxfee, buf,
				 bolt11, amount_msat,
				 exemptfee, maxfeepercent)) {
			plugin_log(cmd->plugin, LOG_INFORM,
				   "Not redirecting pay (weird maxfee params)");
			goto dont_redirect;
		}
	} else {
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Not redirecting pay (unexpected params type)");
		goto dont_redirect;
	}

	plugin_log(cmd->plugin, LOG_INFORM, "Redirecting pay->xpay");
	response = jsonrpc_stream_success(cmd);
	json_object_start(response, "replace");
	json_add_string(response, "jsonrpc", "2.0");
	json_add_tok(response, "id", id_tok, buf);
	json_add_string(response, "method", "xpay-as-pay");
	json_object_start(response, "params");
	json_add_tok(response, "invstring", bolt11, buf);
	if (amount_msat)
		json_add_tok(response, "amount_msat", amount_msat, buf);
	if (retry_for)
		json_add_tok(response, "retry_for", retry_for, buf);
	/* Even if this was a number token, handing it as a string is
	 * allowed by parse_msat */
	if (maxfee)
		json_add_string(response, "maxfee", maxfee);
	if (partial_msat)
		json_add_tok(response, "partial_msat", partial_msat, buf);
	json_object_end(response);
	json_object_end(response);
	return command_finished(cmd, response);

dont_redirect:
	return command_hook_success(cmd);
}

static const struct plugin_hook hooks[] = {
	{
		"rpc_command",
		handle_rpc_command,
	},
};

int main(int argc, char *argv[])
{
	struct xpay *xpay;

	setup_locale();
	xpay = tal(NULL, struct xpay);
	xpay->take_over_pay = false;
	plugin_main(argv, init, take(xpay),
		    PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    notifications, ARRAY_SIZE(notifications),
		    hooks, ARRAY_SIZE(hooks),
	            NULL, 0,
		    plugin_option_dynamic("xpay-handle-pay", "bool",
					  "Make xpay take over pay commands it can handle.",
					  bool_option, bool_jsonfmt, &xpay->take_over_pay),
		    NULL);
}
