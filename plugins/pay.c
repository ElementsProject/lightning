#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12_merkle.h>
#include <common/gossmap.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <plugins/libplugin-pay.h>
#include <stdio.h>

/* Public key of this node. */
static struct node_id my_id;
static unsigned int maxdelay_default;
static bool exp_offers;
static bool disablempp = false;

static LIST_HEAD(payments);

struct pay_command {
	/* Global state */
	struct plugin *plugin;

	/* Destination, as text */
	const char *dest;

	/* How much we're paying, and what riskfactor for routing. */
	struct amount_msat msat;
	/* Blank amount to pay, without fees and shadow route(s). */
	struct amount_msat initial_msat;
	/* riskfactor 12.345% -> riskfactor_millionths = 12345000 */
	u64 riskfactor_millionths;
	unsigned int final_cltv;

	/* Limits on what routes we'll accept. */
	/* 12.345% -> maxfee_pct_millionths = 12345000 */
	u64 maxfee_pct_millionths;
	unsigned int maxdelay;
	struct amount_msat exemptfee;

	/* Payment hash, as text. */
	const char *payment_hash;

	/* Payment secret, if specified by invoice. */
	const char *payment_secret;

	/* Payment metadata, if specified by invoice. */
	const char *payment_metadata;

	/* Description, if any. */
	const char *label;

	/* Chatty description of attempts. */
	struct pay_status *ps;

	/* Error to use if getroute says it can't find route. */
	const char *expensive_route;

	/* Time to stop retrying. */
	struct timeabs stoptime;

	/* Channels which have failed us. */
	const char **excludes;

	/* Current routehint, if any. */
	struct route_info *current_routehint;

	/* Any remaining routehints to try. */
	struct route_info **routehints;

	/* Disable the use of shadow route ?  (--developer allows this) */
	double use_shadow;

	/* Current node during shadow route calculation. */
	const char *shadow_dest;
};

/* FIXME: Add this to ccan/time? */
#define UTC_TIMELEN (sizeof("YYYY-mm-ddTHH:MM:SS.nnnZ"))
static void utc_timestring(const struct timeabs *time, char str[UTC_TIMELEN])
{
	char iso8601_msec_fmt[sizeof("YYYY-mm-ddTHH:MM:SS.%03dZ")];
	struct tm *t = gmtime(&time->ts.tv_sec);

	/* Shouldn't happen, but see
	 *  https://github.com/ElementsProject/lightning/issues/4991 :( */
	if (!t) {
		snprintf(str, UTC_TIMELEN, "1970-01-01T00:00:00.000Z");
		return;
	}
	strftime(iso8601_msec_fmt, sizeof(iso8601_msec_fmt), "%FT%T.%%03dZ", t);
	snprintf(str, UTC_TIMELEN, iso8601_msec_fmt,
		 (int) time->ts.tv_nsec / 1000000);
}

static void json_add_sendpay_result(struct json_stream *s, const struct payment_result *r)
{
	if (r->code != 0) {
		/* This is a failure */
		json_add_string(s, "message", r->message);
		json_add_u32(s, "code", r->code);

		json_object_start(s, "data");
		json_add_u32(s, "id", r->id);
		json_add_hex(s, "raw_message", r->raw_message, tal_bytelen(r->raw_message));
		json_add_num(s, "failcode", r->failcode);
		json_add_string(s, "failcodename", r->failcodename);

		if (r->erring_index)
			json_add_num(s, "erring_index", *r->erring_index);

		if (r->erring_node)
			json_add_node_id(s, "erring_node", r->erring_node);

		if (r->erring_channel)
			json_add_short_channel_id(s, "erring_channel",
						  r->erring_channel);

		if (r->erring_direction)
			json_add_num(s, "erring_direction",
				     *r->erring_direction);

		json_object_end(s);
	} else {
		/* This is a success */
		json_add_u32(s, "id", r->id);
		json_add_preimage(s, "payment_preimage", r->payment_preimage);
	}

}

static void paystatus_add_payment(struct json_stream *s, const struct payment *p)
{
	char timestr[UTC_TIMELEN];

	utc_timestring(&p->start_time, timestr);

	json_object_start(s, NULL);
	if (p->why != NULL)
		json_add_string(s, "strategy", p->why);
	json_add_string(s, "start_time", timestr);
	json_add_u64(s, "age_in_seconds",
		     time_to_sec(time_between(time_now(), p->start_time)));

	/* Any final state will have an end time. */
	if (p->step >= PAYMENT_STEP_SPLIT) {
		utc_timestring(&p->end_time, timestr);
		json_add_string(s, "end_time", timestr);
	}

	/* TODO Add routehint. */
	/* TODO Add route details */

	if (p->step < PAYMENT_STEP_SPLIT)
		json_add_string(s, "state", "pending");
	else
		json_add_string(s, "state", "completed");

	if (p->step == PAYMENT_STEP_SPLIT) {
		/* Don't add anything, this is neither a success nor a failure. */
	} else if (p->result != NULL) {
		if (p->step == PAYMENT_STEP_SUCCESS)
			json_object_start(s, "success");
		else
			json_object_start(s, "failure");
		json_add_sendpay_result(s, p->result);
		json_object_end(s);
	} else if (p->step >= PAYMENT_STEP_SPLIT) {
		json_object_start(s, "failure");
		json_add_num(s, "code", PAY_ROUTE_NOT_FOUND);
		json_add_string(s, "message", "Call to getroute: Could not find a route");
		json_object_end(s);
	}

	json_object_end(s);
	for (size_t i = 0; i < tal_count(p->children); i++)
		paystatus_add_payment(s, p->children[i]);
}

static struct command_result *json_paystatus(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	const char *invstring;
	struct json_stream *ret;
	struct payment *p;

	if (!param(cmd, buf, params,
		   /* FIXME: rename to invstring */
		   p_opt("bolt11", param_invstring, &invstring),
		   NULL))
		return command_param_failed();

	ret = jsonrpc_stream_success(cmd);
	json_array_start(ret, "pay");

	list_for_each(&payments, p, list) {
		assert(p->parent == NULL);
		if (invstring && !streq(invstring, p->invstring))
			continue;

		json_object_start(ret, NULL);
		if (p->label != NULL)
			json_add_string(ret, "label", p->label);

		if (p->invstring)
			json_add_invstring(ret, p->invstring);
		json_add_amount_msat(ret, "amount_msat", p->amount);

		json_add_node_id(ret, "destination", p->destination);

		/* TODO(cdecker) Add label in once we track labels. */
		/* TODO(cdecker) Add routehint_modifications in once we track
		 * them. */
		/* TODO(cdecker) Add shadow route once we support it. */

		/* If it's in listpeers right now, this can be 0 */
		json_array_start(ret, "attempts");
		paystatus_add_payment(ret, p);
		json_array_end(ret);
		json_object_end(ret);
	}
	json_array_end(ret);

	return command_finished(cmd, ret);
}

static bool attempt_ongoing(const struct sha256 *payment_hash)
{
	struct payment *root;
	struct payment_tree_result res;
	enum payment_step diff,
	    final_states = PAYMENT_STEP_FAILED | PAYMENT_STEP_SUCCESS;

	list_for_each(&payments, root, list) {
		if (!sha256_eq(payment_hash, root->payment_hash))
			continue;
		res = payment_collect_result(root);
		diff = res.leafstates & ~final_states;
		return diff != 0;
	}
	return false;
}

/* A unique key for each payment attempt, even if the same invoice was
 * attempted multiple times. */
struct pay_sort_key {
	const struct sha256 *payment_hash;
	u64 groupid;
};

/* We consolidate multi-part payments into a single entry. */
struct pay_mpp {
	/* payment_hash from the invoice and lookup key */
	const struct sha256 *payment_hash;

	/* This is the bolt11/bolt12 string */
	const char *invstring;

	/* Accumulated states of all sendpay commands involved. */
	enum payment_result_state state;

	/* Optional label (of first one!) */
	const jsmntok_t *label;
	/* Optional description (used for bolt11 with description_hash) */
	const jsmntok_t *description;
	/* Optional preimage (iff status is successful) */
	const jsmntok_t *preimage;
	/* Only counts "complete" or "pending" payments. */
	size_t num_nonfailed_parts;
	/* Total amount sent ("complete" or "pending" only). */
	struct amount_msat amount_sent;

	/* Total amount received by the recipient ("complete" or "pending"
	 * only). Null if we have any part for which we didn't know the
	 * amount. */
	struct amount_msat *amount;

	/* Timestamp of the first part */
	u32 timestamp;

	/* Completion timestamp. The lowest `completed_at` value for a
	 * successful part. */
	u64 success_at;

	/* The destination of the payment, if specified. */
	const jsmntok_t *destination;

	/* Which sendpay group is this? Necessary for invoices that have been
	 * attempted multiple times. */
	struct pay_sort_key sortkey;
};

static const struct pay_sort_key *pay_mpp_key(const struct pay_mpp *pm)
{
	return &pm->sortkey;
}

static size_t pay_mpp_hash(const struct pay_sort_key *key)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	siphash24_update(&ctx, key->payment_hash, sizeof(struct sha256));
	siphash24_update(&ctx, &key->groupid, sizeof(u64));
	return siphash24_done(&ctx);
}

static bool pay_mpp_eq(const struct pay_mpp *pm, const struct pay_sort_key *key)
{
	return memcmp(pm->sortkey.payment_hash, key->payment_hash,
		      sizeof(struct sha256)) == 0 &&
		      pm->sortkey.groupid == key->groupid;
}

HTABLE_DEFINE_TYPE(struct pay_mpp, pay_mpp_key, pay_mpp_hash, pay_mpp_eq,
		   pay_map);

static void add_amount_sent(struct plugin *p,
			    const char *invstring,
			    struct pay_mpp *mpp,
			    const char *buf,
			    const jsmntok_t *t)
{
	struct amount_msat sent, recv;
	const jsmntok_t *msattok;


	json_to_msat(buf, json_get_member(buf, t, "amount_sent_msat"), &sent);
	if (!amount_msat_add(&mpp->amount_sent, mpp->amount_sent, sent))
		plugin_log(p, LOG_BROKEN,
			   "Cannot add amount_sent_msat for %s: %s + %s",
			   invstring,
			   type_to_string(tmpctx, struct amount_msat, &mpp->amount_sent),
			   type_to_string(tmpctx, struct amount_msat, &sent));

	msattok = json_get_member(buf, t, "amount_msat");

	/* If this is an unannotated partial payment we drop out estimate for
	 * all parts. */
	if (msattok == NULL) {
		mpp->amount = tal_free(mpp->amount);
		return;
	}

	/* If we had a part of this multi-part payment for which we don't know
	 * the amount, then this is NULL. No point in summing up if we don't
	 * have the exact value.*/
	if (mpp->amount == NULL)
		return;

	if (!json_to_msat(buf, msattok, &recv))
		plugin_err(p, "Cannot convert amount_sat %.*s",
			   json_tok_full_len(msattok),
			   json_tok_full(buf, msattok));

	if (!amount_msat_add(mpp->amount, *mpp->amount, recv))
		plugin_log(p, LOG_BROKEN,
			   "Cannot add amount_msat for %s: %s + %s",
			   invstring,
			   type_to_string(tmpctx, struct amount_msat, mpp->amount),
			   type_to_string(tmpctx, struct amount_msat, &sent));
}

static void add_new_entry(struct json_stream *ret,
			  const char *buf,
			  const struct pay_mpp *pm)
{
	json_object_start(ret, NULL);
	if (pm->invstring)
		json_add_invstring(ret, pm->invstring);
	if (pm->description)
		json_add_tok(ret, "description", pm->description, buf);
	if (pm->destination)
		json_add_tok(ret, "destination", pm->destination, buf);

	json_add_sha256(ret, "payment_hash", pm->payment_hash);

	if (pm->state & PAYMENT_COMPLETE)
		json_add_string(ret, "status", "complete");
	else if (pm->state & PAYMENT_PENDING || attempt_ongoing(pm->payment_hash))
		json_add_string(ret, "status", "pending");
	else
		json_add_string(ret, "status", "failed");

	json_add_u32(ret, "created_at", pm->timestamp);

	if (pm->success_at < UINT64_MAX)
		json_add_u64(ret, "completed_at", pm->success_at);

	if (pm->label)
		json_add_tok(ret, "label", pm->label, buf);
	if (pm->preimage)
		json_add_tok(ret, "preimage", pm->preimage, buf);

	/* This is only tallied for pending and successful payments, not
	 * failures. */
	if (pm->amount != NULL && pm->num_nonfailed_parts > 0)
		json_add_amount_msat(ret, "amount_msat", *pm->amount);

	json_add_amount_msat(ret, "amount_sent_msat", pm->amount_sent);

	if (pm->num_nonfailed_parts > 1)
		json_add_u64(ret, "number_of_parts",
			     pm->num_nonfailed_parts);
	json_object_end(ret);
}

static struct command_result *listsendpays_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						char *invstring)
{
	size_t i;
	const jsmntok_t *t, *arr;
	struct json_stream *ret;
	struct pay_map *pay_map;
	struct pay_mpp *pm;
	struct pay_sort_key *order = tal_arr(tmpctx, struct pay_sort_key, 0);

	pay_map = tal(cmd, struct pay_map);
	pay_map_init(pay_map);

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY)
		return command_fail(cmd, LIGHTNINGD,
				    "Unexpected non-array result from listsendpays");

	json_for_each_arr(i, t, arr) {
		const jsmntok_t *status, *invstrtok, *hashtok, *createdtok,
		    *completedtok, *grouptok;
		const char *invstr = invstring;
		struct sha256 payment_hash;
		u32 created_at;
		u64 completed_at;
		u64 groupid;
		struct pay_sort_key key;

		invstrtok = json_get_member(buf, t, "bolt11");
		if (!invstrtok)
			invstrtok = json_get_member(buf, t, "bolt12");
		hashtok = json_get_member(buf, t, "payment_hash");
		createdtok = json_get_member(buf, t, "created_at");
		completedtok = json_get_member(buf, t, "completed_at");
		assert(hashtok != NULL);
		assert(createdtok != NULL);

		if (completedtok != NULL)
			json_to_u64(buf, completedtok, &completed_at);
		else
			completed_at = UINT64_MAX;

		grouptok = json_get_member(buf, t, "groupid");
		if (grouptok != NULL)
			json_to_u64(buf, grouptok, &groupid);
		else
			groupid = 0;

		json_to_sha256(buf, hashtok, &payment_hash);
		json_to_u32(buf, createdtok, &created_at);
		if (invstrtok)
			invstr = json_strdup(cmd, buf, invstrtok);

		key.payment_hash = &payment_hash;
		key.groupid = groupid;

		pm = pay_map_get(pay_map, &key);
		if (!pm) {
			pm = tal(cmd, struct pay_mpp);
			pm->state = 0;
			pm->payment_hash = tal_dup(pm, struct sha256, &payment_hash);
			pm->invstring = tal_steal(pm, invstr);
			pm->destination = json_get_member(buf, t, "destination");
			pm->label = json_get_member(buf, t, "label");
			pm->description = json_get_member(buf, t, "description");
			pm->preimage = NULL;
			pm->amount_sent = AMOUNT_MSAT(0);
			pm->amount = talz(pm, struct amount_msat);
			pm->num_nonfailed_parts = 0;
			pm->timestamp = created_at;
			pm->sortkey.payment_hash = pm->payment_hash;
			pm->sortkey.groupid = groupid;
			pm->success_at = UINT64_MAX;
			pay_map_add(pay_map, pm);
			// First time we see the groupid we add it to the order
			// array, so we can retrieve them in the correct order.
			tal_arr_expand(&order, pm->sortkey);
		} else {
			/* Not all payments have bolt11/bolt12 or
			 * description, as an optimization */
			if (!pm->invstring)
				pm->invstring = tal_steal(pm, invstr);
			if (!pm->description)
				pm->description = json_get_member(buf, t, "description");
		}

		status = json_get_member(buf, t, "status");
		if (json_tok_streq(buf, status, "complete")) {
			add_amount_sent(cmd->plugin, pm->invstring, pm, buf, t);
			pm->num_nonfailed_parts++;
			pm->preimage
				= json_get_member(buf, t, "payment_preimage");
			pm->state |= PAYMENT_COMPLETE;

			/* We count down from UINT64_MAX. */
			if (pm->success_at > completed_at)
				pm->success_at = completed_at;

		} else if (json_tok_streq(buf, status, "pending")) {
			add_amount_sent(cmd->plugin, pm->invstring, pm, buf, t);
			pm->num_nonfailed_parts++;
			pm->state |= PAYMENT_PENDING;
		} else {
			pm->state |= PAYMENT_FAILED;
		}
	}

	ret = jsonrpc_stream_success(cmd);
	json_array_start(ret, "pays");
	for (i = 0; i < tal_count(order); i++) {
		pm = pay_map_get(pay_map, &order[i]);
		assert(pm != NULL);
		add_new_entry(ret, buf, pm);
	}
	json_array_end(ret);
	return command_finished(cmd, ret);
}

static struct command_result *json_listpays(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *params)
{
	const char *invstring, *status_str;
	struct sha256 *payment_hash;
	struct out_req *req;

	/* FIXME: would be nice to parse as a bolt11 so check worked in future */
	if (!param(cmd, buf, params,
		   /* FIXME: parameter should be invstring now */
		   p_opt("bolt11", param_invstring, &invstring),
		   p_opt("payment_hash", param_sha256, &payment_hash),
		   p_opt("status", param_string, &status_str),
		   NULL))
		return command_param_failed();

	req = jsonrpc_request_start(cmd->plugin, cmd, "listsendpays",
				    listsendpays_done, forward_error,
				    cast_const(char *, invstring));
	if (invstring)
		json_add_string(req->js, "bolt11", invstring);

	if (payment_hash)
		json_add_sha256(req->js, "payment_hash", payment_hash);

	if (status_str)
		json_add_string(req->js, "status", status_str);
	return send_outreq(cmd->plugin, req);
}

static void memleak_mark_payments(struct plugin *p, struct htable *memtable)
{
	memleak_scan_list_head(memtable, &payments);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	rpc_scan(p, "getinfo", take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &my_id));

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{configs:"
		 "{max-locktime-blocks:{value_int:%},"
		 "experimental-offers:{set:%}}}",
		 JSON_SCAN(json_to_number, &maxdelay_default),
		 JSON_SCAN(json_to_bool, &exp_offers));

	plugin_set_memleak_handler(p, memleak_mark_payments);
	return NULL;
}

static void on_payment_success(struct payment *payment)
{
	struct payment *p, *nxt;
	struct payment_tree_result result = payment_collect_result(payment);
	struct json_stream *ret;
	struct command *cmd;
	assert(result.treestates & PAYMENT_STEP_SUCCESS);
	assert(result.leafstates & PAYMENT_STEP_SUCCESS);
	assert(result.preimage != NULL);

	/* Iterate through any pending payments we suspended and
	 * terminate them. */

	list_for_each_safe(&payments, p, nxt, list) {
		/* The result for the active payment is returned in
		 * `payment_finished`. */
		if (payment == p)
			continue;

		/* Both groupid and payment_hash must match. This is
		 * because when we suspended the payment itself, we
		 * set the groupid to match. */
		if (!sha256_eq(payment->payment_hash, p->payment_hash) ||
		    payment->groupid != p->groupid)
			continue;
		if (p->cmd == NULL)
			continue;

		cmd = p->cmd;
		p->cmd = NULL;

		ret = jsonrpc_stream_success(cmd);
		json_add_node_id(ret, "destination", p->destination);
		json_add_sha256(ret, "payment_hash", p->payment_hash);
		json_add_timeabs(ret, "created_at", p->start_time);
		json_add_num(ret, "parts", result.attempts);

		json_add_amount_msat(ret, "amount_msat", p->amount);
		json_add_amount_msat(ret, "amount_sent_msat", result.sent);

		if (result.leafstates != PAYMENT_STEP_SUCCESS)
			json_add_string(
				ret, "warning_partial_completion",
				"Some parts of the payment are not yet "
				"completed, but we have the confirmation "
				"from the recipient.");
		json_add_preimage(ret, "payment_preimage", result.preimage);

		json_add_string(ret, "status", "complete");
		if (command_finished(cmd, ret)) {/* Ignore result. */}
	}
}

static void payment_add_attempt(struct json_stream *s, const char *fieldname, struct payment *p, bool recurse)
{
	bool finished = p->step >= PAYMENT_STEP_RETRY,
	     success = p->step == PAYMENT_STEP_SUCCESS;

	/* A fieldname is only reasonable if we're not recursing. Otherwise the
	 * fieldname would be reused for all attempts. */
	assert(!recurse || fieldname == NULL);

	json_object_start(s, fieldname);

	if (!finished)
		json_add_string(s, "status", "pending");
	else if (success)
		json_add_string(s, "status", "success");
	else
		json_add_string(s, "status", "failed");

	if (p->failreason != NULL)
		json_add_string(s, "failreason", p->failreason);

	json_add_u64(s, "partid", p->partid);
	json_add_amount_msat(s, "amount_msat", p->amount);
	if (p->parent != NULL)
		json_add_u64(s, "parent_partid", p->parent->partid);

	json_object_end(s);
	for (size_t i=0; i<tal_count(p->children); i++) {
		payment_add_attempt(s, fieldname, p->children[i], recurse);
	}
}

static void payment_json_add_attempts(struct json_stream *s,
				      const char *fieldname, struct payment *p)
{
	assert(p == payment_root(p));
	json_array_start(s, fieldname);
	payment_add_attempt(s, NULL, p, true);
	json_array_end(s);
}

static void on_payment_failure(struct payment *payment)
{
	struct payment *p, *nxt;
	struct payment_tree_result result = payment_collect_result(payment);
	list_for_each_safe(&payments, p, nxt, list)
	{
		struct json_stream *ret;
		struct command *cmd;
		const char *msg;
		/* The result for the active payment is returned in
		 * `payment_finished`. */
		if (payment == p)
			continue;

		/* When we suspended we've set the groupid to match so
		 * we'd know which calls were duplicates. */
		if (!sha256_eq(payment->payment_hash, p->payment_hash) ||
		    payment->groupid != p->groupid)
			continue;
		if (p->cmd == NULL)
			continue;

		cmd = p->cmd;
		p->cmd = NULL;
		if (p->aborterror != NULL) {
			/* We set an explicit toplevel error message,
			 * so let's report that. */
			ret = jsonrpc_stream_fail(cmd, PAY_STOPPED_RETRYING,
						  p->aborterror);
			payment_json_add_attempts(ret, "attempts", p);

			if (command_finished(cmd, ret)) {/* Ignore result. */}
		} else if (result.failure == NULL || result.failure->failcode < NODE) {
			/* This is failing because we have no more routes to try */
			msg = tal_fmt(cmd,
				      "Ran out of routes to try after "
				      "%d attempt%s: see `paystatus`",
				      result.attempts,
				      result.attempts == 1 ? "" : "s");
			ret = jsonrpc_stream_fail(cmd, PAY_STOPPED_RETRYING,
						  msg);
			payment_json_add_attempts(ret, "attempts", p);

			if (command_finished(cmd, ret)) {/* Ignore result. */}

		}  else {
			struct payment_result *failure = result.failure;
			assert(failure!= NULL);

			ret = jsonrpc_stream_fail(cmd, failure->code,
						  failure->message);

			json_add_u64(ret, "id", failure->id);

			json_add_u32(ret, "failcode", failure->failcode);
			json_add_string(ret, "failcodename",
					failure->failcodename);

			if (p->invstring)
				json_add_invstring(ret, p->invstring);

			json_add_hex_talarr(ret, "raw_message",
					    result.failure->raw_message);
			json_add_num(ret, "created_at", p->start_time.ts.tv_sec);
			json_add_node_id(ret, "destination", p->destination);
			json_add_sha256(ret, "payment_hash", p->payment_hash);
			// OK
			if (result.leafstates & PAYMENT_STEP_SUCCESS) {
				/* If one sub-payment succeeded then we have
				 * proof of payment, and the payment is a
				 * success. */
				json_add_string(ret, "status", "complete");

			} else if (result.leafstates & ~PAYMENT_STEP_FAILED) {
				/* If there are non-failed leafs we are still trying. */
				json_add_string(ret, "status", "pending");

			} else {
				json_add_string(ret, "status", "failed");
			}

			json_add_amount_msat(ret, "amount_msat", p->amount);

			json_add_amount_msat(ret, "amount_sent_msat",
					     result.sent);

			if (failure != NULL) {
				if (failure->erring_index)
					json_add_num(ret, "erring_index",
						     *failure->erring_index);

				if (failure->erring_node)
					json_add_node_id(ret, "erring_node",
							 failure->erring_node);

				if (failure->erring_channel)
					json_add_short_channel_id(
					    ret, "erring_channel",
					    failure->erring_channel);

				if (failure->erring_direction)
					json_add_num(
					    ret, "erring_direction",
					    *failure->erring_direction);
			}

			if (command_finished(cmd, ret)) { /* Ignore result. */}
		}
	}
}

static struct command_result *selfpay_success(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct payment *p)
{
	struct json_stream *ret = jsonrpc_stream_success(cmd);
	struct preimage preimage;
	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{payment_preimage:%}",
			JSON_SCAN(json_to_preimage, &preimage));
	if (err)
		plugin_err(p->plugin,
			   "selfpay didn't have payment_preimage? %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	json_add_payment_success(ret, p, &preimage, NULL);
	return command_finished(cmd, ret);
}

static struct command_result *selfpay(struct command *cmd, struct payment *p)
{
	struct out_req *req;

	/* This "struct payment" simply gets freed once command is done. */
	tal_steal(cmd, p);

	req = jsonrpc_request_start(cmd->plugin, cmd, "sendpay",
				    selfpay_success,
				    forward_error, p);
	/* Empty route means "to-self" */
	json_array_start(req->js, "route");
	json_array_end(req->js);
	json_add_sha256(req->js, "payment_hash", p->payment_hash);
	if (p->label)
		json_add_string(req->js, "label", p->label);
	json_add_amount_msat(req->js, "amount_msat", p->amount);
	json_add_string(req->js, "bolt11", p->invstring);
	if (p->payment_secret)
		json_add_secret(req->js, "payment_secret", p->payment_secret);
	json_add_u64(req->js, "groupid", p->groupid);
	if (p->payment_metadata)
		json_add_hex_talarr(req->js, "payment_metadata", p->payment_metadata);
	if (p->description)
		json_add_string(req->js, "description", p->description);
	return send_outreq(cmd->plugin, req);
}

/* We are interested in any prior attempts to pay this payment_hash /
 * invoice so we can set the `groupid` correctly and ensure we don't
 * already have a pending payment running. We also collect the summary
 * about an eventual previous complete payment so we can return that
 * as a no-op. */
static struct command_result *
payment_listsendpays_previous(struct command *cmd, const char *buf,
			      const jsmntok_t *result, struct payment *p)
{
	size_t i;
	const jsmntok_t *t, *arr, *err;
	/* What was the groupid of an eventual previous attempt? */
	u64 last_group = 0;
	/* Do we have pending sendpays for the previous attempt? */
	bool pending = false;

	/* Group ID of the first pending payment, this will be the one
	 * who's result gets replayed if we end up suspending. */
	u64 pending_group_id = 0;
	/* Did a prior attempt succeed? */
	bool completed = false;

	/* Metadata for a complete payment, if one exists. */
	struct json_stream *ret;
	u32 parts = 0;
	struct preimage preimage;
	struct amount_msat sent, msat;
	struct node_id destination;
	u32 created_at;

	err = json_get_member(buf, result, "error");
	if (err)
		return command_fail(
			   cmd, LIGHTNINGD,
			   "Error retrieving previous pay attempts: %s",
			   json_strdup(tmpctx, buf, err));

			   arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY)
		return command_fail(
		    cmd, LIGHTNINGD,
		    "Unexpected non-array result from listsendpays");

	/* We iterate through all prior sendpays, looking for the
	 * latest group and remembering what its state is. */
	json_for_each_arr(i, t, arr)
	{
		u64 groupid;
		const jsmntok_t *status, *grouptok;
		struct amount_msat diff_sent, diff_msat;
		grouptok = json_get_member(buf, t, "groupid");
		json_to_u64(buf, grouptok, &groupid);

		/* New group, reset what we collected. */
		if (last_group != groupid) {
			completed = false;
			pending = false;
			last_group = groupid;

			parts = 1;
			json_scan(tmpctx, buf, t,
				  "{destination:%"
				  ",created_at:%"
				  ",amount_msat:%"
				  ",amount_sent_msat:%"
				  ",payment_preimage:%}",
				  JSON_SCAN(json_to_node_id, &destination),
				  JSON_SCAN(json_to_u32, &created_at),
				  JSON_SCAN(json_to_msat, &msat),
				  JSON_SCAN(json_to_msat, &sent),
				  JSON_SCAN(json_to_preimage, &preimage));
		} else {
			json_scan(tmpctx, buf, t,
				  "{amount_msat:%"
				  ",amount_sent_msat:%}",
				  JSON_SCAN(json_to_msat, &diff_msat),
				  JSON_SCAN(json_to_msat, &diff_sent));
			if (!amount_msat_add(&msat, msat, diff_msat) ||
			    !amount_msat_add(&sent, sent, diff_sent))
				plugin_err(p->plugin,
					   "msat overflow adding up parts");
			parts++;
		}

		status = json_get_member(buf, t, "status");
		completed |= json_tok_streq(buf, status, "complete");
		pending |= json_tok_streq(buf, status, "pending");

		/* Remember the group id of the first pending group so
		 * we can replay its result later. */
		if (!pending_group_id && pending)
			pending_group_id = groupid;
	}

	if (completed) {
		ret = jsonrpc_stream_success(cmd);
		json_add_preimage(ret, "payment_preimage", &preimage);
		json_add_string(ret, "status", "complete");
		json_add_amount_msat(ret, "amount_msat", msat);
		json_add_amount_msat(ret, "amount_sent_msat", sent);
		json_add_node_id(ret, "destination", p->destination);
		json_add_sha256(ret, "payment_hash", p->payment_hash);
		json_add_u32(ret, "created_at", created_at);
		json_add_num(ret, "parts", parts);
		return command_finished(cmd, ret);
	} else if (pending) {
		/* We suspend this call and wait for the
		 * `on_payment_success` or `on_payment_failure`
		 * handler of the currently running payment to notify
		 * us about its completion. We latch on to the result
		 * from the call we extracted above. */
		p->groupid = pending_group_id;
		return command_still_pending(cmd);
	}
	p->groupid = last_group + 1;
	p->on_payment_success = on_payment_success;
	p->on_payment_failure = on_payment_failure;

	/* Bypass everything if we're doing (synchronous) self-pay */
	if (node_id_eq(&my_id, p->destination))
		return selfpay(cmd, p);

	payment_start(p);
	return command_still_pending(cmd);
}

struct payment_modifier *paymod_mods[] = {
	&check_preapproveinvoice_pay_mod,
	/* NOTE: The order in which these four paymods are executed is
	 * significant!
	 * local_channel_hints *must* execute first before route_exclusions
	 * which *must* execute before directpay.
	 * exemptfee *must* also execute before directpay.
	 */
	&local_channel_hints_pay_mod,
	&route_exclusions_pay_mod,
	&exemptfee_pay_mod,
	&directpay_pay_mod,
	&shadowroute_pay_mod,
	/* NOTE: The order in which these two paymods are executed is
	 * significant! `routehints` *must* execute first before
	 * payee_incoming_limit.
	 *
	 * FIXME: Giving an ordered list of paymods to the paymod
	 * system is the wrong interface, given that the order in
	 * which paymods execute is significant.  (This is typical of
	 * Entity-Component-System pattern.)  What should be done is
	 * that libplugin-pay should have a canonical list of paymods
	 * in the order they execute correctly, and whether they are
	 * default-enabled/default-disabled, and then clients like
	 * `pay` and `keysend` will disable/enable paymods that do not
	 * help them, instead of the current interface where clients
	 * provide an *ordered* list of paymods they want to use.
	 */
	&routehints_pay_mod,
	&payee_incoming_limit_pay_mod,
	&waitblockheight_pay_mod,
	&retry_pay_mod,
	&adaptive_splitter_pay_mod,
	NULL,
};

static void destroy_payment(struct payment *p)
{
	list_del(&p->list);
}

static struct command_result *json_pay(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *params)
{
	struct payment *p;
	const char *b11str;
	struct bolt11 *b11;
	char *b11_fail, *b12_fail;
	u64 *maxfee_pct_millionths;
	u32 *maxdelay;
	struct amount_msat *exemptfee, *msat, *maxfee;
	const char *label, *description;
	unsigned int *retryfor;
	u64 *riskfactor_millionths;
	struct shadow_route_data *shadow_route;
	struct amount_msat *invmsat;
	u64 invexpiry;
	struct sha256 *local_invreq_id;
	const struct tlv_invoice *b12;
	struct out_req *req;
	struct route_exclusion **exclusions;
	bool *dev_use_shadow;

	/* If any of the modifiers need to add params to the JSON-RPC call we
	 * would add them to the `param()` call below, and have them be
	 * initialized directly that way. */
	if (!param(cmd, buf, params,
		   /* FIXME: parameter should be invstring now */
		   p_req("bolt11", param_invstring, &b11str),
		   p_opt("amount_msat|msatoshi", param_msat, &msat),
		   p_opt("label", param_string, &label),
		   p_opt_def("riskfactor", param_millionths,
			     &riskfactor_millionths, 10000000),
		   p_opt("maxfeepercent", param_millionths,
			 &maxfee_pct_millionths),
		   p_opt_def("retry_for", param_number, &retryfor, 60),
		   p_opt_def("maxdelay", param_number, &maxdelay,
			     maxdelay_default),
		   p_opt("exemptfee", param_msat, &exemptfee),
		   p_opt("localinvreqid", param_sha256, &local_invreq_id),
		   p_opt("exclude", param_route_exclusion_array, &exclusions),
		   p_opt("maxfee", param_msat, &maxfee),
		   p_opt("description", param_escaped_string, &description),
		   p_opt_dev("dev_use_shadow", param_bool, &dev_use_shadow, true),
		      NULL))
		return command_param_failed();

	p = payment_new(cmd, cmd, NULL /* No parent */, paymod_mods);
	p->invstring = tal_steal(p, b11str);
	p->description = tal_steal(p, description);
	/* Overridded by bolt12 if present */
	p->blindedpath = NULL;
	p->blindedpay = NULL;

	if (!bolt12_has_prefix(b11str)) {
		b11 =
		    bolt11_decode(tmpctx, b11str, plugin_feature_set(cmd->plugin),
				  description, chainparams, &b11_fail);
		if (b11 == NULL)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt11: %s", b11_fail);

		invmsat = b11->msat;
		invexpiry = b11->timestamp + b11->expiry;

		p->destination = tal_dup(p, struct node_id, &b11->receiver_id);
		p->payment_hash = tal_dup(p, struct sha256, &b11->payment_hash);
		p->payment_secret =
			tal_dup_or_null(p, struct secret, b11->payment_secret);
		if (b11->metadata)
			p->payment_metadata = tal_dup_talarr(p, u8, b11->metadata);
		else
			p->payment_metadata = NULL;
		/* FIXME: libplugin-pay plays with this array, and there are many FIXMEs
		 * about it.  But it looks like a leak, so we suppress it here. */
		p->routes = notleak_with_children(tal_steal(p, b11->routes));
		p->min_final_cltv_expiry = b11->min_final_cltv_expiry;
		p->features = tal_steal(p, b11->features);
		/* Sanity check */
		if (feature_offered(b11->features, OPT_VAR_ONION) &&
		    !b11->payment_secret)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Invalid bolt11:"
			    " sets feature var_onion with no secret");
	} else {
		b12 = invoice_decode(tmpctx, b11str, strlen(b11str),
				     plugin_feature_set(cmd->plugin),
				     chainparams, &b12_fail);
		if (b12 == NULL)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt12: %s", b12_fail);
		if (!exp_offers)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "experimental-offers disabled");

		/* FIXME: We disable MPP for now */
		/* p->features = tal_steal(p, b12->features); */
		p->features = NULL;

		if (!b12->invoice_node_id)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing node_id");
		if (!b12->invoice_payment_hash)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing payment_hash");
		if (!b12->invoice_created_at)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing created_at");
		if (!b12->invoice_amount)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing invoice_amount");
		invmsat = tal(cmd, struct amount_msat);
		*invmsat = amount_msat(*b12->invoice_amount);

		p->destination = tal(p, struct node_id);
		node_id_from_pubkey(p->destination, b12->invoice_node_id);
		p->payment_hash = tal_dup(p, struct sha256,
					  b12->invoice_payment_hash);
		if (b12->invreq_recurrence_counter && !label)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "recurring invoice requires a label");

		/* BOLT-offers #12:
		 * - MUST reject the invoice if `invoice_paths` is not present
		 *  or is empty.
		 */
		if (tal_count(b12->invoice_paths) == 0)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing invoice_paths");

		/* BOLT-offers #12:
		 * - MUST reject the invoice if `invoice_blindedpay` does not
		 *   contain exactly one `blinded_payinfo` per
		 *   `invoice_paths`.`blinded_path`. */
		if (tal_count(b12->invoice_paths)
		    != tal_count(b12->invoice_blindedpay)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Wrong blinding info: %zu paths, %zu payinfo",
					    tal_count(b12->invoice_paths),
					    tal_count(b12->invoice_blindedpay));
		}

		/* FIXME: do MPP across these!  We choose first one. */
		p->blindedpath = tal_steal(p, b12->invoice_paths[0]);
		p->blindedpay = tal_steal(p, b12->invoice_blindedpay[0]);
		p->min_final_cltv_expiry = p->blindedpay->cltv_expiry_delta;

		/* Set destination to introduction point */
		node_id_from_pubkey(p->destination, &p->blindedpath->first_node_id);
		p->payment_metadata = NULL;
		p->routes = NULL;
		/* BOLT-offers #12:
		 * - if `invoice_relative_expiry` is present:
		 *   - MUST reject the invoice if the current time since
		 *     1970-01-01 UTC is greater than `invoice_created_at` plus
		 *     `seconds_from_creation`.
		 * - otherwise:
		 *   - MUST reject the invoice if the current time since
		 *     1970-01-01 UTC is greater than `invoice_created_at` plus
		 *     7200.
		 */
		if (b12->invoice_relative_expiry)
			invexpiry = *b12->invoice_created_at + *b12->invoice_relative_expiry;
		else
			invexpiry = *b12->invoice_created_at + BOLT12_DEFAULT_REL_EXPIRY;
		p->local_invreq_id = tal_steal(p, local_invreq_id);
	}

	if (time_now().ts.tv_sec > invexpiry)
		return command_fail(cmd, PAY_INVOICE_EXPIRED, "Invoice expired");

	if (invmsat) {
		if (msat) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter unnecessary");
		}
		p->amount = *invmsat;
		tal_free(invmsat);
	} else {
		if (!msat) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter required");
		}
		p->amount = *msat;
	}

	/* We replace real final values if we're using a blinded path */
	if (p->blindedpath) {
		p->blindedfinalcltv = p->min_final_cltv_expiry;
		p->blindedfinalamount = p->amount;

		p->min_final_cltv_expiry += p->blindedpay->cltv_expiry_delta;
		if (!amount_msat_add_fee(&p->amount,
					 p->blindedpay->fee_base_msat,
					 p->blindedpay->fee_proportional_millionths))
			return command_fail(cmd, PAY_ROUTE_TOO_EXPENSIVE,
					    "This payment blinded path fee overflows!");
	}

	p->local_id = &my_id;
	p->json_buffer = buf;
	p->json_toks = params;
	p->why = "Initial attempt";
	p->constraints.cltv_budget = *maxdelay;
	tal_free(maxdelay);
	p->deadline = timeabs_add(time_now(), time_from_sec(*retryfor));
	tal_free(retryfor);
	p->getroute->riskfactorppm = *riskfactor_millionths;
	tal_free(riskfactor_millionths);

	if (maxfee) {
		if (maxfee_pct_millionths || exemptfee) {
			return command_fail(
				cmd, JSONRPC2_INVALID_PARAMS,
				"If you specify maxfee, cannot specify maxfeepercent or exemptfee.");
		}
		p->constraints.fee_budget = *maxfee;
		payment_mod_exemptfee_get_data(p)->amount = AMOUNT_MSAT(0);
	} else {
		u64 maxppm;

		if (maxfee_pct_millionths)
			maxppm = *maxfee_pct_millionths / 100;
		else
			maxppm = 500000 / 100;
		if (!amount_msat_fee(&p->constraints.fee_budget, p->amount, 0,
				     maxppm)) {
			return command_fail(
				cmd, JSONRPC2_INVALID_PARAMS,
				"Overflow when computing fee budget, fee rate too high.");
		}
		payment_mod_exemptfee_get_data(p)->amount
			= exemptfee ? *exemptfee : AMOUNT_MSAT(5000);
	}

	shadow_route = payment_mod_shadowroute_get_data(p);
	payment_mod_adaptive_splitter_get_data(p)->disable = disablempp;
	payment_mod_route_exclusions_get_data(p)->exclusions = exclusions;

	/* This is an MPP enabled pay command, disable amount fuzzing. */
	shadow_route->fuzz_amount = false;
	shadow_route->use_shadow = *dev_use_shadow;
	tal_free(dev_use_shadow);

	p->label = tal_steal(p, label);
	list_add_tail(&payments, &p->list);
	tal_add_destructor(p, destroy_payment);
	/* We're keeping this around now */
	tal_steal(cmd->plugin, p);

	req = jsonrpc_request_start(cmd->plugin, cmd, "listsendpays",
				    payment_listsendpays_previous,
				    payment_listsendpays_previous, p);

	json_add_sha256(req->js, "payment_hash", p->payment_hash);
	return send_outreq(cmd->plugin, req);
}

static const struct plugin_command commands[] = {
	{
		"paystatus",
		"payment",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	}, {
		"listpays",
		"payment",
		"List result of payment {bolt11} or {payment_hash}, or all",
		"Covers old payments (failed and succeeded) and current ones.",
		json_listpays
	},
	{
		"pay",
		"payment",
		"Send payment specified by {bolt11}",
		"Attempt to pay the {bolt11} invoice.",
		json_pay
	},
};

static const char *notification_topics[] = {
	"pay_success",
	"pay_failure",
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, NULL, 0,
		    notification_topics, ARRAY_SIZE(notification_topics),
		    plugin_option("disable-mpp", "flag",
				  "Disable multi-part payments.",
				  flag_option, &disablempp),
		    NULL);
}
