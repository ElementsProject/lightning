#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <common/amount.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <plugins/libplugin.h>
#include <plugins/xpay/listpays.h>
#include <plugins/xpay/xpay.h>

/* A unique key for each payment attempt, even if the same invoice was
 * attempted multiple times. */
struct pay_sort_key {
	const struct sha256 *payment_hash;
	u64 groupid;
};

enum payment_result_state {
	PAYMENT_PENDING = 1,
	PAYMENT_COMPLETE = 2,
	PAYMENT_FAILED = 4,
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

	/* 1-based index indicating order this payment was created in. */
	u64 created_index;
	/* 1-based index indicating order this payment was changed
	 * (only present if it has changed since creation). */
	u64 updated_index;
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
	return sha256_eq(pm->sortkey.payment_hash, key->payment_hash)
		&& pm->sortkey.groupid == key->groupid;
}

HTABLE_DEFINE_NODUPS_TYPE(struct pay_mpp, pay_mpp_key, pay_mpp_hash, pay_mpp_eq,
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
	if (!amount_msat_accumulate(&mpp->amount_sent, sent))
		plugin_log(p, LOG_BROKEN,
			   "Cannot add amount_sent_msat for %s: %s + %s",
			   invstring,
			   fmt_amount_msat(tmpctx, mpp->amount_sent),
			   fmt_amount_msat(tmpctx, sent));

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

	if (!amount_msat_accumulate(mpp->amount, recv))
		plugin_log(p, LOG_BROKEN,
			   "Cannot add amount_msat for %s: %s + %s",
			   invstring,
			   fmt_amount_msat(tmpctx, *mpp->amount),
			   fmt_amount_msat(tmpctx, sent));
}

static void add_new_entry(struct plugin *plugin,
			  struct json_stream *ret,
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
	else if (pm->state & PAYMENT_PENDING || attempt_ongoing(plugin, pm->payment_hash))
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

	json_add_u64(ret, "created_index", pm->created_index);

	if(pm->updated_index)
		json_add_u64(ret, "updated_index", pm->updated_index);
	json_object_end(ret);
}

static struct command_result *listsendpays_done(struct command *cmd,
						const char *method,
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
		    *completedtok, *grouptok, *created_indextok, *updated_indextok;
		const char *invstr = invstring;
		struct sha256 payment_hash;
		u32 created_at;
		u64 completed_at;
		u64 groupid;
		struct pay_sort_key key;
		u64 created_index;
		u64 updated_index;

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

		created_indextok = json_get_member(buf, t, "created_index");
		updated_indextok = json_get_member(buf, t, "updated_index");
		assert(created_indextok != NULL);
		json_to_u64(buf, created_indextok, &created_index);
		if (updated_indextok != NULL)
			json_to_u64(buf, updated_indextok, &updated_index);
		else
			updated_index = 0;

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
			pm->created_index = created_index;
			pm->updated_index = updated_index;
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
			/* What's the "created_index" of the merged record?
			 * We take the *lowest*, since that will never change
			 * (unless they delete payments!). */
			if (created_index < pm->created_index)
				pm->created_index = created_index;
			/* On the other hand, we take the *highest*
			 * updated_index, so we see any changes. */
			if (updated_index > pm->updated_index)
				pm->updated_index = updated_index;
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
		add_new_entry(cmd->plugin, ret, buf, pm);
	}
	json_array_end(ret);
	return command_finished(cmd, ret);
}

struct command_result *json_listpays(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *params)
{
	const char *invstring, *status_str;
	struct sha256 *payment_hash;
	struct out_req *req;
	const char *listindex;
	u64 *liststart;
	u32 *listlimit;

	/* FIXME: would be nice to parse as a bolt11 so check worked in future */
	if (!param(cmd, buf, params,
		   /* FIXME: parameter should be invstring now */
		   p_opt("bolt11", param_invstring, &invstring),
		   p_opt("payment_hash", param_sha256, &payment_hash),
		   p_opt("status", param_string, &status_str),
		   p_opt("index", param_string, &listindex),
		   p_opt_def("start", param_u64, &liststart, 0),
		   p_opt("limit", param_u32, &listlimit),
		   NULL))
		return command_param_failed();

	if (*liststart != 0 && !listindex) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify {start} with {index}");
	}
	if (listlimit && !listindex) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify {limit} with {index}");
	}

	req = jsonrpc_request_start(cmd, "listsendpays",
				    listsendpays_done, forward_error,
				    cast_const(char *, invstring));
	if (invstring)
		json_add_string(req->js, "bolt11", invstring);

	if (payment_hash)
		json_add_sha256(req->js, "payment_hash", payment_hash);

	if (status_str)
		json_add_string(req->js, "status", status_str);

	if (listindex){
		json_add_string(req->js, "index", listindex);
		if (liststart)
			json_add_u64(req->js, "start", *liststart);
		if (listlimit)
			json_add_u32(req->js, "limit", *listlimit);
	}
	return send_outreq(req);
}
