#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12.h>
#include <common/bolt12_id.h>
#include <common/gossmap.h>
#include <common/iso4217.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/onion_message.h>
#include <common/overflows.h>
#include <plugins/offers.h>
#include <plugins/offers_offer.h>
#include <sodium/randombytes.h>

static bool msat_or_any(const char *buffer,
			const jsmntok_t *tok,
			struct tlv_offer *offer)
{
	struct amount_msat msat;
	if (json_tok_streq(buffer, tok, "any"))
		return true;

	if (!parse_amount_msat(&msat,
			       buffer + tok->start, tok->end - tok->start))
		return false;

	offer->offer_amount = tal_dup(offer, u64,
				&msat.millisatoshis); /* Raw: other currencies */
	return true;
}

static struct command_result *param_amount(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   struct tlv_offer *offer)
{
	const struct iso4217_name_and_divisor *isocode;
	jsmntok_t number, whole, frac;
	u64 cents;

	if (msat_or_any(buffer, tok, offer))
		return NULL;

	offer->offer_amount = tal(offer, u64);

	/* BOLT-offers #12:
	 *
	 * - MUST specify `offer_currency` `iso4217` as an ISO 4712 three-letter code.
	 * - MUST specify `offer_amount` in the currency unit adjusted by the ISO 4712
	 *   exponent (e.g. USD cents).
	 */
	if (tok->end - tok->start < ISO4217_NAMELEN)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be 'any', msatoshis or <amount>[.<amount>]<ISO-4712>");

	isocode = find_iso4217(buffer + tok->end - ISO4217_NAMELEN, ISO4217_NAMELEN);
	if (!isocode)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Unknown currency suffix %.*s",
				    ISO4217_NAMELEN,
				    buffer + tok->end - ISO4217_NAMELEN);

	offer->offer_currency
		= tal_dup_arr(offer, utf8, isocode->name, ISO4217_NAMELEN, 0);

	number = *tok;
	number.end -= ISO4217_NAMELEN;
	if (!split_tok(buffer, &number, '.', &whole, &frac)) {
		whole = number;
		cents = 0;
	} else {
		if (frac.end - frac.start != isocode->minor_unit)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Currency %s requires %u minor units",
					    isocode->name, isocode->minor_unit);
		if (!json_to_u64(buffer, &frac, &cents))
			return command_fail_badparam(cmd, name, buffer,
						     &number,
						     "Bad minor units");
	}

	if (!json_to_u64(buffer, &whole, offer->offer_amount))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be 'any', msatoshis or <ISO-4712><amount>[.<amount>]");

	for (size_t i = 0; i < isocode->minor_unit; i++) {
		if (mul_overflows_u64(*offer->offer_amount, 10))
			return command_fail_badparam(cmd, name, buffer,
						     &whole,
						     "excessively large value");
		*offer->offer_amount *= 10;
	}

	*offer->offer_amount += cents;
	return NULL;
}

/* BOLT 13:
 * - MUST set `time_unit` to 0 (seconds), 1 (days), 2 (months), 3 (years).
 */
struct time_string {
	const char *suffix;
	u32 unit;
	u64 mul;
};

static const struct time_string *json_to_time(const char *buffer,
					      const jsmntok_t *tok,
					      u32 *mul)
{
	static const struct time_string suffixes[] = {
		{ "second", 0, 1 },
		{ "seconds", 0, 1 },
		{ "minute", 0, 60 },
		{ "minutes", 0, 60 },
		{ "hour", 0, 60*60 },
		{ "hours", 0, 60*60 },
		{ "day", 1, 1 },
		{ "days", 1, 1 },
		{ "week", 1, 7 },
		{ "weeks", 1, 7 },
		{ "month", 2, 1 },
		{ "months", 2, 1 },
		{ "year", 3, 1 },
		{ "years", 3, 1 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(suffixes); i++) {
		if (json_tok_endswith(buffer, tok, suffixes[i].suffix)) {
			jsmntok_t t = *tok;
			t.end -= strlen(suffixes[i].suffix);
			if (!json_to_u32(buffer, &t, mul))
				return NULL;
			return suffixes + i;
		}
	}
	return NULL;
}

static struct command_result *param_recurrence(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct recurrence **recurrence)
{
	u32 mul;
	const struct time_string *ts;

	ts = json_to_time(buffer, tok, &mul);
	if (!ts)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "not a valid time");

	*recurrence = tal(cmd, struct recurrence);
	(*recurrence)->time_unit = ts->unit;
	(*recurrence)->period = ts->mul * mul;
	return NULL;
}

static struct command_result *param_recurrence_base(struct command *cmd,
						    const char *name,
						    const char *buffer,
						    const jsmntok_t *tok,
						    struct recurrence_base **base)
{
	*base = tal(cmd, struct recurrence_base);
	(*base)->start_any_period = true;

	if (!json_to_u64(buffer, tok, &(*base)->basetime))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "not a valid basetime");
	return NULL;
}

static struct command_result *param_recurrence_start_any_period(struct command *cmd,
								const char *name,
								const char *buffer,
								const jsmntok_t *tok,
								struct recurrence_base **base)
{
	bool *val;
	struct command_result *res = param_bool(cmd, name, buffer, tok, &val);
	if (res)
		return res;

	if (*val == false && !*base)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Cannot set to false without specifying recurrence_base!");
	(*base)->start_any_period = false;
	return NULL;
}

/* -time+time[%] */
static struct command_result *param_recurrence_paywindow(struct command *cmd,
							 const char *name,
							 const char *buffer,
							 const jsmntok_t *tok,
							 struct recurrence_paywindow
							 **paywindow)
{
	jsmntok_t t, before, after;

	*paywindow = tal(cmd, struct recurrence_paywindow);
	t = *tok;
	if (json_tok_endswith(buffer, &t, "%")) {
		(*paywindow)->proportional_amount = true;
		t.end--;
	} else
		(*paywindow)->proportional_amount = false;

	if (!json_tok_startswith(buffer, &t, "-"))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "expected -time+time[%]");
	t.start++;
	if (!split_tok(buffer, &t, '+', &before, &after))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "expected -time+time[%]");

	if (!json_to_u32(buffer, &before, &(*paywindow)->seconds_before))
		return command_fail_badparam(cmd, name, buffer, &before,
					     "expected number of seconds");
	if (!json_to_u32(buffer, &after, &(*paywindow)->seconds_after))
		return command_fail_badparam(cmd, name, buffer, &after,
					     "expected number of seconds");
	return NULL;
}

struct offer_info {
	struct tlv_offer *offer;
	const char *label;
	bool *single_use;
};

static struct command_result *check_result(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   void *arg UNNEEDED)
{
	bool active;

	/* If it's inactive, we can't return it, */
	if (!json_to_bool(buf, json_get_member(buf, result, "active"),
			  &active)) {
		return command_fail(cmd,
				    LIGHTNINGD,
				    "Bad createoffer/createinvoicerequest status reply %.*s",
				    json_tok_full_len(result),
				    json_tok_full(buf, result));
	}
	if (!active)
		return command_fail(cmd,
				    OFFER_ALREADY_EXISTS,
				    "Already exists, but isn't active");

	/* Otherwise, push through the result. */
	return forward_result(cmd, buf, result, arg);
}

static struct command_result *create_offer(struct command *cmd,
					   struct offer_info *offinfo)
{
	struct out_req *req;

	/* We simply pass this through. */
	req = jsonrpc_request_start(cmd, "createoffer",
				    check_result, forward_error,
				    offinfo);
	json_add_string(req->js, "bolt12",
			offer_encode(tmpctx, offinfo->offer));
	if (offinfo->label)
		json_add_string(req->js, "label", offinfo->label);
	json_add_bool(req->js, "single_use", *offinfo->single_use);

	return send_outreq(req);
}

static struct command_result *found_best_peer(struct command *cmd,
					      const struct chaninfo *best,
					      struct offer_info *offinfo)
{
	/* BOLT-offers #12:
	 *   - if it is connected only by private channels:
	 *     - MUST include `offer_paths` containing one or more paths to the node from
	 *       publicly reachable nodes.
	 */
	if (!best) {
		/* FIXME: Make this a warning in the result! */
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "No incoming channel to public peer, so no blinded path");
	} else {
		struct pubkey *ids;
		struct secret blinding_path_secret;
		struct sha256 offer_id;

		/* Note: "id" of offer minus paths */
		offer_offer_id(offinfo->offer, &offer_id);

		/* Make a small 1-hop path to us */
		ids = tal_arr(tmpctx, struct pubkey, 2);
		ids[0] = best->id;
		ids[1] = id;

		/* So we recognize this */
		/* We can check this when they try to take up offer. */
		bolt12_path_secret(&offerblinding_base, &offer_id,
				   &blinding_path_secret);

		offinfo->offer->offer_paths = tal_arr(offinfo->offer, struct blinded_path *, 1);
		offinfo->offer->offer_paths[0]
			= incoming_message_blinded_path(offinfo->offer->offer_paths,
							ids,
							NULL,
							&blinding_path_secret);
	}

	return create_offer(cmd, offinfo);
}

static struct command_result *maybe_add_path(struct command *cmd,
					     struct offer_info *offinfo)
{
	/* BOLT-offers #12:
	 *   - if it is connected only by private channels:
	 *     - MUST include `offer_paths` containing one or more paths to the node from
	 *       publicly reachable nodes.
	 */
	if (!offinfo->offer->offer_paths) {
		struct node_id local_nodeid;

		node_id_from_pubkey(&local_nodeid, &id);
		if (!gossmap_find_node(get_gossmap(cmd->plugin), &local_nodeid))
			return find_best_peer(cmd, OPT_ONION_MESSAGES,
					      found_best_peer, offinfo);
	}
	return create_offer(cmd, offinfo);
}

static struct command_result *currency_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct offer_info *offinfo)
{
	/* Fail in this case, by forwarding warnings. */
	if (!json_get_member(buf, result, "msat"))
		return forward_error(cmd, buf, result, offinfo);

	return maybe_add_path(cmd, offinfo);
}

static bool json_to_sciddir_or_pubkey(const char *buffer, const jsmntok_t *tok,
				      struct sciddir_or_pubkey *sciddir_or_pubkey)
{
	struct pubkey pk;
	struct short_channel_id_dir scidd;

	if (json_to_pubkey(buffer, tok, &pk)) {
		sciddir_or_pubkey_from_pubkey(sciddir_or_pubkey, &pk);
		return true;
	} else if (json_to_short_channel_id_dir(buffer, tok, &scidd)) {
		sciddir_or_pubkey_from_scidd(sciddir_or_pubkey, &scidd);
		return true;
	}

	return false;
}

struct path {
	/* Optional: a scid as the entry point */
	struct short_channel_id_dir *first_scidd;
	/* A node id for every element on the path */
	struct pubkey *path;
};

static struct command_result *param_paths(struct command *cmd, const char *name,
					  const char *buffer, const jsmntok_t *tok,
					  struct path ***paths)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "Must be array");

	*paths = tal_arr(cmd, struct path *, tok->size);
	json_for_each_arr(i, t, tok) {
		size_t j;
		const jsmntok_t *p;

		if (t->type != JSMN_ARRAY || t->size == 0) {
			return command_fail_badparam(cmd, name, buffer, t,
						     "Must be array of non-empty arrays");
		}

		(*paths)[i] = tal(*paths, struct path);
		(*paths)[i]->path = tal_arr((*paths)[i], struct pubkey, t->size);
		json_for_each_arr(j, p, t) {
			struct pubkey pk;
			if (j == 0) {
				struct sciddir_or_pubkey init;
				if (!json_to_sciddir_or_pubkey(buffer, p, &init)) {
					return command_fail_badparam(cmd, name, buffer, p,
								     "invalid pubkey/sciddir");
				}
				if (!init.is_pubkey) {
					(*paths)[i]->first_scidd = tal_dup((*paths)[i],
									  struct short_channel_id_dir,
									  &init.scidd);
					if (!gossmap_scidd_pubkey(get_gossmap(cmd->plugin), &init)) {
						return command_fail_badparam(cmd, name, buffer, p,
									     "unknown sciddir");
					}
				} else {
					(*paths)[i]->first_scidd = NULL;
				}
				pk = init.pubkey;
			} else {
				if (!json_to_pubkey(buffer, p, &pk)) {
					return command_fail_badparam(cmd, name, buffer, p,
								     "invalid pubkey");
				}
			}
			if (j == t->size - 1 && !pubkey_eq(&pk, &id))
				return command_fail_badparam(cmd, name, buffer, p,
							     "final pubkey must be this node");
			(*paths)[i]->path[j] = pk;
		}
	}
	return NULL;
}

struct command_result *json_offer(struct command *cmd,
				  const char *buffer,
				  const jsmntok_t *params)
{
	const char *desc, *issuer;
	struct tlv_offer *offer;
	struct offer_info *offinfo = tal(cmd, struct offer_info);
	struct path **paths;

	offinfo->offer = offer = tlv_offer_new(offinfo);

	if (!param(cmd, buffer, params,
		   p_req("amount", param_amount, offer),
		   p_opt("description", param_escaped_string, &desc),
		   p_opt("issuer", param_escaped_string, &issuer),
		   p_opt("label", param_escaped_string, &offinfo->label),
		   p_opt("quantity_max", param_u64, &offer->offer_quantity_max),
		   p_opt("absolute_expiry", param_u64, &offer->offer_absolute_expiry),
		   p_opt("recurrence", param_recurrence, &offer->offer_recurrence),
		   p_opt("recurrence_base",
			 param_recurrence_base,
			 &offer->offer_recurrence_base),
		   p_opt("recurrence_paywindow",
			 param_recurrence_paywindow,
			 &offer->offer_recurrence_paywindow),
		   p_opt("recurrence_limit",
			 param_number,
			 &offer->offer_recurrence_limit),
		   p_opt_def("single_use", param_bool,
			     &offinfo->single_use, false),
		   p_opt("recurrence_start_any_period",
			 param_recurrence_start_any_period,
			 &offer->offer_recurrence_base),
		   p_opt("dev_paths", param_paths, &paths),
		   NULL))
		return command_param_failed();

	if (!offers_enabled)
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-offers not enabled");

	/* Doesn't make sense to have max quantity 1. */
	if (offer->offer_quantity_max && *offer->offer_quantity_max == 1)
		return command_fail_badparam(cmd, "quantity_max",
					     buffer, params,
					     "must be 0 or > 1");
	/* BOLT-offers #12:
	 *
	 * - if the chain for the invoice is not solely bitcoin:
	 *   - MUST specify `offer_chains` the offer is valid for.
	 * - otherwise:
	 *   - MAY omit `offer_chains`, implying that bitcoin is only chain.
	 */
	if (!streq(chainparams->network_name, "bitcoin")) {
		offer->offer_chains = tal_arr(offer, struct bitcoin_blkid, 1);
		offer->offer_chains[0] = chainparams->genesis_blockhash;
	}

	if (!offer->offer_recurrence) {
		if (offer->offer_recurrence_limit)
			return command_fail_badparam(cmd, "recurrence_limit",
						     buffer, params,
						     "needs recurrence");
		if (offer->offer_recurrence_base)
			return command_fail_badparam(cmd, "recurrence_base",
						     buffer, params,
						     "needs recurrence");
		if (offer->offer_recurrence_paywindow)
			return command_fail_badparam(cmd, "recurrence_paywindow",
						     buffer, params,
						     "needs recurrence");
	}

	if (desc)
		offer->offer_description
			= tal_dup_arr(offer, char, desc, strlen(desc), 0);

	/* BOLT-offers #12:
	 *
	 * - if `offer_amount` is set and `offer_description` is not set:
	 *    - MUST NOT respond to the offer.
	 */
	if (!offer->offer_description && offer->offer_amount)
		return command_fail_badparam(cmd, "description", buffer, params,
					     "description is required for the user to know what it was they paid for");

	/* BOLT-offers #12:
	 * - if it sets `offer_issuer`:
	 *   - SHOULD set it to identify the issuer of the invoice clearly.
	 *   - if it includes a domain name:
	 *     - SHOULD begin it with either user@domain or domain
	 *     - MAY follow with a space and more text
	 */
	if (issuer) {
		offer->offer_issuer
			= tal_dup_arr(offer, char, issuer, strlen(issuer), 0);
	}

	/* BOLT-offers #12:
	 * - if it includes `offer_paths`:
	 *...
	 * - otherwise:
	 *   - MUST set `offer_issuer_id` to the node's public key to request the
	 *     invoice from.
	 */
	offer->offer_issuer_id = tal_dup(offer, struct pubkey, &id);

	/* Now rest of offer will not change: we use pathless offer to create secret. */
	if (paths) {
		struct secret blinding_path_secret;
		struct sha256 offer_id;
		/* Note: "id" of offer minus paths */
		offer_offer_id(offer, &offer_id);

		/* We can check this when they try to take up offer. */
		bolt12_path_secret(&offerblinding_base, &offer_id,
				   &blinding_path_secret);

		offer->offer_paths = tal_arr(offer, struct blinded_path *, tal_count(paths));
		for (size_t i = 0; i < tal_count(paths); i++) {
			offer->offer_paths[i] = incoming_message_blinded_path(offer->offer_paths,
									      paths[i]->path,
									      NULL,
									      &blinding_path_secret);
			/* Override entry point if they said to */
			if (paths[i]->first_scidd)
				sciddir_or_pubkey_from_scidd(&offer->offer_paths[i]->first_node_id,
							     paths[i]->first_scidd);
		}
	}

	/* If they specify a different currency, warn if we can't
	 * convert it! */
	if (offer->offer_currency) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd, "currencyconvert",
					    currency_done, forward_error,
					    offinfo);
		json_add_u32(req->js, "amount", 1);
		json_add_stringn(req->js, "currency",
				 (const char *)offer->offer_currency,
				 tal_bytelen(offer->offer_currency));
		return send_outreq(req);
	}

	return maybe_add_path(cmd, offinfo);
}

static struct command_result *call_createinvoicerequest(struct command *cmd,
							struct tlv_invoice_request *invreq,
							bool single_use,
							const char *label)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "createinvoicerequest",
				    check_result, forward_error,
				    invreq);
	json_add_string(req->js, "bolt12", invrequest_encode(tmpctx, invreq));
	json_add_bool(req->js, "savetodb", true);
	json_add_bool(req->js, "single_use", single_use);
	if (label)
		json_add_string(req->js, "recurrence_label", label);
	return send_outreq(req);
}

struct invrequest_data {
	struct tlv_invoice_request *invreq;
	bool single_use;
	const char *label;
};

static struct command_result *found_best_peer_invrequest(struct command *cmd,
							 const struct chaninfo *best,
							 struct invrequest_data *irdata)
{
	if (!best) {
		/* FIXME: Make this a warning in the result! */
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "No incoming channel to public peer, so no blinded path for invoice request");
	} else {
		struct pubkey *ids;
		struct secret blinding_path_secret;
		struct sha256 invreq_id;

		/* BOLT-offers #12:
		 *   - MUST set `invreq_paths` as it would set (or not set) `offer_paths` for an offer.
		 */
		/* BOLT-offers #12:
		 *
		 *   - if it is connected only by private channels:
		 *     - MUST include `offer_paths` containing one or more paths to the node from
		 *       publicly reachable nodes.
		 */
		/* Note: "id" of invreq minus paths (which we haven't added yet!) */
		invreq_invreq_id(irdata->invreq, &invreq_id);

		/* Make a small 1-hop path to us */
		ids = tal_arr(tmpctx, struct pubkey, 2);
		ids[0] = best->id;
		ids[1] = id;

		/* So we recognize this */
		/* We can check this when they try to take up invoice_request. */
		bolt12_path_secret(&offerblinding_base, &invreq_id,
				   &blinding_path_secret);

		plugin_log(cmd->plugin, LOG_DBG,
			   "Setting blinided path (invreq_id = %s, path_secret = %s)",
			   fmt_sha256(tmpctx, &invreq_id),
			   fmt_secret(tmpctx, &blinding_path_secret));
		irdata->invreq->invreq_paths = tal_arr(irdata->invreq, struct blinded_path *, 1);
		irdata->invreq->invreq_paths[0]
			= incoming_message_blinded_path(irdata->invreq->invreq_paths,
							ids,
							NULL,
							&blinding_path_secret);
	}

	return call_createinvoicerequest(cmd,
					 irdata->invreq, irdata->single_use, irdata->label);
}

struct command_result *json_invoicerequest(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *params)
{
	const char *desc, *issuer, *label;
	struct tlv_invoice_request *invreq;
	struct amount_msat *msat;
	bool *single_use;
	struct node_id local_nodeid;

	invreq = tlv_invoice_request_new(cmd);

	if (!param(cmd, buffer, params,
		   p_req("amount", param_msat, &msat),
		   p_opt("description", param_escaped_string, &desc),
		   p_opt("issuer", param_escaped_string, &issuer),
		   p_opt("label", param_escaped_string, &label),
		   p_opt("absolute_expiry", param_u64,
			 &invreq->offer_absolute_expiry),
		   p_opt_def("single_use", param_bool, &single_use, true),
		   NULL))
		return command_param_failed();

	if (!offers_enabled)
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-offers not enabled");

	/* BOLT-offers #12:
	 * - otherwise (not responding to an offer):
	 *   - MUST set `offer_description` to a complete description of the purpose of the payment.
	 *   - MUST set (or not set) `offer_absolute_expiry` and `offer_issuer` as it would for an offer.
	 *   - MUST set `invreq_payer_id` (as it would set `offer_issuer_id` for an offer).
	 *   - MUST set `invreq_paths` as it would set (or not set) `offer_paths` for an offer.
	 *   - MUST NOT include `signature`, `offer_metadata`, `offer_chains`, `offer_amount`, `offer_currency`, `offer_features`, `offer_quantity_max`, `offer_paths` or `offer_issuer_id`
	 *   - if the chain for the invoice is not solely bitcoin:
	 *     - MUST specify `invreq_chain` the offer is valid for.
	 *     - MUST set `invreq_amount`.
	 */
	if (desc)
		invreq->offer_description = tal_dup_arr(invreq, char, desc, strlen(desc), 0);
	else
		invreq->offer_description = NULL;

	if (issuer) {
		invreq->offer_issuer
			= tal_dup_arr(invreq, char, issuer, strlen(issuer), 0);
	}

	if (!streq(chainparams->network_name, "bitcoin")) {
		invreq->invreq_chain
			= tal_dup(invreq, struct bitcoin_blkid,
				  &chainparams->genesis_blockhash);
	}
	/* BOLT-offers #12:
	 * - if it sets `invreq_amount`:
	 *   - MUST set `msat` in multiples of the minimum lightning-payable unit
	 *       (e.g. milli-satoshis for bitcoin) for `invreq_chain` (or for bitcoin, if there is no `invreq_chain`).
	 */
	invreq->invreq_amount
		= tal_dup(invreq, u64, &msat->millisatoshis); /* Raw: wire */

	/* BOLT-offers #12:
	 * - MUST set `invreq_metadata` to an unpredictable series of bytes.
	 */
	invreq->invreq_metadata = tal_arr(invreq, u8, 16);
	randombytes_buf(invreq->invreq_metadata,
			tal_bytelen(invreq->invreq_metadata));

	/* BOLT-offers #12:
	 * - otherwise (not responding to an offer):
	 *...
	 *   - MUST set `invreq_payer_id` (as it would set `offer_issuer_id` for an offer).
	 */
	/* FIXME: Allow invoicerequests using aliases! */
	invreq->invreq_payer_id = tal_dup(invreq, struct pubkey, &id);

	/* BOLT-offers #12:
	 * - if it supports bolt12 invoice request features:
	 *   - MUST set `invreq_features`.`features` to the bitmap of features.
	 */

	/* FIXME: We only set blinded path if private, we should allow
	 * setting otherwise! */
	node_id_from_pubkey(&local_nodeid, &id);
	if (!gossmap_find_node(get_gossmap(cmd->plugin), &local_nodeid)) {
		struct invrequest_data *idata = tal(cmd, struct invrequest_data);
		idata->invreq = invreq;
		idata->single_use = *single_use;
		idata->label = label;
		return find_best_peer(cmd, OPT_ONION_MESSAGES,
				      found_best_peer_invrequest, idata);
	}

	return call_createinvoicerequest(cmd, invreq, *single_use, label);
}

