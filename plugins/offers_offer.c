#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12.h>
#include <common/iso4217.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/overflows.h>
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
	/* Make copy so we can manipulate it */
	jsmntok_t t = *tok;

	*base = tal(cmd, struct recurrence_base);
	if (json_tok_startswith(buffer, &t, "@")) {
		t.start++;
		(*base)->start_any_period = false;
	} else
		(*base)->start_any_period = true;

	if (!json_to_u64(buffer, &t, &(*base)->basetime))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "not a valid basetime or @basetime");
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
	const struct tlv_offer *offer;
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
	req = jsonrpc_request_start(cmd->plugin, cmd, "createoffer",
				    check_result, forward_error,
				    offinfo);
	json_add_string(req->js, "bolt12",
			offer_encode(tmpctx, offinfo->offer));
	if (offinfo->label)
		json_add_string(req->js, "label", offinfo->label);
	json_add_bool(req->js, "single_use", *offinfo->single_use);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *currency_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct offer_info *offinfo)
{
	/* Fail in this case, by forwarding warnings. */
	if (!json_get_member(buf, result, "msat"))
		return forward_error(cmd, buf, result, offinfo);

	return create_offer(cmd, offinfo);
}

struct command_result *json_offer(struct command *cmd,
				  const char *buffer,
				  const jsmntok_t *params)
{
	const char *desc, *issuer;
	struct tlv_offer *offer;
	struct offer_info *offinfo = tal(cmd, struct offer_info);

	offinfo->offer = offer = tlv_offer_new(offinfo);

	if (!param(cmd, buffer, params,
		   p_req("amount", param_amount, offer),
		   p_req("description", param_escaped_string, &desc),
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
		   /* FIXME: hints support! */
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

	/* BOLT-offers #12:
	 * - MUST set `offer_description` to a complete description of the
	 *   purpose of the payment.
	 */
	offer->offer_description
		= tal_dup_arr(offer, char, desc, strlen(desc), 0);

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
	 * - MUST set `offer_node_id` to the node's public key to request the
	 *   invoice from.
	 */
	offer->offer_node_id = tal_dup(offer, struct pubkey, &id);

	/* If they specify a different currency, warn if we can't
	 * convert it! */
	if (offer->offer_currency) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd->plugin, cmd, "currencyconvert",
					    currency_done, forward_error,
					    offinfo);
		json_add_u32(req->js, "amount", 1);
		json_add_stringn(req->js, "currency",
				 (const char *)offer->offer_currency,
				 tal_bytelen(offer->offer_currency));
		return send_outreq(cmd->plugin, req);
	}

	return create_offer(cmd, offinfo);
}

struct command_result *json_invoicerequest(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *params)
{
	const char *desc, *issuer, *label;
	struct tlv_invoice_request *invreq;
	struct out_req *req;
	struct amount_msat *msat;
	bool *single_use;

	invreq = tlv_invoice_request_new(cmd);

	if (!param(cmd, buffer, params,
		   p_req("amount", param_msat, &msat),
		   p_req("description", param_escaped_string, &desc),
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
	 *   - MUST set (or not set) `offer_metadata`, `offer_description`, `offer_absolute_expiry`, `offer_paths` and `offer_issuer` as it would for an offer.
	 *   - MUST set `invreq_payer_id` as it would set `offer_node_id` for an offer.
	 *   - MUST NOT include `signature`, `offer_chains`, `offer_amount`, `offer_currency`, `offer_features`, `offer_quantity_max` or `offer_node_id`
	 *   - if the chain for the invoice is not solely bitcoin:
	 *     - MUST specify `invreq_chain` the offer is valid for.
	 *   - MUST set `invreq_amount`.
	 */
	invreq->offer_description
		= tal_dup_arr(invreq, char, desc, strlen(desc), 0);
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

	/* FIXME: enable blinded paths! */

	/* BOLT-offers #12:
	 * - MUST set `invreq_metadata` to an unpredictable series of bytes.
	 */
	/* BOLT-offers #12:
	 * - otherwise (not responding to an offer):
	 *...
	 *   - MUST set `invreq_payer_id` as it would set `offer_node_id` for an offer.
	 */
	/* createinvoicerequest sets these! */

	/* BOLT-offers #12:
	 * - if it supports bolt12 invoice request features:
	 *   - MUST set `invreq_features`.`features` to the bitmap of features.
	 */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoicerequest",
				    check_result, forward_error,
				    invreq);
	json_add_string(req->js, "bolt12", invrequest_encode(tmpctx, invreq));
	json_add_bool(req->js, "savetodb", true);
	/* FIXME: Allow invoicerequests using aliases! */
	json_add_bool(req->js, "exposeid", true);
	json_add_bool(req->js, "single_use", *single_use);
	if (label)
		json_add_string(req->js, "label", label);
	return send_outreq(cmd->plugin, req);
}

