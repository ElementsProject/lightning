#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12.h>
#include <common/iso4217.h>
#include <common/json_tok.h>
#include <common/overflows.h>
#include <plugins/offers_offer.h>

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

	offer->amount = tal_dup(offer, u64,
				&msat.millisatoshis); /* Raw: other currencies */
	return true;
}

static struct command_result *param_msat_or_any(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct tlv_offer *offer)
{
	if (msat_or_any(buffer, tok, offer))
		return NULL;
	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be 'any' or msatoshis");
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

	offer->amount = tal(offer, u64);

	/* BOLT-offers #12:
	 *
	 * - MUST specify `iso4217` as an ISO 4712 three-letter code.
	 * - MUST specify `amount` in the currency unit adjusted by the ISO 4712
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

	offer->currency
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

	if (!json_to_u64(buffer, &whole, offer->amount))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be 'any', msatoshis or <ISO-4712><amount>[.<amount>]");

	for (size_t i = 0; i < isocode->minor_unit; i++) {
		if (mul_overflows_u64(*offer->amount, 10))
			return command_fail_badparam(cmd, name, buffer,
						     &whole,
						     "excessively large value");
		*offer->amount *= 10;
	}

	*offer->amount += cents;
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
					       struct tlv_offer_recurrence
					       **recurrence)
{
	u32 mul;
	const struct time_string *ts;

	ts = json_to_time(buffer, tok, &mul);
	if (!ts)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "not a valid time");

	*recurrence = tal(cmd, struct tlv_offer_recurrence);
	(*recurrence)->time_unit = ts->unit;
	(*recurrence)->period = ts->mul * mul;
	return NULL;
}

static struct command_result *param_recurrence_base(struct command *cmd,
						    const char *name,
						    const char *buffer,
						    const jsmntok_t *tok,
						    struct tlv_offer_recurrence_base **base)
{
	/* Make copy so we can manipulate it */
	jsmntok_t t = *tok;

	*base = tal(cmd, struct tlv_offer_recurrence_base);
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
							 struct tlv_offer_recurrence_paywindow
							 **paywindow)
{
	jsmntok_t t, before, after;

	*paywindow = tal(cmd, struct tlv_offer_recurrence_paywindow);
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

static struct command_result *param_invoice_payment_hash(struct command *cmd,
							 const char *name,
							 const char *buffer,
							 const jsmntok_t *tok,
							 struct sha256 **hash)
{
	struct tlv_invoice *inv;
	char *fail;

	inv = invoice_decode(tmpctx, buffer + tok->start, tok->end - tok->start,
			     plugin_feature_set(cmd->plugin), chainparams,
			     &fail);
	if (!inv)
		return command_fail_badparam(cmd, name, buffer, tok,
					     tal_fmt(cmd,
						     "Unparsable invoice: %s",
						     fail));

	if (!inv->payment_hash)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "invoice missing payment_hash");

	*hash = tal_steal(cmd, inv->payment_hash);
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
				    "Bad creaoffer status reply %.*s",
				    json_tok_full_len(result),
				    json_tok_full(buf, result));
	}
	if (!active)
		return command_fail(cmd,
				    OFFER_ALREADY_EXISTS,
				    "Offer already exists, but isn't active");

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

	/* "issuer" used to be called "vendor" */
	if (deprecated_apis
	    && params
	    && params->type == JSMN_OBJECT
	    && json_get_member(buffer, params, "vendor")) {
		if (!param(cmd, buffer, params,
			   p_req("amount", param_amount, offer),
			   p_req("description", param_escaped_string, &desc),
			   p_opt("vendor", param_escaped_string, &issuer),
			   p_opt("label", param_escaped_string, &offinfo->label),
			   p_opt("quantity_min", param_u64, &offer->quantity_min),
			   p_opt("quantity_max", param_u64, &offer->quantity_max),
			   p_opt("absolute_expiry", param_u64, &offer->absolute_expiry),
			   p_opt("recurrence", param_recurrence, &offer->recurrence),
			   p_opt("recurrence_base",
				 param_recurrence_base,
				 &offer->recurrence_base),
			   p_opt("recurrence_paywindow",
				 param_recurrence_paywindow,
				 &offer->recurrence_paywindow),
			   p_opt("recurrence_limit",
				 param_number,
				 &offer->recurrence_limit),
			   p_opt_def("single_use", param_bool,
				     &offinfo->single_use, false),
			   NULL))
			return command_param_failed();
		goto after_params;
	}

	if (!param(cmd, buffer, params,
		   p_req("amount", param_amount, offer),
		   p_req("description", param_escaped_string, &desc),
		   p_opt("issuer", param_escaped_string, &issuer),
		   p_opt("label", param_escaped_string, &offinfo->label),
		   p_opt("quantity_min", param_u64, &offer->quantity_min),
		   p_opt("quantity_max", param_u64, &offer->quantity_max),
		   p_opt("absolute_expiry", param_u64, &offer->absolute_expiry),
		   p_opt("recurrence", param_recurrence, &offer->recurrence),
		   p_opt("recurrence_base",
			 param_recurrence_base,
			 &offer->recurrence_base),
		   p_opt("recurrence_paywindow",
			 param_recurrence_paywindow,
			 &offer->recurrence_paywindow),
		   p_opt("recurrence_limit",
			 param_number,
			 &offer->recurrence_limit),
		   p_opt_def("single_use", param_bool,
			     &offinfo->single_use, false),
		   /* FIXME: hints support! */
		   NULL))
		return command_param_failed();

after_params:
	if (!offers_enabled)
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-offers not enabled");

	/* BOLT-offers #12:
	 * - MUST NOT set `quantity_min` or `quantity_max` less than 1.
	 */
	if (offer->quantity_min && *offer->quantity_min < 1)
		return command_fail_badparam(cmd, "quantity_min",
					     buffer, params,
					     "must be >= 1");
	if (offer->quantity_max && *offer->quantity_max < 1)
		return command_fail_badparam(cmd, "quantity_max",
					     buffer, params,
					     "must be >= 1");
	/* BOLT-offers #12:
	 * - if both:
	 *    - MUST set `quantity_min` less than or equal to `quantity_max`.
	 */
	if (offer->quantity_min && offer->quantity_max) {
		if (*offer->quantity_min > *offer->quantity_max)
			return command_fail_badparam(cmd, "quantity_min",
						     buffer, params,
						     "must be <= quantity_max");
	}

	/* BOLT-offers #12:
	 *
	 * - if the chain for the invoice is not solely bitcoin:
	 *   - MUST specify `chains` the offer is valid for.
	 * - otherwise:
	 *   - the bitcoin chain is implied as the first and only entry.
	 */
	if (!streq(chainparams->network_name, "bitcoin")) {
		offer->chains = tal_arr(offer, struct bitcoin_blkid, 1);
		offer->chains[0] = chainparams->genesis_blockhash;
	}

	if (!offer->recurrence) {
		if (offer->recurrence_limit)
			return command_fail_badparam(cmd, "recurrence_limit",
						     buffer, params,
						     "needs recurrence");
		if (offer->recurrence_base)
			return command_fail_badparam(cmd, "recurrence_base",
						     buffer, params,
						     "needs recurrence");
		if (offer->recurrence_paywindow)
			return command_fail_badparam(cmd, "recurrence_paywindow",
						     buffer, params,
						     "needs recurrence");
	}

	offer->description = tal_dup_arr(offer, char, desc, strlen(desc), 0);
	if (issuer) {
		offer->issuer
			= tal_dup_arr(offer, char, issuer, strlen(issuer), 0);
	}

	offer->node_id = tal_dup(offer, struct point32, &id);

	/* If they specify a different currency, warn if we can't
	 * convert it! */
	if (offer->currency) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd->plugin, cmd, "currencyconvert",
					    currency_done, forward_error,
					    offinfo);
		json_add_u32(req->js, "amount", 1);
		json_add_stringn(req->js, "currency",
				 (const char *)offer->currency,
				 tal_bytelen(offer->currency));
		return send_outreq(cmd->plugin, req);
	}

	return create_offer(cmd, offinfo);
}

struct command_result *json_offerout(struct command *cmd,
				     const char *buffer,
				     const jsmntok_t *params)
{
	const char *desc, *issuer, *label;
	struct tlv_offer *offer;
	struct out_req *req;

	offer = tlv_offer_new(cmd);

	/* "issuer" used to be called "vendor" */
	if (deprecated_apis
	    && params
	    && params->type == JSMN_OBJECT
	    && json_get_member(buffer, params, "vendor")) {
		if (!param(cmd, buffer, params,
			   p_req("amount", param_msat_or_any, offer),
			   p_req("description", param_escaped_string, &desc),
			   p_opt("vendor", param_escaped_string, &issuer),
			   p_opt("label", param_escaped_string, &label),
			   p_opt("absolute_expiry", param_u64, &offer->absolute_expiry),
			   p_opt("refund_for", param_invoice_payment_hash, &offer->refund_for),
			   /* FIXME: hints support! */
			   NULL))
			return command_param_failed();
		goto after_params;
	}

	if (!param(cmd, buffer, params,
		   p_req("amount", param_msat_or_any, offer),
		   p_req("description", param_escaped_string, &desc),
		   p_opt("issuer", param_escaped_string, &issuer),
		   p_opt("label", param_escaped_string, &label),
		   p_opt("absolute_expiry", param_u64, &offer->absolute_expiry),
		   p_opt("refund_for", param_invoice_payment_hash, &offer->refund_for),
		   /* FIXME: hints support! */
		   NULL))
		return command_param_failed();

after_params:
	if (!offers_enabled)
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-offers not enabled");

	offer->send_invoice = tal(offer, struct tlv_offer_send_invoice);

	/* BOLT-offers #12:
	 *
	 * - if the chain for the invoice is not solely bitcoin:
	 *   - MUST specify `chains` the offer is valid for.
	 * - otherwise:
	 *   - the bitcoin chain is implied as the first and only entry.
	 */
	if (!streq(chainparams->network_name, "bitcoin")) {
		offer->chains = tal_arr(offer, struct bitcoin_blkid, 1);
		offer->chains[0] = chainparams->genesis_blockhash;
	}

	offer->description = tal_dup_arr(offer, char, desc, strlen(desc), 0);
	if (issuer)
		offer->issuer = tal_dup_arr(offer, char,
					    issuer, strlen(issuer), 0);

	offer->node_id = tal_dup(offer, struct point32, &id);

	req = jsonrpc_request_start(cmd->plugin, cmd, "createoffer",
				    check_result, forward_error,
				    offer);
	json_add_string(req->js, "bolt12", offer_encode(tmpctx, offer));
	if (label)
		json_add_string(req->js, "label", label);
	json_add_bool(req->js, "single_use", true);

	return send_outreq(cmd->plugin, req);
}

