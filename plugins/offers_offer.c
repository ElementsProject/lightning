#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <common/bolt12.h>
#include <common/iso4217.h>
#include <common/json_stream.h>
#include <common/overflows.h>
#include <plugins/offers_offer.h>
#include <wire/onion_wire.h>

static struct command_result *param_amount(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   struct tlv_offer *offer)
{
	struct amount_msat msat;
	const struct iso4217_name_and_divisor *isocode;
	jsmntok_t number, whole, frac;
	u64 cents;

	if (json_tok_streq(buffer, tok, "any"))
		return NULL;

	offer->amount = tal(offer, u64);
	if (parse_amount_msat(&msat, buffer + tok->start, tok->end - tok->start)) {
		*offer->amount = msat.millisatoshis; /* Raw: other currencies */
		return NULL;
	}

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

struct command_result *json_offer(struct command *cmd,
				  const char *buffer,
				  const jsmntok_t *params)
{
	const char *desc, *vendor, *label;
	struct tlv_offer *offer;
	struct out_req *req;
	bool *single_use, *send_invoice;

	offer = tlv_offer_new(cmd);

	if (!param(cmd, buffer, params,
		   p_req("amount", param_amount, offer),
		   p_req("description", param_escaped_string, &desc),
		   p_opt("send_invoice", param_bool, &send_invoice),
		   p_opt("label", param_escaped_string, &label),
		   p_opt("vendor", param_escaped_string, &vendor),
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
		   p_opt("refund_for", param_invoice_payment_hash, &offer->refund_for),
		   p_opt("single_use", param_bool, &single_use),
		   /* FIXME: hints support! */
		   NULL))
		return command_param_failed();

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

	/* If refund_for, send_invoice is true. */
	if (offer->refund_for) {
		if (!send_invoice) {
			send_invoice = tal(cmd, bool);
			*send_invoice = true;
		}
		if (!*send_invoice)
			return command_fail_badparam(cmd, "refund_for",
						     buffer, params,
						     "needs send_invoice=true");
	} else {
		if (!send_invoice) {
			send_invoice = tal(cmd, bool);
			*send_invoice = false;
		}
	}

	if (*send_invoice)
		offer->send_invoice = tal(offer, struct tlv_offer_send_invoice);

	/* single_use defaults to 'true' for send_invoices, false otherwise */
	if (!single_use) {
		single_use = tal(cmd, bool);
		*single_use = offer->send_invoice ? true : false;
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
	if (vendor) {
		offer->vendor
			= tal_dup_arr(offer, char, vendor, strlen(vendor), 0);
	}

	offer->node_id = tal_dup(offer, struct pubkey32, &id);

	/* We simply pass this through. */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createoffer",
				    forward_result, forward_error,
				    offer);
	json_add_string(req->js, "bolt12", offer_encode(tmpctx, offer));
	if (label)
		json_add_string(req->js, "label", label);
	json_add_bool(req->js, "single_use", *single_use);

	return send_outreq(cmd->plugin, req);
}

