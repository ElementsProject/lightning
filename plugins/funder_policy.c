#include "config.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/lease_rates.h>
#include <common/pseudorand.h>
#include <inttypes.h>
#include <plugins/funder_policy.h>

const char *funder_opt_name(enum funder_opt opt)
{
	switch (opt) {
	case MATCH:
		return "match";
	case AVAILABLE:
		return "available";
	case FIXED:
		return "fixed";
	}
	abort();
}

char *funding_option(struct plugin *plugin, const char *arg, bool check_only, enum funder_opt *opt)
{
	enum funder_opt v;
	if (streq(arg, "match"))
		v = MATCH;
	else if (streq(arg, "available"))
		v = AVAILABLE;
	else if (streq(arg, "fixed"))
		v = FIXED;
	else
		return tal_fmt(tmpctx, "'%s' is not a valid option"
			       " (match, available, fixed)",
			       arg);

	if (!check_only)
		*opt = v;
	return NULL;
}

bool jsonfmt_funding_option(struct plugin *plugin,
			    struct json_stream *js,
			    const char *fieldname,
			    enum funder_opt *opt)
{
	json_add_string(js, fieldname, funder_opt_name(*opt));
	return true;
}

const char *funder_policy_desc(const tal_t *ctx,
			       const struct funder_policy *policy)
{
	if (policy->opt == FIXED) {
		struct amount_sat amt = amount_sat(policy->mod);
		return tal_fmt(ctx, "%s (%s)",
			       funder_opt_name(policy->opt),
			       fmt_amount_sat(ctx, amt));
	} else
		return tal_fmt(ctx, "%s (%"PRIu64"%%)",
			       funder_opt_name(policy->opt), policy->mod);

	/* FIXME: add in more info? */
}

static struct funder_policy *
new_funder_policy(const tal_t *ctx,
		  enum funder_opt opt,
		  u64 policy_mod,
		  struct amount_sat min_their_funding,
		  struct amount_sat max_their_funding,
		  struct amount_sat per_channel_min,
		  struct amount_sat per_channel_max,
		  u32 fuzz_factor,
		  struct amount_sat reserve_tank,
		  u32 fund_probability,
		  bool leases_only,
		  struct lease_rates *rates)
{
	struct funder_policy *policy = tal(ctx, struct funder_policy);

	policy->opt = opt;
	policy->mod = policy_mod;
	policy->min_their_funding = min_their_funding;
	policy->max_their_funding = max_their_funding;
	policy->per_channel_min = per_channel_min;
	policy->per_channel_max = per_channel_max;
	policy->fuzz_factor = fuzz_factor;
	policy->reserve_tank = reserve_tank;
	policy->fund_probability = fund_probability;
	policy->leases_only = leases_only;
	policy->rates = rates;

	return policy;
}

struct funder_policy *
default_funder_policy(const tal_t *ctx,
		      enum funder_opt policy,
		      u64 policy_mod)
{
	return new_funder_policy(ctx, policy, policy_mod,
				 AMOUNT_SAT(10000),
				 AMOUNT_SAT(UINT_MAX),
				 AMOUNT_SAT(10000),
				 AMOUNT_SAT(UINT_MAX),
				 0, 		/* fuzz_factor */
				 AMOUNT_SAT(0), /* reserve_tank */
				 100,
				 true, /* Leases-only by default */
				 NULL);
}

struct lease_rates *
default_lease_rates(const tal_t *ctx)
{
	struct lease_rates *rates = tal(ctx, struct lease_rates);

	/* Default basis is .65%, (7.8% APR) */
	rates->lease_fee_basis = 65;
	/* 2000sat base rate */
	rates->lease_fee_base_sat = 2000;
	/* Max of 100,000ppm (10%) */
	rates->channel_fee_max_proportional_thousandths = 100;
	/* Max of 5000sat */
	rates->channel_fee_max_base_msat = 5000000;

	/* Let's set our default max weight to two inputs + an output
	 * (use helpers b/c elements) */
	rates->funding_weight
		= 2 * bitcoin_tx_simple_input_weight(false)
		+ bitcoin_tx_output_weight(BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN);

	return rates;
}

char *funder_check_policy(const struct funder_policy *policy)
{
	if (policy->fund_probability > 100)
		return "fund_probability max is 100";

	if (policy->fuzz_factor > 100)
		return "fuzz_percent max is 100";

	switch (policy->opt) {
	case FIXED:
		/* We don't do anything for fixed */
		return NULL;
	case MATCH:
		if (policy->mod > 200)
			return "Max allowed policy_mod for 'match'"
			       " is 200";
		return NULL;
	case AVAILABLE:
		if (policy->mod > 100)
			return "Max allowed policy_mod for 'available'"
			       " is 100";
		return NULL;
	}
	abort();
}

static struct amount_sat
apply_fuzz(u32 fuzz_factor, struct amount_sat val)
{
	s32 fuzz_percent;
	s64 fuzz;
	bool ok;
	/* Don't even deal with stupid numbers. */
	if ((s64)val.satoshis < 0) /* Raw: val check */
		return AMOUNT_SAT(0);

	fuzz_percent = pseudorand((fuzz_factor * 2) + 1) - fuzz_factor;
	fuzz = (s64)val.satoshis * fuzz_percent / 100; /* Raw: fuzzing */
	if (fuzz > 0)
		ok = amount_sat_add(&val, val, amount_sat(fuzz));
	else
		ok = amount_sat_sub(&val, val, amount_sat(fuzz * -1));

	assert(ok);
	return val;
}

static struct amount_sat
apply_policy(struct funder_policy *policy,
	     struct amount_sat their_funding,
	     struct amount_sat requested_lease,
	     struct amount_sat available_funds)
{
	struct amount_sat our_funding;

	switch (policy->opt) {
	case MATCH:
		/* For matches, we use requested funding, if availalbe */
		if (!amount_sat_is_zero(requested_lease))
			their_funding = requested_lease;

		/* if this fails, it implies ludicrous funding offer, *and*
		 * > 100% match. Just Say No, kids. */
		if (!amount_sat_scale(&our_funding, their_funding,
				      policy->mod / 100.0))
			our_funding = AMOUNT_SAT(0);
		return our_funding;
	case AVAILABLE:
		/* Use the 'available_funds' as the starting
		 * point for your contribution */
		if (!amount_sat_scale(&our_funding, available_funds,
				      policy->mod / 100.0))
			abort();
		return our_funding;
	case FIXED:
		/* Use a static amount */
		return amount_sat(policy->mod);
	}

	abort();
}

const char *
calculate_our_funding(struct funder_policy *policy,
		      struct node_id id,
		      struct amount_sat their_funding,
		      struct amount_sat *our_last_funding,
		      struct amount_sat available_funds,
		      struct amount_sat channel_max,
		      struct amount_sat requested_lease,
		      struct amount_sat *our_funding)
{
	struct amount_sat avail_channel_space, net_available_funds;

	/* Are we only funding lease requests ? */
	if (policy->leases_only && amount_sat_is_zero(requested_lease)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx,
			       "Skipping funding open; leases-only=true"
			       " and this open isn't asking for a lease");
	}

	/* Are we skipping this one? */
	if (pseudorand(100) >= policy->fund_probability
	    /* We don't skip lease requests */
	    && amount_sat_is_zero(requested_lease)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx,
			       "Skipping, failed fund_probability test");
	}

	/* Figure out amount of actual headroom we have */
	if (!amount_sat_sub(&avail_channel_space, channel_max, their_funding)
	    || amount_sat_is_zero(avail_channel_space)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "No space available in channel."
			       " channel_max %s, their_funding %s",
			       fmt_amount_sat(tmpctx, channel_max),
			       fmt_amount_sat(tmpctx, their_funding));
	}

	/* Figure out actual available funds, given our requested
	 * 'reserve_tank' */
	if (!amount_sat_sub(&net_available_funds, available_funds,
			    policy->reserve_tank)
	    || amount_sat_is_zero(net_available_funds)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Reserve tank too low."
			       " available_funds %s, reserve_tank requires %s",
			       fmt_amount_sat(tmpctx, available_funds),
			       fmt_amount_sat(tmpctx, policy->reserve_tank));
	}

	/* Are they funding enough ? */
	if (amount_sat_less(their_funding, policy->min_their_funding)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Peer's funding too little."
			       " their_funding %s,"
			       " min_their_funding requires %s",
			       fmt_amount_sat(tmpctx, their_funding),
			       fmt_amount_sat(tmpctx, policy->min_their_funding));
	}

	/* Are they funding too much ? */
	if (amount_sat_greater(their_funding, policy->max_their_funding)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Peer's funding too much."
			       " their_funding %s,"
			       " max_their_funding requires %s",
			       fmt_amount_sat(tmpctx, their_funding),
			       fmt_amount_sat(tmpctx, policy->max_their_funding));
	}

	/* What's our amount, given our policy */
	*our_funding = apply_policy(policy,
				    their_funding,
				    requested_lease,
				    available_funds);

	/* Don't return an 'error' if we're already at 0 */
	if (amount_sat_is_zero(*our_funding))
		return NULL;

	/* our_funding is probably sane, so let's fuzz this amount a bit */
	*our_funding = apply_fuzz(policy->fuzz_factor, *our_funding);

	/* Is our_funding more than we can fit? if so set to avail space */
	if (amount_sat_greater(*our_funding, avail_channel_space))
		*our_funding = avail_channel_space;

	/* Is our_funding more than we want to fund in a channel?
	 * if so set at our desired per-channel max */
	if (amount_sat_greater(*our_funding, policy->per_channel_max))
		*our_funding = policy->per_channel_max;

	/* Is our_funding more than we have available? if so
	 * set to max available */
	if (amount_sat_greater(*our_funding, net_available_funds))
		*our_funding = net_available_funds;

	/* Are we putting in less than last time + it's a lease?
	 * Return an error as a convenience to the buyer */
	if (our_last_funding && !amount_sat_is_zero(requested_lease)) {
		if (amount_sat_less(*our_funding, *our_last_funding)
		    && amount_sat_less(*our_funding, requested_lease)) {
			return tal_fmt(tmpctx, "New amount (%s) is less than"
				       " last (%s); peer requested a lease (%s)",
				       fmt_amount_sat(tmpctx, *our_funding),
				       fmt_amount_sat(tmpctx,
						      *our_last_funding),
				       fmt_amount_sat(tmpctx, requested_lease));
		}
	}

	/* Is our_funding less than our per-channel minimum?
	 * if so, don't fund */
	if (amount_sat_less(*our_funding, policy->per_channel_min)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Can't meet our min channel requirement."
			       " our_funding %s,"
			       " per_channel_min requires %s",
			       fmt_amount_sat(tmpctx, *our_funding),
			       fmt_amount_sat(tmpctx, policy->per_channel_min));
	}

	return NULL;
}
