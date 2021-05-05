#include <assert.h>
#include <ccan/tal/str/str.h>
#include <common/node_id.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
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

char *funding_option(const char *arg, enum funder_opt *opt)
{
	if (streq(arg, "match"))
		*opt = MATCH;
	else if (streq(arg, "available"))
		*opt = AVAILABLE;
	else if (streq(arg, "fixed"))
		*opt = FIXED;
	else
		return tal_fmt(NULL, "'%s' is not a valid option"
			       " (match, available, fixed)",
			       arg);
	return NULL;
}

const char *funder_policy_desc(const tal_t *ctx,
			       struct funder_policy policy)
{
	if (policy.opt == FIXED) {
		struct amount_sat amt = amount_sat(policy.mod);
		return tal_fmt(ctx, "%s (%s)",
			       funder_opt_name(policy.opt),
			       type_to_string(ctx, struct amount_sat, &amt));
	} else
		return tal_fmt(ctx, "%s (%"PRIu64"%%)",
			       funder_opt_name(policy.opt), policy.mod);

	/* FIXME: add in more info? */
}

struct funder_policy
new_funder_policy(enum funder_opt opt,
		  u64 policy_mod,
		  struct amount_sat min_their_funding,
		  struct amount_sat max_their_funding,
		  struct amount_sat per_channel_min,
		  struct amount_sat per_channel_max,
		  u32 fuzz_factor,
		  struct amount_sat reserve_tank,
		  u32 fund_probability)
{
	struct funder_policy policy;

	policy.opt = opt;
	policy.mod = policy_mod;
	policy.min_their_funding = min_their_funding;
	policy.max_their_funding = max_their_funding;
	policy.per_channel_min = per_channel_min;
	policy.per_channel_max = per_channel_max;
	policy.fuzz_factor = fuzz_factor;
	policy.reserve_tank = reserve_tank;
	policy.fund_probability = fund_probability;

	return policy;
}

struct funder_policy
default_funder_policy(enum funder_opt policy,
		      u64 policy_mod)
{
	return new_funder_policy(policy, policy_mod,
				 AMOUNT_SAT(10000),
				 AMOUNT_SAT(UINT_MAX),
				 AMOUNT_SAT(10000),
				 AMOUNT_SAT(UINT_MAX),
				 5, 		/* fuzz_factor */
				 AMOUNT_SAT(0), /* reserve_tank */
				 100);
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
apply_policy(struct funder_policy policy,
	     struct amount_sat their_funding,
	     struct amount_sat available_funds)
{
	struct amount_sat our_funding;

	switch (policy.opt) {
	case MATCH:
		/* if this fails, it implies ludicrous funding offer, *and*
		 * > 100% match. Just Say No, kids. */
		if (!amount_sat_scale(&our_funding, their_funding,
				      policy.mod / 100.0))
			our_funding = AMOUNT_SAT(0);
		return our_funding;
	case AVAILABLE:
		/* Use the 'available_funds' as the starting
		 * point for your contribution */
		if (!amount_sat_scale(&our_funding, available_funds,
				      policy.mod / 100.0))
			abort();
		return our_funding;
	case FIXED:
		/* Use a static amount */
		return amount_sat(policy.mod);
	}

	abort();
}

const char *
calculate_our_funding(struct funder_policy policy,
		      struct node_id id,
		      struct amount_sat their_funding,
		      struct amount_sat available_funds,
		      struct amount_sat channel_max,
		      struct amount_sat *our_funding)
{
	struct amount_sat avail_channel_space, net_available_funds;

	/* Are we skipping this one? */
	if (pseudorand(100) >= policy.fund_probability) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx,
			       "Skipping, failed fund_probability test");
	}

	/* Figure out amount of actual headroom we have */
	if (!amount_sat_sub(&avail_channel_space, channel_max, their_funding)
	    || amount_sat_eq(avail_channel_space, AMOUNT_SAT(0))) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "No space available in channel."
			       " channel_max %s, their_funding %s",
			       type_to_string(tmpctx, struct amount_sat,
					      &channel_max),
			       type_to_string(tmpctx, struct amount_sat,
					      &their_funding));
	}

	/* Figure out actual available funds, given our requested
	 * 'reserve_tank' */
	if (!amount_sat_sub(&net_available_funds, available_funds,
			    policy.reserve_tank)
	    || amount_sat_eq(net_available_funds, AMOUNT_SAT(0))) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Reserve tank too low."
			       " available_funds %s, reserve_tank requires %s",
			       type_to_string(tmpctx, struct amount_sat,
					      &available_funds),
			       type_to_string(tmpctx, struct amount_sat,
					      &policy.reserve_tank));
	}

	/* Are they funding enough ? */
	if (amount_sat_less(their_funding, policy.min_their_funding)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Peer's funding too little."
			       " their_funding %s,"
			       " min_their_funding requires %s",
			       type_to_string(tmpctx, struct amount_sat,
					      &their_funding),
			       type_to_string(tmpctx, struct amount_sat,
					      &policy.min_their_funding));
	}

	/* Are they funding too much ? */
	if (amount_sat_greater(their_funding, policy.max_their_funding)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Peer's funding too much."
			       " their_funding %s,"
			       " max_their_funding requires %s",
			       type_to_string(tmpctx, struct amount_sat,
					      &their_funding),
			       type_to_string(tmpctx, struct amount_sat,
					      &policy.max_their_funding));
	}

	/* What's our amount, given our policy */
	*our_funding = apply_policy(policy, their_funding, available_funds);

	/* Don't return an 'error' if we're already at 0 */
	if (amount_sat_eq(*our_funding, AMOUNT_SAT(0)))
		return NULL;

	/* our_funding is probably sane, so let's fuzz this amount a bit */
	*our_funding = apply_fuzz(policy.fuzz_factor, *our_funding);

	/* Is our_funding more than we can fit? if so set to avail space */
	if (amount_sat_greater(*our_funding, avail_channel_space))
		*our_funding = avail_channel_space;

	/* Is our_funding more than we want to fund in a channel?
	 * if so set at our desired per-channel max */
	if (amount_sat_greater(*our_funding, policy.per_channel_max))
		*our_funding = policy.per_channel_max;

	/* Is our_funding more than we have available? if so
	 * set to max available */
	if (amount_sat_greater(*our_funding, net_available_funds))
		*our_funding = net_available_funds;

	/* Is our_funding less than our per-channel minimum?
	 * if so, don't fund */
	if (amount_sat_less(*our_funding, policy.per_channel_min)) {
		*our_funding = AMOUNT_SAT(0);
		return tal_fmt(tmpctx, "Can't meet our min channel requirement."
			       " our_funding %s,"
			       " per_channel_min requires %s",
			       type_to_string(tmpctx, struct amount_sat,
					      our_funding),
			       type_to_string(tmpctx, struct amount_sat,
					      &policy.per_channel_min));
	}

	return NULL;
}
