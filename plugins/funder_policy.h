#ifndef LIGHTNING_PLUGINS_FUNDER_POLICY_H
#define LIGHTNING_PLUGINS_FUNDER_POLICY_H
#include "config.h"
#include <common/amount.h>

struct lease_rates;
struct node_id;

/* Policy Options */
enum funder_opt {
	/* Use their_funding/requested_amt as the starting
	 * point for your contribution */
	MATCH,

	/* Use the 'available_funds' as the starting
	 * point for your contribution */
	AVAILABLE,

	/* Use a static amount */
	FIXED,
};

struct funder_policy {
	/* How to interpret/apply the 'mod' field */
	enum funder_opt opt;

	/* for MATCH/AVAILABLE, is a percent of base;
	 * for FIXED is the satoshi amount */
	u64 mod;

	/* `their_funding` must be this much or greater to activate
	 * the policy. Defaults to 10,000 sats */
	struct amount_sat min_their_funding;

	/* `their_funding` must be this amount or less to activate
	 * the policy. Defaults to MAX_UNITsats */
	struct amount_sat max_their_funding;

	/* Upper limit on amount to add. Defaults to
	 * `available_funds` */
	struct amount_sat per_channel_max;

	/* Lower limit on amount to add. Defaults to
	 * 10,000sat */
	struct amount_sat per_channel_min;

	/* Percent to fuzz by. Default is 5% */
	u32 fuzz_factor;

	/* Minimum amount to leave unused in `available_funds`.
	 * Note that this is presently best-effort due to concurrency.
	 * Default is 0msat */
	struct amount_sat reserve_tank;

	/* Percent of open offers we'll consider funding. */
	u32 fund_probability;

	/* If we're advertising liquidity, only
	 * provide funds for lease requests */
	bool leases_only;

	/* Rates we're currently charging for channel leases */
	struct lease_rates *rates;
};

/* Get a new funder_policy, set to the defaults */
struct funder_policy *
default_funder_policy(const tal_t *ctx,
		      enum funder_opt policy,
		      u64 policy_mod);

/* Defaults to use for the lease_rates */
struct lease_rates *
default_lease_rates(const tal_t *ctx);

/* Given the policy and this request's details, figure
 * out how much we should contribute to this channel */
const char *
calculate_our_funding(struct funder_policy *policy,
		      struct node_id id,
		      struct amount_sat their_funding,
		      struct amount_sat available_funds,
		      struct amount_sat channel_max,
		      struct amount_sat lease_request,
		      struct amount_sat *our_funding);

/* Get the name of this policy option */
const char *funder_opt_name(enum funder_opt opt);

/* Get a (short, for now) description of the provided policy */
const char *funder_policy_desc(const tal_t *ctx,
			       const struct funder_policy *policy);

/* Convert a cmdline option to a funding_opt */
char *funding_option(const char *arg, enum funder_opt *opt);

/* Check policy settings, return error if fails */
char *funder_check_policy(const struct funder_policy *policy);
#endif /* LIGHTNING_PLUGINS_FUNDER_POLICY_H */
