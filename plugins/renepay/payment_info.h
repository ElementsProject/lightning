#ifndef LIGHTNING_PLUGINS_RENEPAY_PAYMENT_INFO_H
#define LIGHTNING_PLUGINS_RENEPAY_PAYMENT_INFO_H

/* Plain data payment information. */

#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/node_id.h>

struct payment_info {
	/* payment_hash is unique */
	struct sha256 payment_hash;

	/* invstring (bolt11 or bolt12) */
	const char *invstr;

	/* Description and labels, if any. */
	const char *description, *label;

	/* payment_secret, if specified by invoice. */
	struct secret *payment_secret;

	/* Payment metadata, if specified by invoice. */
	const u8 *payment_metadata;

	/* Extracted routehints */
	const struct route_info **routehints;

	/* How much, what, where */
	struct node_id destination;
	struct amount_msat amount;

	/* === Payment attempt parameters === */

	/* Limits on what routes we'll accept. */
	struct amount_msat maxspend;

	/* Max accepted HTLC delay.*/
	unsigned int maxdelay;

	/* TODO new feature: Maximum number of hops */
	// see common/gossip_constants.h:8:#define ROUTING_MAX_HOPS 20
	// int max_num_hops;

	/* We promised this in pay() output */
	struct timeabs start_time;

	/* We stop trying after this time is reached. */
	struct timeabs stop_time;

	u32 final_cltv;

	/* === Developer options === */

	/* Penalty for base fee */
	double base_fee_penalty;

	/* Conversion from prob. cost to millionths */
	double prob_cost_factor;
	/* prob. cost = - prob_cost_factor * log prob. */

	/* Penalty for CLTV delays */
	double delay_feefactor;

	/* With these the effective linear fee cost is computed as
	 *
	 * linear fee cost =
	 * 	millionths
	 * 	+ base_fee* base_fee_penalty
	 * 	+delay*delay_feefactor;
	 * */

	/* The minimum acceptable prob. of success */
	double min_prob_success;

	/* Maximum number of hops allowed. */
	u32 max_hops;

	/* --developer allows disabling shadow route */
	bool use_shadow;
};

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAYMENT_INFO_H */
