#ifndef LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#define LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#include "config.h"
#include <common/gossmap.h>
#include <plugins/libplugin.h>

enum payment_status {
        PAYMENT_PENDING, PAYMENT_SUCCESS, PAYMENT_FAIL
};


struct payment {
	struct renepay * renepay;

	/* Chatty description of attempts. */
	const char **paynotes;

	/* Total sent, including fees. */
	struct amount_msat total_sent;

	/* Total that is delivering (i.e. without fees) */
	struct amount_msat total_delivering;

	/* invstring (bolt11 or bolt12) */
	const char *invstr;

	/* How much, what, where */
	struct amount_msat amount;
	struct node_id destination;
	struct sha256 payment_hash;


	/* Limits on what routes we'll accept. */
	struct amount_msat maxspend;

	/* Max accepted HTLC delay.*/
	unsigned int maxdelay;

	/* We promised this in pay() output */
	struct timeabs start_time;

	/* We stop trying after this time is reached. */
	struct timeabs stop_time;

	/* Payment preimage, in case of success. */
	const struct preimage *preimage;

	/* payment_secret, if specified by invoice. */
	struct secret *payment_secret;

	/* Payment metadata, if specified by invoice. */
	const u8 *payment_metadata;

	/* To know if the last attempt failed, succeeded or is it pending. */
	enum payment_status status;

	u32 final_cltv;

	/* Inside pay_plugin->payments list */
	struct list_node list;

	/* Description and labels, if any. */
	const char *description, *label;


	/* Penalty for CLTV delays */
	double delay_feefactor;

	/* Penalty for base fee */
	double base_fee_penalty;

	/* With these the effective linear fee cost is computed as
	 *
	 * linear fee cost =
	 * 	millionths
	 * 	+ base_fee* base_fee_penalty
	 * 	+delay*delay_feefactor;
	 * */

	/* The minimum acceptable prob. of success */
	double min_prob_success;

	/* Conversion from prob. cost to millionths */
	double prob_cost_factor;
	/* linear prob. cost =
	 * 	- prob_cost_factor * log prob. */


	/* If this is paying a local offer, this is the one (sendpay ensures we
	 * don't pay twice for single-use offers) */
	// TODO(eduardo): this is not being used!
	struct sha256 *local_offer_id;

	/* DEVELOPER allows disabling shadow route */
	bool use_shadow;

	/* Groupid, so listpays() can group them back together */
	u64 groupid;

	struct command_result * result;
};

/* Data only kept while the payment is being processed. */
struct renepay
{
	/* The command, and our owner (needed for timer func) */
	struct command *cmd;

	/* Payment information that will eventually outlive renepay and be
	 * registered. */
	struct payment * payment;

	/* Localmods to apply to gossip_map for our own use. */
	bool localmods_applied;
	struct gossmap_localmods *local_gossmods;

	/* Channels we decided to disable for various reasons. */
	struct short_channel_id *disabled;

	/* Timers. */
	struct plugin_timer *rexmit_timer;

	/* Keep track of the number of attempts. */
	int next_attempt;
	/* Used in get_payflows to set ids to each pay_flow. */
	u64 next_partid;

	/* Root to destroy pending flows */
	tal_t *all_flows;
};

struct payment * payment_new(struct renepay *renepay);
struct renepay * renepay_new(struct command *cmd);
void renepay_cleanup(
		struct renepay * renepay,
		struct gossmap * gossmap);

void payment_fail(struct payment * p);
void payment_success(struct payment * p);
struct amount_msat payment_sent(struct payment const * p);
struct amount_msat payment_delivered(struct payment const * p);
struct amount_msat payment_amount(struct payment const * p);
struct amount_msat payment_fees(struct payment const*p);

void payment_note(struct payment *p, const char *fmt, ...);
void payment_assert_delivering_incomplete(struct payment const * p);
void payment_assert_delivering_all(struct payment const * p);


int renepay_current_attempt(const struct renepay *renepay);
int renepay_attempt_count(const struct renepay *renepay);
void renepay_new_attempt(struct renepay *renepay);

struct command_result *renepay_success(struct renepay *renepay);

struct command_result *renepay_fail(
	struct renepay * renepay,
	enum jsonrpc_errcode code,
	const char *fmt, ...);

u64 renepay_parts(struct renepay const * renepay);

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H */
