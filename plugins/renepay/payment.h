#ifndef LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#define LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#include "config.h"
#include <common/gossmap.h>
#include <plugins/libplugin.h>

struct pay_flow;

enum payment_status {
        PAYMENT_PENDING, PAYMENT_SUCCESS, PAYMENT_FAIL
};

struct payment {
	/* Inside pay_plugin->payments list */
	struct list_node list;

	/* Overall, how are we going? */
	enum payment_status status;

	/* The flows we are managing. */
	struct list_head flows;

	/* Deadline for flow status collection. */
	struct timemono *progress_deadline;

	/* The command if still running */
	struct command *cmd;

	/* Localmods to apply to gossip_map for our own use. */
	struct gossmap_localmods *local_gossmods;

	/* Channels we decided to disable for various reasons. */
	struct short_channel_id *disabled_scids;

	/* Used in get_payflows to set ids to each pay_flow. */
	u64 next_partid;

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

	u32 final_cltv;

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
	/* prob. cost =
	 * 	- prob_cost_factor * log prob. */


	/* If this is paying a local offer, this is the one (sendpay ensures we
	 * don't pay twice for single-use offers) */
	// TODO(eduardo): this is not being used!
	struct sha256 *local_offer_id;

	/* --developer allows disabling shadow route */
	bool use_shadow;

	/* Groupid, so listpays() can group them back together */
	u64 groupid;
};


struct payment *payment_new(const tal_t *ctx,
			    struct command *cmd,
			    const char *invstr TAKES,
			    const char *label TAKES,
			    const char *description TAKES,
			    const struct sha256 *local_offer_id TAKES,
			    const struct secret *payment_secret TAKES,
			    const u8 *payment_metadata TAKES,
			    const struct node_id *destination,
			    const struct sha256 *payment_hash,
			    struct amount_msat amount,
			    struct amount_msat maxfee,
			    unsigned int maxdelay,
			    u64 retryfor,
			    u16 final_cltv,
			    /* Tweakable in --developer mode */
			    u64 base_fee_penalty,
			    u64 prob_cost_factor,
			    u64 riskfactor_millionths,
			    u64 min_prob_success_millionths,
			    bool use_shadow);

struct amount_msat payment_sent(const struct payment *p);
struct amount_msat payment_delivered(const struct payment *p);
struct amount_msat payment_amount(const struct payment *p);
struct amount_msat payment_fees(const struct payment *p);

/* These log at LOG_DBG, append to notes, and send command notification */
void payment_note(struct payment *p,
		  enum log_level lvl,
		  const char *fmt, ...);
void payflow_note(struct pay_flow *pf,
		  enum log_level lvl,
		  const char *fmt, ...);
void payment_assert_delivering_incomplete(const struct payment *p);
void payment_assert_delivering_all(const struct payment *p);

/* A flow has changed state, or we've hit a timeout: do something! */
void payment_reconsider(struct payment *p);

u64 payment_parts(const struct payment *payment);

/* Disable this scid for this payment, and tell me why! */
void payflow_disable_chan(struct pay_flow *pf,
			  struct short_channel_id scid,
			  enum log_level lvl,
			  const char *fmt, ...);

/* Sometimes, disabling chan is independent of a flow. */
void payment_disable_chan(struct payment *p,
			  struct short_channel_id scid,
			  enum log_level lvl,
			  const char *fmt, ...);

struct command_result *payment_fail(
	struct payment *payment,
	enum jsonrpc_errcode code,
	const char *fmt, ...);

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H */
