#ifndef LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#define LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#include "config.h"
#include <common/gossmap.h>
#include <common/route.h>
#include <plugins/libplugin.h>
#include <plugins/renepay/payment_info.h>

enum payment_status { PAYMENT_PENDING, PAYMENT_SUCCESS, PAYMENT_FAIL };

#define INVALID_STATE UINT64_MAX

struct payment {
	/* Inside pay_plugin->payments list */
	struct payment_info payment_info;


	/* === Public State === */
	/* TODO: these properties should be private and only changed through
	 * payment_ methods. */

	/* Overall, how are we going? */
	enum payment_status status;

	/* Payment preimage, in case of success. */
	const struct preimage *preimage;

	/* Final error code and message, in case of failure. */
	enum jsonrpc_errcode error_code;
	const char *error_msg;

	/* Total sent, including fees. */
	struct amount_msat total_sent;

	/* Total that is delivering (i.e. without fees) */
	struct amount_msat total_delivering;

	/* Chatty description of attempts. */
	const char **paynotes;

	/* Groupid, so listpays() can group them back together */
	u64 groupid;


	/* === Hidden State === */
	/* Position in the payment virtual machine */
	u64 exec_state;

	/* Number of pending RPCs responses before we move to the next state. */
	u32 pending_rpcs;

	/* Used in get_payflows to set ids to each pay_flow. */
	u64 next_partid;

	/* Running commands that want this payment */
	struct command **cmd_array;

	/* Here we queue channel and node disabling orders. */
	struct route_exclusion *exclusions;

	/* Flag to indicate wether we would like to retry the payment. */
	bool retry;

	/* Timer we use to wait for results. */
	struct plugin_timer *waitresult_timer;

	struct routetracker *routetracker;

	/* The name of the layer where we put information regarding this
	 * payment. */
	char *private_layer;
};

static inline const struct sha256 payment_hash(const struct payment *p)
{
	return p->payment_info.payment_hash;
}

static inline size_t payment_hash64(const struct sha256 h)
{
	return ((u64)h.u.u32[1] << 32) ^ h.u.u32[0];
}

static inline bool payment_hash_eq(const struct payment *p,
				   const struct sha256 h)
{
	return p->payment_info.payment_hash.u.u32[0] == h.u.u32[0] &&
	       p->payment_info.payment_hash.u.u32[1] == h.u.u32[1] &&
	       p->payment_info.payment_hash.u.u32[2] == h.u.u32[2] &&
	       p->payment_info.payment_hash.u.u32[3] == h.u.u32[3] &&
	       p->payment_info.payment_hash.u.u32[4] == h.u.u32[4] &&
	       p->payment_info.payment_hash.u.u32[5] == h.u.u32[5] &&
	       p->payment_info.payment_hash.u.u32[6] == h.u.u32[6] &&
	       p->payment_info.payment_hash.u.u32[7] == h.u.u32[7];
}

HTABLE_DEFINE_TYPE(struct payment, payment_hash, payment_hash64,
		   payment_hash_eq, payment_map);

struct payment *payment_new(
	const tal_t *ctx,
	const struct sha256 *payment_hash,
	const char *invstr TAKES,
	const char *label TAKES,
	const char *description TAKES,
	const struct secret *payment_secret TAKES,
	const u8 *payment_metadata TAKES,
	const struct route_info **routehints TAKES,
	const struct node_id *destination,
	struct amount_msat amount,
	struct amount_msat maxfee,
	unsigned int maxdelay,
	u64 retryfor,
	u16 final_cltv,
	/* Tweakable in --developer mode */
	u64 base_fee_penalty_millionths,
	u64 prob_cost_factor_millionths,
	u64 riskfactor_millionths,
	u64 min_prob_success_millionths,
	u64 base_prob_success_millionths,
	bool use_shadow,
	const struct route_exclusion **exclusions);

bool payment_update(
	struct payment *p,
	struct amount_msat maxfee,
	unsigned int maxdelay,
	u64 retryfor,
	u16 final_cltv,
	    /* Tweakable in --developer mode */
	u64 base_fee_penalty_millionths,
	u64 prob_cost_factor_millionths,
	u64 riskfactor_millionths,
	u64 min_prob_success_millionths,
	u64 base_prob_success_millionths,
	bool use_shadow,
	const struct route_exclusion **exclusions);

struct amount_msat payment_sent(const struct payment *p);
struct amount_msat payment_delivered(const struct payment *p);
struct amount_msat payment_amount(const struct payment *p);
struct amount_msat payment_fees(const struct payment *p);

u64 payment_parts(const struct payment *payment);

/* attach a command to this payment */
bool payment_register_command(struct payment *p, struct command *cmd);
/* are there pending commands on this payment? */
bool payment_commands_empty(const struct payment *p);
struct command *payment_command(struct payment *p);

/* get me the result of this payment, not necessarily a completed payment */
struct json_stream *payment_result(struct payment *p, struct command *cmd);

/* Flag the payment as success and write the preimage as proof. */
void register_payment_success(struct payment *payment,
			      const struct preimage *preimage TAKES);
/* Flag the payment as success and write the preimage as proof and end the
 * payment execution. */
struct command_result *payment_success(struct payment *payment,
				       const struct preimage *preimage TAKES);

/* Flag the payment as failed and write the reason. */
void register_payment_fail(struct payment *payment, enum jsonrpc_errcode code,
			   const char *fmt, ...);
/* Flag the payment as failed and write the reason and end the payment
 * execution. */
struct command_result *payment_fail(struct payment *payment,
				    enum jsonrpc_errcode code, const char *fmt,
				    ...);

/* These log at LOG_DBG, append to notes, and send command notification */
void payment_note(struct payment *p, enum log_level lvl, const char *fmt, ...);

void payment_disable_chan(struct payment *p, struct short_channel_id_dir scidd,
			  enum log_level lvl, const char *fmt, ...);

void payment_warn_chan(struct payment *p, struct short_channel_id_dir scidd,
		       enum log_level lvl, const char *fmt, ...);

void payment_disable_node(struct payment *p, struct node_id node,
			  enum log_level lvl, const char *fmt, ...);

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H */
