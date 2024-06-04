#ifndef LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#define LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H
#include "config.h"
#include <common/gossmap.h>
#include <plugins/libplugin.h>
#include <plugins/renepay/disabledmap.h>
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

	/* Used in get_payflows to set ids to each pay_flow. */
	u64 next_partid;

	/* Running commands that want this payment */
	struct command **cmd_array;

	/* Localmods to apply to gossip_map for our own use. */
	struct gossmap_localmods *local_gossmods;

	struct disabledmap *disabledmap;

	/* Flag to indicate wether we have collected enough results to make a
	 * decision on the payment progress. */
	bool have_results;

	/* Flag to indicate wether we would like to retry the payment. */
	bool retry;

	/* Timer we use to wait for results. */
	struct plugin_timer *waitresult_timer;

	struct routetracker *routetracker;
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
	bool use_shadow);

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
	bool use_shadow);

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

/* flag the payment as success and write the preimage as proof */
struct command_result *payment_success(struct payment *payment,
				       const struct preimage *preimage TAKES);

/* flag the payment as failed and write the reason */
struct command_result *payment_fail(struct payment *payment,
				    enum jsonrpc_errcode code, const char *fmt,
				    ...);

/* These log at LOG_DBG, append to notes, and send command notification */
void payment_note(struct payment *p, enum log_level lvl, const char *fmt, ...);

void payment_disable_chan(struct payment *p, struct short_channel_id scid,
			  enum log_level lvl, const char *fmt, ...);

void payment_warn_chan(struct payment *p, struct short_channel_id scid,
		       enum log_level lvl, const char *fmt, ...);

void payment_disable_node(struct payment *p, struct node_id node,
			  enum log_level lvl, const char *fmt, ...);

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAYMENT_H */
