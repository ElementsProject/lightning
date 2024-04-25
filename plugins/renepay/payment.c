#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/routetracker.h>

static struct command_result *payment_finish(struct payment *p);

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
	    bool use_shadow)
{
	struct payment *p = tal(ctx, struct payment);

	/* === Unique properties === */
	assert(payment_hash);
	p->payment_hash = *payment_hash;

	assert(invstr);
	p->invstr = tal_strdup(p, invstr);

	p->label = tal_strdup_or_null(p, label);
	p->description = tal_strdup_or_null(p, description);
	p->payment_secret = tal_dup_or_null(p, struct secret, payment_secret);
	p->payment_metadata = tal_dup_talarr(p, u8, payment_metadata);

	if (taken(routehints))
		p->routehints = tal_steal(p, routehints);
	else {
		/* Deep copy */
		p->routehints =
		    tal_dup_talarr(p, const struct route_info *, routehints);
		for (size_t i = 0; i < tal_count(p->routehints); i++)
			p->routehints[i] =
			    tal_steal(p->routehints, p->routehints[i]);
	}

	assert(destination);
	p->destination = *destination;
	p->amount = amount;


	/* === Payment attempt parameters === */
	if (!amount_msat_add(&p->maxspend, amount, maxfee))
		p->maxspend = AMOUNT_MSAT(UINT64_MAX);
	p->maxdelay = maxdelay;

	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(retryfor));

	p->final_cltv = final_cltv;

	/* === Developer options === */
	p->base_fee_penalty = base_fee_penalty_millionths / 1e6;
	p->prob_cost_factor = prob_cost_factor_millionths / 1e6;
	p->delay_feefactor = riskfactor_millionths / 1e6;
	p->min_prob_success = min_prob_success_millionths / 1e6;
	p->use_shadow = use_shadow;


	/* === Public State === */
	p->status = PAYMENT_PENDING;
	p->preimage = NULL;
	p->error_code = LIGHTNINGD;
	p->error_msg = NULL;
	p->total_sent = AMOUNT_MSAT(0);
	p->total_delivering = AMOUNT_MSAT(0);
	p->paynotes = tal_arr(p, const char *, 0);
	p->groupid = 1;


	/* === Hidden State === */
	p->exec_state = INVALID_STATE;
	p->next_partid = 1;
	p->cmd_array = tal_arr(p, struct command *, 0);
	p->local_gossmods = NULL;
	p->disabled_scids = tal_arr(p, struct short_channel_id, 0);
	p->warned_scids = tal_arr(p, struct short_channel_id, 0);
	p->disabled_nodes = tal_arr(p, struct node_id, 0);

	p->have_results = false;
	p->retry = false;
	p->waitresult_timer = NULL;

	p->routes_computed = NULL;
	p->routetracker = new_routetracker(p);
	return p;
}

/* A payment that finishes execution must clean its hidden state. */
static void payment_cleanup(struct payment *p)
{
	p->exec_state = INVALID_STATE;
	tal_resize(&p->cmd_array, 0);
	p->local_gossmods = tal_free(p->local_gossmods);
	tal_resize(&p->disabled_scids, 0);
	tal_resize(&p->warned_scids, 0);
	tal_resize(&p->disabled_nodes, 0);
	p->waitresult_timer = tal_free(p->waitresult_timer);

	p->routes_computed = tal_free(p->routes_computed);
	routetracker_cleanup(p->routetracker);
}

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
		bool use_shadow)
{
	assert(p);

	/* === Unique properties === */
	// unchanged

	/* === Payment attempt parameters === */
	if (!amount_msat_add(&p->maxspend, p->amount, maxfee))
		p->maxspend = AMOUNT_MSAT(UINT64_MAX);
	p->maxdelay = maxdelay;

	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(retryfor));

	p->final_cltv = final_cltv;

	/* === Developer options === */
	p->base_fee_penalty = base_fee_penalty_millionths / 1e6;
	p->prob_cost_factor = prob_cost_factor_millionths / 1e6;
	p->delay_feefactor = riskfactor_millionths / 1e6;
	p->min_prob_success = min_prob_success_millionths / 1e6;
	p->use_shadow = use_shadow;


	/* === Public State === */
	p->status = PAYMENT_PENDING;

	/* I shouldn't be calling a payment_update on a payment that already
	 * succeed */
	assert(p->preimage == NULL);

	p->error_code = LIGHTNINGD;
	p->error_msg = tal_free(p->error_msg);;
	p->total_sent = AMOUNT_MSAT(0);
	p->total_delivering = AMOUNT_MSAT(0);
	// p->paynotes are unchanged, they accumulate messages
	p->groupid++;


	/* === Hidden State === */
	p->exec_state = INVALID_STATE;
	p->next_partid = 1;

	/* I shouldn't be calling a payment_update on a payment that has pending
	 * cmds. */
	assert(p->cmd_array);
	assert(tal_count(p->cmd_array) == 0);

	p->local_gossmods = tal_free(p->local_gossmods);

	assert(p->disabled_scids);
	tal_resize(&p->disabled_scids, 0);
	
	assert(p->warned_scids);
	tal_resize(&p->warned_scids, 0);
	
	assert(p->disabled_nodes);
	tal_resize(&p->disabled_nodes, 0);

	p->have_results = false;
	p->retry = false;
	p->waitresult_timer = tal_free(p->waitresult_timer);

	/* It is weird to have routes here stuck. */
	if (p->routes_computed)
		plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
			   "We have %zu unsent routes in this payment.",
			   tal_count(p->routes_computed));
	p->routes_computed = tal_free(p->routes_computed);
	return true;
}

struct amount_msat payment_sent(const struct payment *p)
{
	assert(p);
	return p->total_sent;
}
struct amount_msat payment_delivered(const struct payment *p)
{
	assert(p);
	return p->total_delivering;
}
struct amount_msat payment_amount(const struct payment *p)
{
	assert(p);
	return p->amount;
}

struct amount_msat payment_fees(const struct payment *p)
{
	assert(p);
	struct amount_msat fees;
	struct amount_msat sent = payment_sent(p),
			   delivered = payment_delivered(p);

	if (!amount_msat_sub(&fees, sent, delivered))
		plugin_err(
		    pay_plugin->plugin,
		    "Strange, sent amount (%s) is less than delivered (%s), "
		    "aborting.",
		    fmt_amount_msat(tmpctx, sent),
		    fmt_amount_msat(tmpctx, delivered));
	return fees;
}

u64 payment_parts(const struct payment *payment)
{
	assert(payment);
	return payment->next_partid - 1;
}

/* attach a command to this payment */
bool payment_register_command(struct payment *p, struct command *cmd)
{
	assert(p);
	assert(cmd);
	assert(p->cmd_array);
	tal_arr_expand(&p->cmd_array, cmd);
	return true;
}

/* are there pending commands on this payment? */
bool payment_commands_empty(const struct payment *p)
{
	assert(p);
	assert(p->cmd_array);
	return tal_count(p->cmd_array) == 0;
}

struct command *payment_command(struct payment *p)
{
	assert(p);
	assert(p->cmd_array);
	if (tal_count(p->cmd_array) == 0)
		return NULL;
	return p->cmd_array[0];
}

struct command_result *payment_success(struct payment *payment,
				       const struct preimage *preimage TAKES)
{
	assert(payment);
	assert(preimage);
	payment->status = PAYMENT_SUCCESS;
	payment->preimage = tal_free(payment->preimage);
	payment->preimage = tal_dup(payment, struct preimage, preimage);
	return payment_finish(payment);
}

struct command_result *payment_fail(struct payment *payment,
				    enum jsonrpc_errcode code, const char *fmt,
				    ...)
{
	payment->status = PAYMENT_FAIL;
	payment->error_code = code;
	payment->error_msg = tal_free(payment->error_msg);

	va_list args;
	va_start(args, fmt);
	payment->error_msg = tal_vfmt(payment, fmt, args);
	va_end(args);

	payment_note(payment, LOG_DBG, "Payment failed: %s",
		     payment->error_msg);

	return payment_finish(payment);
}

void payment_note(struct payment *p, enum log_level lvl, const char *fmt, ...)
{
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(p->paynotes, fmt, ap);
	va_end(ap);

	tal_arr_expand(&p->paynotes, str);
	/* Log at debug, unless it's weird... */
	plugin_log(pay_plugin->plugin, lvl < LOG_UNUSUAL ? LOG_DBG : lvl, "%s",
		   str);

	for (size_t i = 0; i < tal_count(p->cmd_array); i++) {
		struct command *cmd = p->cmd_array[i];
		plugin_notify_message(cmd, lvl, "%s", str);
	}
}

static struct command_result *my_command_finish(struct payment *p,
						struct command *cmd)
{
	struct json_stream *result;
	if (p->status == PAYMENT_SUCCESS) {
		result = jsonrpc_stream_success(cmd);
		json_add_payment(result, p);
		return command_finished(cmd, result);
	}
	assert(p->status == PAYMENT_FAIL);
	assert(p->error_msg);
	return command_fail(cmd, p->error_code, "%s", p->error_msg);
}

static struct command_result *payment_finish(struct payment *p)
{
	assert(p->status == PAYMENT_FAIL || p->status == PAYMENT_SUCCESS);
	assert(!payment_commands_empty(p));
	struct command *cmd = p->cmd_array[0];

	// notify all commands that the payment completed
	for (size_t i = 1; i < tal_count(p->cmd_array); ++i) {
		my_command_finish(p, p->cmd_array[i]);
	}

	// set the payment into a valid final state
	payment_cleanup(p);

	return my_command_finish(p, cmd);
}

/* FIXME: disabled_scids should be a set rather than an array, so that we don't
 * have to worry about disabling the same channel multiple times. */
void payment_disable_chan(struct payment *p, struct short_channel_id scid,
			  enum log_level lvl, const char *fmt, ...)
{
	assert(p);
	assert(p->disabled_scids);
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	payment_note(p, lvl, "disabling %s: %s",
		     fmt_short_channel_id(tmpctx, scid),
		     str);
	tal_arr_expand(&p->disabled_scids, scid);
}

/* FIXME use a map instead of a array here. */
void payment_warn_chan(struct payment *p, struct short_channel_id scid,
		       enum log_level lvl, const char *fmt, ...)
{
	assert(p);
	assert(p->warned_scids);
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	for (size_t i = 0; i < tal_count(p->warned_scids); i++) {
		if (short_channel_id_eq(scid, p->warned_scids[i])) {
			payment_disable_chan(p, scid, lvl,
					     "%s, channel warned twice", str);
			return;
		}
	}

	payment_note(
	    p, lvl, "flagged for warning %s: %s, next time it will be disabled",
	    fmt_short_channel_id(tmpctx, scid), str);
	tal_arr_expand(&p->warned_scids, scid);
}

/* FIXME use a map instead of a array here. */
void payment_disable_node(struct payment *p, struct node_id node,
			  enum log_level lvl, const char *fmt, ...)
{
	assert(p);
	assert(p->disabled_nodes);
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	payment_note(p, lvl, "disabling node %s: %s",
		     fmt_node_id(tmpctx, &node),
		     str);
	tal_arr_expand(&p->disabled_nodes, node);
}
