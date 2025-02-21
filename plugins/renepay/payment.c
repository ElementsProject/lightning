#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/renepay.h>
#include <plugins/renepay/routetracker.h>

static struct command_result *payment_finish(struct payment *p);

struct payment *payment_new(const tal_t *ctx, const struct sha256 *payment_hash,
			    const char *invstr TAKES,
			    struct plugin *plugin)
{
	struct payment *p = tal(ctx, struct payment);
	memset(p, 0, sizeof(struct payment));
	p->plugin = plugin;
	struct payment_info *pinfo = &p->payment_info;

	assert(payment_hash);
	pinfo->payment_hash = *payment_hash;

	assert(invstr);
	pinfo->invstr = tal_strdup(p, invstr);

	p->status = PAYMENT_PENDING;
	p->preimage = NULL;
	p->error_code = LIGHTNINGD;
	p->error_msg = NULL;
	p->total_sent = AMOUNT_MSAT(0);
	p->total_delivering = AMOUNT_MSAT(0);
	p->paynotes = tal_arr(p, const char*, 0);
	p->groupid = 1;

	p->exec_state = INVALID_STATE;
	p->next_partid = 1;
	p->cmd_array = tal_arr(p, struct command *, 0);
	p->have_results = false;
	p->retry = false;
	p->waitresult_timer = NULL;
	p->routetracker = new_routetracker(p, p);
	p->payment_layer = fmt_sha256(p, &pinfo->payment_hash);
	return p;
}

/* A payment that finishes execution must clean its hidden state. */
static void payment_cleanup(struct payment *p)
{
	p->exec_state = INVALID_STATE;
	tal_resize(&p->cmd_array, 0);

	p->waitresult_timer = tal_free(p->waitresult_timer);

	routetracker_cleanup(p->routetracker);
}

/* Sets state values to ongoing payment */
bool payment_refresh(struct payment *p){
	assert(p);
	struct payment_info *pinfo = &p->payment_info;
	/* === Public State === */
	p->status = PAYMENT_PENDING;

	/* I shouldn't be calling a payment_update on a payment that already
	 * succeed */
	assert(p->preimage == NULL);

	p->error_code = LIGHTNINGD;
	p->error_msg = tal_free(p->error_msg);
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

	p->have_results = false;
	p->retry = false;
	p->waitresult_timer = tal_free(p->waitresult_timer);

	pinfo->start_time = time_now();
	pinfo->stop_time =
	    timeabs_add(pinfo->start_time, time_from_sec(pinfo->retryfor));

	return true;
}

bool payment_set_constraints(
		struct payment *p,
		struct amount_msat amount,
		struct amount_msat maxfee,
		unsigned int maxdelay,
		u64 retryfor,
		u64 base_fee_penalty_millionths,
		u64 prob_cost_factor_millionths,
		u64 riskfactor_millionths,
		u64 min_prob_success_millionths,
		u64 base_prob_success_millionths,
		bool use_shadow,
		const struct route_exclusion **exclusions)
{
	// FIXME: add exclusions to a layer
	assert(p);
	struct payment_info *pinfo = &p->payment_info;

	/* === Payment attempt parameters === */
	pinfo->amount = amount;
	if (!amount_msat_add(&pinfo->maxspend, pinfo->amount, maxfee))
		pinfo->maxspend = AMOUNT_MSAT(UINT64_MAX);
	pinfo->maxdelay = maxdelay;

	pinfo->retryfor = retryfor;

	/* === Developer options === */
	pinfo->base_fee_penalty = base_fee_penalty_millionths / 1e6;
	pinfo->prob_cost_factor = prob_cost_factor_millionths / 1e6;
	pinfo->delay_feefactor = riskfactor_millionths / 1e6;
	pinfo->min_prob_success = min_prob_success_millionths / 1e6;
	pinfo->base_prob_success = base_prob_success_millionths / 1e6;
	pinfo->use_shadow = use_shadow;

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
	return p->payment_info.amount;
}

struct amount_msat payment_fees(const struct payment *p)
{
	assert(p);
	struct amount_msat fees;
	struct amount_msat sent = payment_sent(p),
			   delivered = payment_delivered(p);

	if (!amount_msat_sub(&fees, sent, delivered))
		plugin_err(
		    p->plugin,
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

void register_payment_success(struct payment *payment,
			      const struct preimage *preimage TAKES)
{
	assert(payment);
	assert(preimage);
	payment->status = PAYMENT_SUCCESS;
	payment->preimage = tal_free(payment->preimage);
	if (taken(preimage))
		payment->preimage = tal_steal(payment, preimage);
	else
		payment->preimage = tal_dup(payment, struct preimage, preimage);
}

struct command_result *payment_success(struct payment *payment,
				       const struct preimage *preimage TAKES)
{
	register_payment_success(payment, preimage);
	return payment_finish(payment);
}

void register_payment_fail(struct payment *payment, enum jsonrpc_errcode code,
			   const char *fmt, ...)
{
	payment->status = PAYMENT_FAIL;
	payment->error_code = code;
	payment->error_msg = tal_free(payment->error_msg);

	va_list args;
	va_start(args, fmt);
	payment->error_msg = tal_vfmt(payment, fmt, args);
	va_end(args);
}

struct command_result *payment_fail(struct payment *payment,
				    enum jsonrpc_errcode code, const char *fmt,
				    ...)
{
	/* can't pass variadic arguments forward, so let's expand them. */
	va_list args;
	va_start(args, fmt);
	const char *error_msg = tal_vfmt(tmpctx, fmt, args);
	va_end(args);
	register_payment_fail(payment, code, "%s", error_msg);

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
	plugin_log(p->plugin, lvl < LOG_UNUSUAL ? LOG_DBG : lvl, "%s",
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

void payment_disable_chan(struct payment *p, struct short_channel_id_dir scidd,
			  enum log_level lvl, const char *fmt, ...)
{
	assert(p);
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	payment_note(p, lvl, "disabling %s: %s",
		     fmt_short_channel_id_dir(tmpctx, &scidd),
		     str);
}

void payment_warn_chan(struct payment *p, struct short_channel_id_dir scidd,
		       enum log_level lvl, const char *fmt, ...)
{
	assert(p);
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	payment_note(
	    p, lvl, "flagged for warning %s: %s, next time it will be disabled",
	    fmt_short_channel_id_dir(tmpctx, &scidd), str);
}

void payment_disable_node(struct payment *p, struct node_id node,
			  enum log_level lvl, const char *fmt, ...)
{
	assert(p);
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	payment_note(p, lvl, "disabling node %s: %s",
		     fmt_node_id(tmpctx, &node),
		     str);
}
