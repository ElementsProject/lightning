#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/payplugin.h>

struct payment *payment_new(
    const tal_t *ctx, const struct sha256 *payment_hash,
    const char *invstr TAKES, const char *label TAKES,
    const char *description TAKES, const struct secret *payment_secret TAKES,
    const u8 *payment_metadata TAKES,
    const struct route_info **routehints TAKES,
    const struct node_id *destination, struct amount_msat amount,
    struct amount_msat maxfee, unsigned int maxdelay, u64 retryfor,
    u16 final_cltv,
    /* Tweakable in --developer mode */
    u64 base_fee_penalty_millionths, u64 prob_cost_factor_millionths,
    u64 riskfactor_millionths, u64 min_prob_success_millionths, bool use_shadow)
{
	struct payment *p = tal(ctx, struct payment);
	p->paynotes = tal_arr(p, const char *, 0);

	p->total_sent = AMOUNT_MSAT(0);
	p->total_delivering = AMOUNT_MSAT(0);

	p->invstr = tal_strdup(p, invstr);

	p->amount = amount;
	p->destination = *destination;
	p->payment_hash = *payment_hash;
	if (!amount_msat_add(&p->maxspend, amount, maxfee))
		p->maxspend = AMOUNT_MSAT(UINT64_MAX);

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
	p->maxdelay = maxdelay;
	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(retryfor));
	p->preimage = NULL;
	p->payment_secret = tal_dup_or_null(p, struct secret, payment_secret);
	p->payment_metadata = tal_dup_talarr(p, u8, payment_metadata);
	p->status = PAYMENT_PENDING;

	p->final_cltv = final_cltv;
	p->description = tal_strdup_or_null(p, description);
	p->label = tal_strdup_or_null(p, label);

	p->delay_feefactor = riskfactor_millionths / 1e6;
	p->base_fee_penalty = base_fee_penalty_millionths / 1e6;
	p->prob_cost_factor = prob_cost_factor_millionths / 1e6;
	p->min_prob_success = min_prob_success_millionths / 1e6;

	p->use_shadow = use_shadow;
	p->groupid = 1;

	p->local_gossmods = NULL;
	p->disabled_scids = tal_arr(p, struct short_channel_id, 0);
	p->next_partid = 1;
	p->progress_deadline = NULL;

	p->cmd_array = tal_arr(p, struct command *, 0);

	p->exec_state = INVALID_STATE;
	p->routes_to_send = tal_arr(p, struct route *, 0);
	p->routes_pending = tal_arr(p, struct route *, 0);
	p->routes_completed = tal_arr(p, struct route *, 0);

	return p;
}

bool payment_update(struct payment *p, const char *invstr TAKES,
		    const char *label TAKES, const char *description TAKES,
		    const struct secret *payment_secret TAKES,
		    const u8 *payment_metadata TAKES,
		    const struct route_info **routehints TAKES,
		    const struct node_id *destination,
		    struct amount_msat amount, struct amount_msat maxfee,
		    unsigned int maxdelay, u64 retryfor, u16 final_cltv,
		    /* Tweakable in --developer mode */
		    u64 base_fee_penalty_millionths,
		    u64 prob_cost_factor_millionths, u64 riskfactor_millionths,
		    u64 min_prob_success_millionths, bool use_shadow)
{
	assert(p);

	p->exec_state = INVALID_STATE;
	p->invstr = tal_free(p->invstr);
	p->invstr = tal_strdup(p, invstr);

	p->label = tal_free(p->label);
	p->label = tal_strdup_or_null(p, label);

	p->description = tal_free(p->description);
	p->description = tal_strdup_or_null(p, description);

	p->payment_secret = tal_free(p->payment_secret);
	p->payment_secret = tal_dup_or_null(p, struct secret, payment_secret);

	p->payment_metadata = tal_free(p->payment_metadata);
	p->payment_metadata = tal_dup_talarr(p, u8, payment_metadata);

	// FIXME (eduardo): I have no idea how take/takes/taken works, so double
	// check payment_new and payment_update for memory blunders.
	p->routehints = tal_free(p->routehints);
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

	p->destination = *destination;
	p->amount = amount;
	if (!amount_msat_add(&p->maxspend, amount, maxfee))
		p->maxspend = AMOUNT_MSAT(UINT64_MAX);

	p->maxdelay = maxdelay;
	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(retryfor));
	p->final_cltv = final_cltv;

	p->delay_feefactor = riskfactor_millionths / 1e6;
	p->base_fee_penalty = base_fee_penalty_millionths / 1e6;
	p->prob_cost_factor = prob_cost_factor_millionths / 1e6;
	p->min_prob_success = min_prob_success_millionths / 1e6;

	p->use_shadow = use_shadow;

	p->progress_deadline = tal_free(p->progress_deadline);

	p->disabled_scids = tal_free(p->disabled_scids);
	p->disabled_scids = tal_arr(p, struct short_channel_id, 0);

	// a new groupid
	p->groupid++;
	p->next_partid = 1;

	p->local_gossmods = tal_free(p->local_gossmods);

	p->exec_state = INVALID_STATE;

	tal_free(p->routes_to_send);
	tal_free(p->routes_pending);
	tal_free(p->routes_completed);

	p->routes_to_send = tal_arr(p, struct route *, 0);
	p->routes_pending = tal_arr(p, struct route *, 0);
	p->routes_completed = tal_arr(p, struct route *, 0);

	return true;
}

struct amount_msat payment_sent(const struct payment *p)
{
	return p->total_sent;
}
struct amount_msat payment_delivered(const struct payment *p)
{
	return p->total_delivering;
}
struct amount_msat payment_amount(const struct payment *p) { return p->amount; }

struct amount_msat payment_fees(const struct payment *p)
{
	struct amount_msat fees;
	struct amount_msat sent = payment_sent(p),
			   delivered = payment_delivered(p);

	if (!amount_msat_sub(&fees, sent, delivered))
		plugin_err(
		    pay_plugin->plugin,
		    "Strange, sent amount (%s) is less than delivered (%s), "
		    "aborting.",
		    type_to_string(tmpctx, struct amount_msat, &sent),
		    type_to_string(tmpctx, struct amount_msat, &delivered));
	return fees;
}

void payment_assert_delivering_all(const struct payment *p)
{
	if (amount_msat_less(p->total_delivering, p->amount)) {
		plugin_err(
		    pay_plugin->plugin,
		    "Strange, delivering (%s) is less than amount (%s)",
		    type_to_string(tmpctx, struct amount_msat,
				   &p->total_delivering),
		    type_to_string(tmpctx, struct amount_msat, &p->amount));
	}
}

u64 payment_parts(const struct payment *payment)
{
	return payment->next_partid - 1;
}

/* attach a command to this payment */
bool payment_register_command(struct payment *p, struct command *cmd)
{
	tal_arr_expand(&p->cmd_array, cmd);
	return true;
}

/* are there pending commands on this payment? */
bool payment_commands_empty(const struct payment *p)
{
	return tal_count(p->cmd_array) == 0;
}

struct command *payment_command(struct payment *p)
{
	if (tal_count(p->cmd_array) == 0)
		return NULL;
	return p->cmd_array[0];
}

/* get me the result of this payment, not necessarily a completed payment */
struct json_stream *payment_result(struct payment *p, struct command *cmd)
{
	struct json_stream *response = jsonrpc_stream_success(cmd);

	json_add_sha256(response, "payment_hash", &p->payment_hash);
	json_add_timeabs(response, "created_at", p->start_time);
	json_add_amount_msat(response, "amount_msat", p->amount);
	json_add_node_id(response, "destination", &p->destination);

	switch (p->status) {
	case PAYMENT_SUCCESS:
		assert(p->preimage);

		json_add_string(response, "status", "complete");
		json_add_preimage(response, "payment_preimage", p->preimage);
		json_add_amount_msat(response, "amount_sent_msat",
				     p->total_sent);
		break;
	case PAYMENT_FAIL:
		json_add_string(response, "status", "failed");
		// TODO: add payment notes or attempts
		// see paystatus_add_payment
		break;
	case PAYMENT_PENDING:
		json_add_string(response, "status", "pending");
		break;
	}
	return response;
}

void payment_success(struct payment *p, const struct preimage *preimage)
{
	payment->status = PAYMENT_SUCCESS;
	payment->preimage = tal_dup(payment, struct preimage, preimage);
}

void payment_fail(struct payment *payment, enum jsonrpc_errcode code,
		  const char *fmt, ...)
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
		result = payment_result(p, cmd);
		return command_finished(cmd, result);
	}
	assert(p->status == PAYMENT_FAIL);
	assert(p->error_msg);
	return command_fail(cmd, p->error_code, "%s", p->error_msg);
}

struct command_result *payment_finish(struct payment *p)
{
	// TODO take the payment into a valid final state

	assert(p->status == PAYMENT_FAIL || p->status == PAYMENT_SUCCESS);
	assert(!payment_commands_empty(p));
	struct command *cmd = p->cmd_array[0];

	// notify all commands that the payment completed
	for (size_t i = 1; i < tal_count(p->cmd_array); ++i) {
		my_command_finish(p, p->cmd_array[i]);
	}
	tal_resize(&p->cmd_array, 0);
	return my_command_finish(p, cmd);
}
