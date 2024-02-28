#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/renepay/payment.h>
#include <plugins/renepay/payplugin.h>

struct payment *payment_new(const tal_t *ctx,
			    const struct sha256 *payment_hash,
			    const char *invstr TAKES,
			    const char *label TAKES,
			    const char *description TAKES,
			    const struct secret *payment_secret TAKES,
			    const u8 *payment_metadata TAKES,
			    const struct route_info **routes TAKES,
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
	struct payment *p = tal(ctx,struct payment);
	p->paynotes = tal_arr(p, const char *, 0);

	p->total_sent = AMOUNT_MSAT(0);
	p->total_delivering = AMOUNT_MSAT(0);

	p->invstr = tal_strdup(p, invstr);

	p->amount = amount;
	p->destination = *destination;
	p->payment_hash = *payment_hash;
	if (!amount_msat_add(&p->maxspend, amount, maxfee))
		p->maxspend = AMOUNT_MSAT(UINT64_MAX);

	if (taken(routes))
		p->routes = tal_steal(p, routes);
	else {
		/* Deep copy */
		p->routes = tal_dup_talarr(p, const struct route_info *, routes);
		for (size_t i = 0; i < tal_count(p->routes); i++)
			p->routes[i] = tal_steal(p->routes, p->routes[i]);
	}
	p->maxdelay = maxdelay;
	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(retryfor));
	p->preimage = NULL;
	p->payment_secret = tal_dup_or_null(p, struct secret, payment_secret);
	p->payment_metadata = tal_dup_talarr(p, u8, payment_metadata);
	p->status=PAYMENT_PENDING;
	list_head_init(&p->flows);
	p->final_cltv=final_cltv;
	// p->list=
	p->description = tal_strdup_or_null(p, description);
	p->label = tal_strdup_or_null(p, label);

	p->delay_feefactor = riskfactor_millionths / 1e6;
	p->base_fee_penalty = base_fee_penalty_millionths / 1e6;
	p->prob_cost_factor = prob_cost_factor_millionths / 1e6;
	p->min_prob_success = min_prob_success_millionths / 1e6;

	p->use_shadow = use_shadow;
	p->groupid=1;

 	p->local_gossmods = NULL;
	p->disabled_scids = tal_arr(p,struct short_channel_id,0);
	p->next_partid=1;
	p->progress_deadline = NULL;

	p->cmd_array = tal_arr(p, struct command *, 0);
	p->modifiers = tal_arr(p, const struct payment_modifier *, 0);

	return p;
}

bool payment_update(struct payment *p,
		    const char *invstr TAKES,
		    const char *label TAKES,
		    const char *description TAKES,
		    const struct secret *payment_secret TAKES,
		    const u8 *payment_metadata TAKES,
		    const struct route_info **routes TAKES,
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
	assert(p);

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
	p->routes = tal_free(p->routes);
	if (taken(routes))
		p->routes = tal_steal(p, routes);
	else {
		/* Deep copy */
		p->routes = tal_dup_talarr(p, const struct route_info *, routes);
		for (size_t i = 0; i < tal_count(p->routes); i++)
			p->routes[i] = tal_steal(p->routes, p->routes[i]);
	}

	p->destination = *destination;
	p->amount = amount;
	if (!amount_msat_add(&p->maxspend, amount, maxfee))
		p->maxspend = AMOUNT_MSAT(UINT64_MAX);

	p->maxdelay = maxdelay;
	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(retryfor));
	p->final_cltv=final_cltv;

	p->delay_feefactor = riskfactor_millionths / 1e6;
	p->base_fee_penalty = base_fee_penalty_millionths / 1e6;
	p->prob_cost_factor = prob_cost_factor_millionths / 1e6;
	p->min_prob_success = min_prob_success_millionths / 1e6;

	p->use_shadow = use_shadow;

	p->progress_deadline = tal_free(p->progress_deadline);

	p->disabled_scids = tal_free(p->disabled_scids);
	p->disabled_scids = tal_arr(p,struct short_channel_id,0);

	// a new groupid
	p->groupid ++;
	p->next_partid=1;

	p->local_gossmods = tal_free(p->local_gossmods);

	return true;
}

/* Disable this scid for this payment, and tell me why! */
void payflow_disable_chan(struct pay_flow *pf,
			  struct short_channel_id scid,
			  enum log_level lvl,
			  const char *fmt, ...)
{
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	payflow_note(pf, lvl, "disabling %s: %s",
		     fmt_short_channel_id(tmpctx, scid),
		     str);
	tal_arr_expand(&pf->payment->disabled_scids, scid);
}

void payment_disable_chan(struct payment *p,
			  struct short_channel_id scid,
			  enum log_level lvl,
			  const char *fmt, ...)
{
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

struct amount_msat payment_sent(const struct payment *p)
{
	return p->total_sent;
}
struct amount_msat payment_delivered(const struct payment *p)
{
	return p->total_delivering;
}
struct amount_msat payment_amount(const struct payment *p)
{
	return p->amount;
}

struct amount_msat payment_fees(const struct payment *p)
{
	struct amount_msat fees;
	struct amount_msat sent = payment_sent(p),
			   delivered = payment_delivered(p);

	if(!amount_msat_sub(&fees,sent,delivered))
		plugin_err(pay_plugin->plugin, "Strange, sent amount (%s) is less than delivered (%s), aborting.",
			   fmt_amount_msat(tmpctx, sent),
			   fmt_amount_msat(tmpctx, delivered));
	return fees;
}

void payment_note(struct payment *p,
		  enum log_level lvl,
		  const char *fmt, ...)
{
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(p->paynotes, fmt, ap);
	va_end(ap);
	tal_arr_expand(&p->paynotes, str);
	/* Log at debug, unless it's weird... */
	plugin_log(pay_plugin->plugin,
		   lvl < LOG_UNUSUAL ? LOG_DBG : lvl, "%s", str);

	struct command *cmd = payment_command(p);
	// FIXME: should we notifiy every cmd?
	if (cmd)
		plugin_notify_message(cmd, lvl, "%s", str);
}

void payflow_note(struct pay_flow *pf,
		  enum log_level lvl,
		  const char *fmt, ...)
{
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	payment_note(pf->payment, lvl, "  Flow %"PRIu64": %s",
		     pf->key.partid, str);
}

void payment_assert_delivering_incomplete(const struct payment *p)
{
	if(!amount_msat_less(p->total_delivering, p->amount))
	{
		plugin_err(pay_plugin->plugin,
			"Strange, delivering (%s) is not smaller than amount (%s)",
			fmt_amount_msat(tmpctx, p->total_delivering),
			fmt_amount_msat(tmpctx, p->amount));
	}
}
void payment_assert_delivering_all(const struct payment *p)
{
	if(amount_msat_less(p->total_delivering, p->amount))
	{
		plugin_err(pay_plugin->plugin,
			"Strange, delivering (%s) is less than amount (%s)",
			fmt_amount_msat(tmpctx, p->total_delivering),
			fmt_amount_msat(tmpctx, p->amount));
	}
}

/* get me the result of this payment, not necessarily a completed payment */
struct json_stream *payment_result(struct payment *p, struct command *cmd)
{
	struct json_stream *response = jsonrpc_stream_success(cmd);

	json_add_sha256(response, "payment_hash", &p->payment_hash);
	json_add_timeabs(response, "created_at", p->start_time);
	json_add_amount_msat(response, "amount_msat", p->amount);
	json_add_node_id(response, "destination", &p->destination);

	// FIXME is this necessary?
	json_add_u32(response, "parts", payment_parts(p));

	switch (p->status) {
	case PAYMENT_SUCCESS:
		assert(p->preimage);

		json_add_string(response, "status", "complete");
		json_add_preimage(response, "payment_preimage", p->preimage);
		json_add_amount_msat(response, "amount_sent_msat",
				     p->total_sent);
		break;
	case PAYMENT_FAIL:
		// FIXME add paynotes so that people can learn why did it failed
		json_add_string(response, "status", "failed");
		break;
	case PAYMENT_PENDING:
		json_add_string(response, "status", "pending");
		break;
	}
	return response;
}

// FIXME success to be defined
struct command_result *payment_success(struct payment *p)
{
	/* We only finish command once: its destructor clears this. */
	struct command *cmd = payment_command(p);
	if (!cmd)
		return NULL;

	struct json_stream *response
		= jsonrpc_stream_success(cmd);

	/* Any one succeeding is success. */
	json_add_preimage(response, "payment_preimage", p->preimage);
	json_add_sha256(response, "payment_hash", &p->payment_hash);
	json_add_timeabs(response, "created_at", p->start_time);
	json_add_u32(response, "parts", payment_parts(p));
	json_add_amount_msat(response, "amount_msat",
				  p->amount);
	json_add_amount_msat(response, "amount_sent_msat",
				  p->total_sent);
	json_add_string(response, "status", "complete");
	json_add_node_id(response, "destination", &p->destination);

	return command_finished(cmd, response);
}

struct command_result *payment_fail(
	struct payment *payment,
	enum jsonrpc_errcode code,
	const char *fmt, ...)
{
	struct command *cmd = payment_command(payment);

	/* We usually get called because a flow failed, but we
	 * can also get called because we couldn't route any more
	 * or some strange error. */
	payment->status = PAYMENT_FAIL;

	/* We only finish command once: its destructor clears this. */
 	if (!cmd)
 		return NULL;

	va_list args;
	va_start(args, fmt);
	char *message = tal_vfmt(tmpctx,fmt,args);
	va_end(args);

	/* Don't bother notifying command, it's about to get failure */
	payment_note(payment, LOG_DBG, "%s", message);

	return command_fail(cmd,code,"%s",message);
}

u64 payment_parts(const struct payment *payment)
{
	return payment->next_partid-1;
}

void payment_reconsider(struct payment *payment)
{
	struct pay_flow *i, *next;
	bool have_state[NUM_PAY_FLOW] = {false};
	enum jsonrpc_errcode final_error COMPILER_WANTS_INIT("gcc 12.3.0 -O3"), ecode;
	const char *final_msg COMPILER_WANTS_INIT("gcc 12.3.0 -O3");
	const char *errmsg;

	plugin_log(pay_plugin->plugin, LOG_DBG, "payment_reconsider");

	/* Harvest results and free up finished flows */
	list_for_each_safe(&payment->flows, i, next, list) {
		plugin_log(pay_plugin->plugin, LOG_DBG, "Flow in state %u", i->state);
		have_state[i->state] = true;

		switch (i->state) {
		case PAY_FLOW_NOT_STARTED:
			/* Can't happen: we start just after we add. */
			plugin_err(pay_plugin->plugin, "flow not started?");
		case PAY_FLOW_IN_PROGRESS:
			/* Don't free, it's still going! */
			continue;
		case PAY_FLOW_FAILED:
			break;
		case PAY_FLOW_FAILED_FINAL:
			final_error = i->final_error;
			final_msg = tal_steal(tmpctx, i->final_msg);
			break;
		case PAY_FLOW_FAILED_GOSSIP_PENDING:
			/* Don't free, it's still going! */
			continue;
		case PAY_FLOW_SUCCESS:
			if (payment->preimage) {
				/* This should be impossible without breaking SHA256 */
				if (!preimage_eq(payment->preimage,
						 i->payment_preimage)) {
					plugin_err(pay_plugin->plugin,
						   "Impossible preimage clash for %s: %s and %s?",
						   fmt_sha256(tmpctx,
							      &payment->payment_hash),
						   fmt_preimage(tmpctx,
								payment->preimage),
						   fmt_preimage(tmpctx,
								i->payment_preimage));
				}
			} else {
				payment->preimage = tal_dup(payment, struct preimage,
							    i->payment_preimage);
			}
			break;
		}
		tal_free(i);
	}

	/* First, did one of these succeed? */
	if (have_state[PAY_FLOW_SUCCESS]) {
		plugin_log(pay_plugin->plugin, LOG_DBG, "one succeeded!");

		switch (payment->status) {
		case PAYMENT_PENDING:
			/* The normal case: one part succeeded, we can succeed immediately */
			payment_success(payment);
			payment->status = PAYMENT_SUCCESS;
			/* fall thru */
		case PAYMENT_SUCCESS:
			/* Since we already succeeded, cmd must be NULL */
			assert(payment_commands_empty(payment));
			break;
		case PAYMENT_FAIL:
			/* OK, they told us it failed, but also
			 * succeeded?  It's theoretically possible,
			 * but someone screwed up. */
			plugin_log(pay_plugin->plugin, LOG_BROKEN,
				   "Destination %s succeeded payment %s"
				   " (preimage %s) after previous final failure?",
				   fmt_node_id(tmpctx, &payment->destination),
				   fmt_sha256(tmpctx, &payment->payment_hash),
				   fmt_preimage(tmpctx, payment->preimage));
			break;
		}

		/* We don't need to do anything else. */
		return;
	}

	/* One of these returned an error from the destination? */
	if (have_state[PAY_FLOW_FAILED_FINAL]) {
		plugin_log(pay_plugin->plugin, LOG_DBG, "one failed final!");
		switch (payment->status) {
		case PAYMENT_PENDING:
			/* The normal case: we can fail immediately */
			payment_fail(payment, final_error, "%s", final_msg);
			/* fall thru */
		case PAYMENT_FAIL:
			/* Since we already failed, cmd must be NULL */
			assert(payment_commands_empty(payment));
			break;
		case PAYMENT_SUCCESS:
			/* OK, they told us it failed, but also
			 * succeeded?  It's theoretically possible,
			 * but someone screwed up. */
			plugin_log(pay_plugin->plugin, LOG_BROKEN,
				   "Destination %s failed payment %s with %u/%s"
				   " after previous success?",
				   fmt_node_id(tmpctx,
						  &payment->destination),
				   fmt_sha256(tmpctx,
						  &payment->payment_hash),
				   final_error, final_msg);
			break;
		}

		/* We don't need to do anything else. */
		return;
	}

	/* Now, do we still care about retrying the payment?  It could
	 * have terminated a while ago, and we're just collecting
	 * outstanding results. */
	switch (payment->status) {
	case PAYMENT_PENDING:
		break;
	case PAYMENT_FAIL:
	case PAYMENT_SUCCESS:
		assert(!payment_commands_empty(payment));
		plugin_log(pay_plugin->plugin, LOG_DBG, "payment already status %u!",
			   payment->status);
		return;
	}

	/* Are we waiting on addgossip?  We'll come back later when
	 * they call pay_flow_finished_adding_gossip. */
	if (have_state[PAY_FLOW_FAILED_GOSSIP_PENDING]) {
		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "%s waiting on addgossip return",
			   fmt_sha256(tmpctx,
					  &payment->payment_hash));
		return;
	}

	/* Do we still have pending payment parts?  First time, we set
	 * up a deadline so we don't respond immediately to every
	 * return: it's better to gather a few failed flows before
	 * retrying. */
	if (have_state[PAY_FLOW_IN_PROGRESS]) {
		struct timemono now = time_mono();

		/* If we don't have a deadline yet, set it now. */
		if (!payment->progress_deadline) {
			payment->progress_deadline = tal(payment, struct timemono);
			*payment->progress_deadline = timemono_add(now,
								   time_from_msec(TIMER_COLLECT_FAILURES_MSEC));
			plugin_log(pay_plugin->plugin, LOG_DBG, "Set deadline");
		}

		/* FIXME: add timemono_before to ccan/time */
		if (time_less_(now.ts, payment->progress_deadline->ts)) {
			/* Come back later. */
			/* We don't care that this temporily looks like a leak; we don't even
			 * care if we end up with multiple outstanding.  They just check
			 * the progress_deadline. */
			plugin_log(pay_plugin->plugin, LOG_DBG, "Setting timer to kick us");
			notleak(plugin_timer(pay_plugin->plugin,
					     timemono_between(*payment->progress_deadline, now),
					     payment_reconsider, payment));
			return;
		}
	}

	/* At this point, we may have some funds to deliver (or we
	 * could still be waiting). */
	if (amount_msat_greater_eq(payment->total_delivering, payment->amount)) {
		plugin_log(pay_plugin->plugin, LOG_DBG, "No more to deliver right now");
		assert(have_state[PAY_FLOW_IN_PROGRESS]);
		return;
	}

	/* If we had a deadline, reset it */
	payment->progress_deadline = tal_free(payment->progress_deadline);

	/* Before we do that, make sure we're not going over time. */
	if (time_after(time_now(), payment->stop_time)) {
		payment_fail(payment, PAY_STOPPED_RETRYING, "Timed out");
		return;
	}

	plugin_log(pay_plugin->plugin, LOG_DBG, "Retrying payment");
	errmsg = try_paying(tmpctx, payment, &ecode);
	if (errmsg)
		payment_fail(payment, ecode, "%s", errmsg);
}

/* Remove all flows with the given state. */
void payment_remove_flows(struct payment *p, enum pay_flow_state state)
{
	struct pay_flow *pf, *next;
	list_for_each_safe(&p->flows, pf, next, list) {
		if(pf->state == state)
			list_del(&pf->list);
	}
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
	if(tal_count(p->cmd_array)==0)
		return NULL;
	return p->cmd_array[0];
}

void payment_clear_modifiers(struct payment *p)
{
	tal_resize(&p->modifiers, 0);
}

void payment_push_modifier(struct payment *p,
			   const struct payment_modifier *mod)
{
	tal_arr_expand(&p->modifiers, mod);
}

const struct payment_modifier *payment_modifier_pop(struct payment *p)
{
	size_t n = tal_count(p->modifiers);
	if (n == 0)
		return NULL;
	const struct payment_modifier *mod = p->modifiers[n - 1];
	tal_resize(&p->modifiers, n - 1);
	return mod;
}
