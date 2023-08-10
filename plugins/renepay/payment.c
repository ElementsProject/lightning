#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <plugins/renepay/debug.h>
#include <plugins/renepay/payment.h>

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
				    /* Tweakable in DEVELOPER mode */
				    u64 base_fee_penalty,
				    u64 prob_cost_factor,
				    u64 riskfactor_millionths,
				    u64 min_prob_success_millionths,
				    bool use_shadow)
{
	struct payment *p = tal(ctx,struct payment);
	p->cmd = cmd;
	p->paynotes = tal_arr(p, const char *, 0);

	p->total_sent = AMOUNT_MSAT(0);
	p->total_delivering = AMOUNT_MSAT(0);

	p->invstr = tal_strdup(p, invstr);

	p->amount = amount;
	p->destination = *destination;
	p->payment_hash = *payment_hash;
	if (!amount_msat_add(&p->maxspend, amount, maxfee))
		p->maxspend = AMOUNT_MSAT(UINT64_MAX);

	p->maxdelay = maxdelay;
	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(retryfor));
	p->preimage = NULL;
	p->payment_secret = tal_dup_or_null(p, struct secret, payment_secret);
	p->payment_metadata = tal_dup_talarr(p, u8, payment_metadata);
	p->status=PAYMENT_PENDING;
	p->final_cltv=final_cltv;
	// p->list=
	p->description = tal_strdup_or_null(p, description);
	p->label = tal_strdup_or_null(p, label);

	p->delay_feefactor = riskfactor_millionths / 1e6;
	p->base_fee_penalty = base_fee_penalty;
	p->prob_cost_factor = prob_cost_factor;
	p->min_prob_success = min_prob_success_millionths / 1e6;

	p->local_offer_id = tal_dup_or_null(p, struct sha256, local_offer_id);
	p->use_shadow = use_shadow;
	p->groupid=1;

	p->result = NULL;
 	p->local_gossmods = gossmap_localmods_new(p);
	p->disabled = tal_arr(p,struct short_channel_id,0);
	p->rexmit_timer = NULL;
	p->next_partid=1;

	return p;
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
		debug_err( "Strange, sent amount (%s) is less than delivered (%s), aborting.",
			   type_to_string(tmpctx,struct amount_msat,&sent),
			   type_to_string(tmpctx,struct amount_msat,&delivered));
	return fees;
}

void payment_note(struct payment *p, const char *fmt, ...)
{
	va_list ap;
	const char *str;

	va_start(ap, fmt);
	str = tal_vfmt(p->paynotes, fmt, ap);
	va_end(ap);
	tal_arr_expand(&p->paynotes, str);
	debug_info("%s",str);
}

void payment_assert_delivering_incomplete(const struct payment *p)
{
	if(!amount_msat_less(p->total_delivering, p->amount))
	{
		debug_err(
			"Strange, delivering (%s) is not smaller than amount (%s)",
			type_to_string(tmpctx,struct amount_msat,&p->total_delivering),
			type_to_string(tmpctx,struct amount_msat,&p->amount));
	}
}
void payment_assert_delivering_all(const struct payment *p)
{
	if(amount_msat_less(p->total_delivering, p->amount))
	{
		debug_err(
			"Strange, delivering (%s) is less than amount (%s)",
			type_to_string(tmpctx,struct amount_msat,&p->total_delivering),
			type_to_string(tmpctx,struct amount_msat,&p->amount));
	}
}

struct command_result *payment_success(struct payment *p)
{
	debug_info("calling %s",__PRETTY_FUNCTION__);

	p->status = PAYMENT_SUCCESS;
	payment_assert_delivering_all(p);

	/* We only finish command once: its destructor clears this. */
	if (!p->cmd)
		return NULL;

	struct json_stream *response
		= jsonrpc_stream_success(p->cmd);

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

	return command_finished(p->cmd, response);
}

struct command_result *payment_fail(
	struct payment *payment,
	enum jsonrpc_errcode code,
	const char *fmt, ...)
{
	/* We only finish command once: its destructor clears this. */
	if (!payment->cmd)
		return NULL;

	if (payment->status != PAYMENT_SUCCESS)
		payment->status = PAYMENT_FAIL;

	va_list args;
	va_start(args, fmt);
	char *message = tal_vfmt(tmpctx,fmt,args);
	va_end(args);

	debug_paynote(payment,"%s",message);

	return command_fail(payment->cmd,code,"%s",message);
}

u64 payment_parts(const struct payment *payment)
{
	return payment->next_partid-1;
}

/* Either the payment succeeded or failed, we need to cleanup/set the plugin
 * into a valid state before the next payment. */
void payment_cleanup(struct payment *payment)
{
	debug_info("calling %s",__PRETTY_FUNCTION__);
	// TODO(eduardo): it can happen that local_gossmods removed below
	// contained a set of channels for which there is information in the
	// uncertainty network (chan_extra_map) and that are part of some pending
	// payflow (payflow_map). Handle this situation.
	payment->local_gossmods = tal_free(payment->local_gossmods);
	payment->rexmit_timer = tal_free(payment->rexmit_timer);
}
