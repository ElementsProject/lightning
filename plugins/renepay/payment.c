#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <plugins/renepay/debug.h>
#include <plugins/renepay/payment.h>

struct payment * payment_new(struct renepay * renepay)
{
	struct payment *p = tal(renepay,struct payment);
	p->renepay = renepay;
	p->paynotes = tal_arr(p, const char *, 0);

	p->total_sent = AMOUNT_MSAT(0);
	p->total_delivering = AMOUNT_MSAT(0);

	p->invstr=NULL;

	p->amount = AMOUNT_MSAT(0);
	// p->destination=
	// p->payment_hash
	p->maxspend = AMOUNT_MSAT(0);
	p->maxdelay=0;
	// p->start_time=
	// p->stop_time=
	p->preimage = NULL;
	p->payment_secret=NULL;
	p->payment_metadata=NULL;
	p->status=PAYMENT_PENDING;
	p->final_cltv=0;
	// p->list=
	p->description=NULL;
	p->label=NULL;

	p->delay_feefactor=0;
	p->base_fee_penalty=0;
	p->prob_cost_factor=0;
	p->min_prob_success=0;

	p->local_offer_id=NULL;
	p->use_shadow=true;
	p->groupid=1;

	p->result = NULL;
	return p;
}

struct renepay * renepay_new(struct command *cmd)
{
	struct renepay *renepay = tal(cmd,struct renepay);

	renepay->cmd = cmd;
	renepay->payment = payment_new(renepay);
	renepay->localmods_applied=false;
 	renepay->local_gossmods = gossmap_localmods_new(renepay);
	renepay->disabled = tal_arr(renepay,struct short_channel_id,0);
	renepay->rexmit_timer = NULL;
	renepay->next_attempt=1;
	renepay->next_partid=1;
	renepay->all_flows = tal(renepay,tal_t);

	return renepay;
}


void payment_fail(struct payment * p)
{
	/* If the payment already succeeded this function call must correspond
	 * to an old sendpay. */
	if(p->status == PAYMENT_SUCCESS)return;
	p->status=PAYMENT_FAIL;
}
void payment_success(struct payment * p)
{
	p->status=PAYMENT_SUCCESS;
}

struct amount_msat payment_sent(struct payment const * p)
{
	return p->total_sent;
}
struct amount_msat payment_delivered(struct payment const * p)
{
	return p->total_delivering;
}
struct amount_msat payment_amount(struct payment const * p)
{
	return p->amount;
}

struct amount_msat payment_fees(struct payment const*p)
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

void payment_assert_delivering_incomplete(struct payment const * p)
{
	if(!amount_msat_less(p->total_delivering, p->amount))
	{
		debug_err(
			"Strange, delivering (%s) is not smaller than amount (%s)",
			type_to_string(tmpctx,struct amount_msat,&p->total_delivering),
			type_to_string(tmpctx,struct amount_msat,&p->amount));
	}
}
void payment_assert_delivering_all(struct payment const * p)
{
	if(amount_msat_less(p->total_delivering, p->amount))
	{
		debug_err(
			"Strange, delivering (%s) is less than amount (%s)",
			type_to_string(tmpctx,struct amount_msat,&p->total_delivering),
			type_to_string(tmpctx,struct amount_msat,&p->amount));
	}
}


int renepay_current_attempt(const struct renepay * renepay)
{
	return renepay->next_attempt-1;
}
int renepay_attempt_count(const struct renepay * renepay)
{
	return renepay->next_attempt-1;
}
void renepay_new_attempt(struct renepay * renepay)
{
	renepay->payment->status=PAYMENT_PENDING;
	renepay->next_attempt++;
}
struct command_result *renepay_success(struct renepay * renepay)
{
	debug_info("calling %s",__PRETTY_FUNCTION__);
	struct payment *p = renepay->payment;

	payment_success(p);
	payment_assert_delivering_all(p);

	struct json_stream *response
		= jsonrpc_stream_success(renepay->cmd);

	/* Any one succeeding is success. */
	json_add_preimage(response, "payment_preimage", p->preimage);
	json_add_sha256(response, "payment_hash", &p->payment_hash);
	json_add_timeabs(response, "created_at", p->start_time);
	json_add_u32(response, "parts", renepay_parts(renepay));
	json_add_amount_msat(response, "amount_msat",
				  p->amount);
	json_add_amount_msat(response, "amount_sent_msat",
				  p->total_sent);
	json_add_string(response, "status", "complete");
	json_add_node_id(response, "destination", &p->destination);

	return command_finished(renepay->cmd, response);
}

struct command_result *renepay_fail(
	struct renepay * renepay,
	enum jsonrpc_errcode code,
	const char *fmt, ...)
{
	/* renepay_fail is called after command finished. */
	if(renepay==NULL)
	{
		return command_still_pending(NULL);
	}
	payment_fail(renepay->payment);

	va_list args;
	va_start(args, fmt);
	char *message = tal_vfmt(tmpctx,fmt,args);
	va_end(args);

	debug_paynote(renepay->payment,"%s",message);

	return command_fail(renepay->cmd,code,"%s",message);
}

u64 renepay_parts(struct renepay const * renepay)
{
	return renepay->next_partid-1;
}

/* Either the payment succeeded or failed, we need to cleanup/set the plugin
 * into a valid state before the next payment. */
void renepay_cleanup(
		struct renepay * renepay,
		struct gossmap * gossmap)
{
	debug_info("calling %s",__PRETTY_FUNCTION__);
	/* Always remove our local mods (routehints) so others can use
	 * gossmap. We do this only after the payment completes. */
	// TODO(eduardo): it can happen that local_gossmods removed below
	// contained a set of channels for which there is information in the
	// uncertainty network (chan_extra_map) and that are part of some pending
	// payflow (payflow_map). Handle this situation.
	if(renepay->localmods_applied)
		gossmap_remove_localmods(gossmap,
					 renepay->local_gossmods);
	// TODO(eduardo): I wonder if it is possible to have two instances of
	// renepay at the same time.
	// 1st problem: dijkstra datastructure is global, this can be fixed,
	// 2nd problem: we don't know if gossmap_apply_localmods and gossmap_remove_localmods,
	// 	can handle different local_gossmods applied to the same gossmap.
	renepay->localmods_applied=false;
	tal_free(renepay->local_gossmods);

	renepay->rexmit_timer = tal_free(renepay->rexmit_timer);

	if(renepay->payment)
		renepay->payment->renepay = NULL;
}
