#include "config.h"
#include <assert.h>
#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/type_to_string.h>
#include <math.h>
#include <plugins/renepay/flow.h>
#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#else
#define SUPERVERBOSE_ENABLED 1
#endif

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

bool chan_extra_is_busy(const struct chan_extra *const ce)
{
	if(ce==NULL)return false;
	return ce->half[0].num_htlcs || ce->half[1].num_htlcs;
}

const char *fmt_chan_extra_map(
		const tal_t *ctx,
		struct chan_extra_map* chan_extra_map)
{
	tal_t *this_ctx = tal(ctx,tal_t);
	char *buff = tal_fmt(ctx,"Uncertainty network:\n");
	struct chan_extra_map_iter it;
	for(struct chan_extra *ch = chan_extra_map_first(chan_extra_map,&it);
	    ch;
	    ch=chan_extra_map_next(chan_extra_map,&it))
	{
		const char *scid_str =
			type_to_string(this_ctx,struct short_channel_id,&ch->scid);
		for(int dir=0;dir<2;++dir)
		{
			tal_append_fmt(&buff,"%s[%d]:(%s,%s)\n",scid_str,dir,
				type_to_string(this_ctx,struct amount_msat,&ch->half[dir].known_min),
				type_to_string(this_ctx,struct amount_msat,&ch->half[dir].known_max));
		}
	}
	tal_free(this_ctx);
	return buff;
}

const char *fmt_chan_extra_details(const tal_t *ctx,
				   struct chan_extra_map* chan_extra_map,
				   const struct short_channel_id_dir *scidd)
{
	const struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
							 scidd->scid);
	const struct chan_extra_half *ch;
	char *str = tal_strdup(ctx, "");
	char sep = '(';

	if (!ce)
		return str;

	ch = &ce->half[scidd->dir];
	if (ch->num_htlcs != 0) {
		tal_append_fmt(&str, "%c%s in %zu htlcs",
			       sep,
			       fmt_amount_msat(tmpctx, ch->htlc_total),
			       ch->num_htlcs);
		sep = ',';
	}
	/* Happens with local channels, where we're certain. */
	if (amount_msat_eq(ch->known_min, ch->known_max)) {
		tal_append_fmt(&str, "%cmin=max=%s",
			       sep,
			       fmt_amount_msat(tmpctx, ch->known_min));
		sep = ',';
	} else {
		if (amount_msat_greater(ch->known_min, AMOUNT_MSAT(0))) {
			tal_append_fmt(&str, "%cmin=%s",
				       sep,
				       fmt_amount_msat(tmpctx, ch->known_min));
			sep = ',';
	}
		if (!amount_msat_eq(ch->known_max, ce->capacity)) {
			tal_append_fmt(&str, "%cmax=%s",
				       sep,
				       fmt_amount_msat(tmpctx, ch->known_max));
			sep = ',';
		}
	}
	if (!streq(str, ""))
		tal_append_fmt(&str, ")");
	return str;
}

struct chan_extra *new_chan_extra(
		struct chan_extra_map *chan_extra_map,
		const struct short_channel_id scid,
		struct amount_msat capacity)
{
	struct chan_extra *ce = tal(chan_extra_map, struct chan_extra);

	ce->scid = scid;
	ce->capacity=capacity;
	for (size_t i = 0; i <= 1; i++) {
		ce->half[i].num_htlcs = 0;
		ce->half[i].htlc_total = AMOUNT_MSAT(0);
		ce->half[i].known_min = AMOUNT_MSAT(0);
		ce->half[i].known_max = capacity;
	}
	chan_extra_map_add(chan_extra_map, ce);

	/* Remove self from map when done */
	// TODO(eduardo):
	// Is this desctructor really necessary? the chan_extra will deallocated
	// when the chan_extra_map is freed. Anyways valgrind complains that the
	// hash table is removing the element with a freed pointer.
	// tal_add_destructor2(ce, destroy_chan_extra, chan_extra_map);
	return ce;
}

/* This helper function preserves the uncertainty network invariant after the
 * knowledge is updated. It assumes that the (channel,!dir) knowledge is
 * correct. */
void chan_extra_adjust_half(struct chan_extra *ce,
			    int dir)
{
	if(!amount_msat_sub(&ce->half[dir].known_max,ce->capacity,ce->half[!dir].known_min))
	{
		plugin_err(pay_plugin->plugin,
			   "%s cannot substract capacity=%s and known_min=%s",
			__PRETTY_FUNCTION__,
			type_to_string(tmpctx,struct amount_msat,&ce->capacity),
			type_to_string(tmpctx,struct amount_msat,&ce->half[!dir].known_min)
			);
	}
	if(!amount_msat_sub(&ce->half[dir].known_min,ce->capacity,ce->half[!dir].known_max))
	{
		plugin_err(pay_plugin->plugin,"%s cannot substract capacity=%s and known_max=%s",
			__PRETTY_FUNCTION__,
			type_to_string(tmpctx,struct amount_msat,&ce->capacity),
			type_to_string(tmpctx,struct amount_msat,&ce->half[!dir].known_max)
			);
	}
}


/* Update the knowledge that this (channel,direction) can send x msat.*/
static void chan_extra_can_send_(
		struct chan_extra *ce,
		int dir,
		struct amount_msat x)
{
	if(amount_msat_greater(x,ce->capacity))
	{
		plugin_err(pay_plugin->plugin,"%s unexpected capacity=%s is less than x=%s",
			__PRETTY_FUNCTION__,
			type_to_string(tmpctx,struct amount_msat,&ce->capacity),
			type_to_string(tmpctx,struct amount_msat,&x)
			);
		x = ce->capacity;
	}

	ce->half[dir].known_min = amount_msat_max(ce->half[dir].known_min,x);
	ce->half[dir].known_max = amount_msat_max(ce->half[dir].known_max,x);

	chan_extra_adjust_half(ce,!dir);
}

void chan_extra_can_send(
		struct chan_extra_map *chan_extra_map,
		const struct short_channel_id_dir *scidd,
		struct amount_msat x)
{
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
						   scidd->scid);
	if(!ce)
	{
		plugin_err(pay_plugin->plugin,"%s unexpected chan_extra ce is NULL",
			__PRETTY_FUNCTION__);
	}
	if(!amount_msat_add(&x,x,ce->half[scidd->dir].htlc_total))
	{
		plugin_err(pay_plugin->plugin,"%s (line %d) cannot add x=%s and htlc_total=%s",
			__PRETTY_FUNCTION__,__LINE__,
			type_to_string(tmpctx,struct amount_msat,&x),
			type_to_string(tmpctx,struct amount_msat,&ce->half[scidd->dir].htlc_total));
	}
	chan_extra_can_send_(ce,scidd->dir,x);
}

/* Update the knowledge that this (channel,direction) cannot send.*/
void chan_extra_cannot_send(
		struct chan_extra_map *chan_extra_map,
		const struct short_channel_id_dir *scidd,
		struct amount_msat sent)
{
	struct amount_msat oldmin, oldmax, x;
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
						   scidd->scid);
	if(!ce)
	{
		plugin_err(pay_plugin->plugin,"%s (line %d) unexpected chan_extra ce is NULL",
			__PRETTY_FUNCTION__,__LINE__);
	}

	/* Note: sent is already included in htlc_total! */
	if(!amount_msat_sub(&x,ce->half[scidd->dir].htlc_total,AMOUNT_MSAT(1)))
	{
		plugin_err(pay_plugin->plugin,"%s (line %d) unexpected htlc_total=%s is less than 0msat",
			__PRETTY_FUNCTION__,__LINE__,
			type_to_string(tmpctx,struct amount_msat,
				       &ce->half[scidd->dir].htlc_total)
			);
		x = AMOUNT_MSAT(0);
	}

	oldmin = ce->half[scidd->dir].known_min;
	oldmax = ce->half[scidd->dir].known_max;

	/* If we "knew" the capacity was at least this, we just showed we're wrong! */
	if (amount_msat_less(x, ce->half[scidd->dir].known_min)) {
		/* Skip to half of x, since we don't know (rounds down) */
		ce->half[scidd->dir].known_min = amount_msat_div(x, 2);
	}

	ce->half[scidd->dir].known_max = amount_msat_min(ce->half[scidd->dir].known_max,x);

	chan_extra_adjust_half(ce,!scidd->dir);
}
/* Update the knowledge that this (channel,direction) has liquidity x.*/
static void chan_extra_set_liquidity_(
		struct chan_extra *ce,
		int dir,
		struct amount_msat x)
{
	if(amount_msat_greater(x,ce->capacity))
	{
		plugin_err(pay_plugin->plugin,"%s unexpected capacity=%s is less than x=%s",
			__PRETTY_FUNCTION__,
			type_to_string(tmpctx,struct amount_msat,&ce->capacity),
			type_to_string(tmpctx,struct amount_msat,&x)
			);
		x = ce->capacity;
	}

	ce->half[dir].known_min = x;
	ce->half[dir].known_max = x;

	chan_extra_adjust_half(ce,!dir);
}
void chan_extra_set_liquidity(
		struct chan_extra_map *chan_extra_map,
		const struct short_channel_id_dir *scidd,
		struct amount_msat x)
{
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
						   scidd->scid);
	if(!ce)
	{
		plugin_err(pay_plugin->plugin,"%s unexpected chan_extra ce is NULL",
			__PRETTY_FUNCTION__);
	}
	chan_extra_set_liquidity_(ce,scidd->dir,x);
}
/* Update the knowledge that this (channel,direction) has sent x msat.*/
void chan_extra_sent_success(
		struct chan_extra_map *chan_extra_map,
		const struct short_channel_id_dir *scidd,
		struct amount_msat x)
{
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
						   scidd->scid);
	if(!ce)
	{
		plugin_err(pay_plugin->plugin,"%s unexpected chan_extra ce is NULL",
			__PRETTY_FUNCTION__);
	}

	if(amount_msat_greater(x,ce->capacity))
	{
		plugin_err(pay_plugin->plugin,"%s unexpected capacity=%s is less than x=%s",
			__PRETTY_FUNCTION__,
			type_to_string(tmpctx,struct amount_msat,&ce->capacity),
			type_to_string(tmpctx,struct amount_msat,&x)
			);
		x = ce->capacity;
	}

	struct amount_msat new_a, new_b;

	if(!amount_msat_sub(&new_a,ce->half[scidd->dir].known_min,x))
		new_a = AMOUNT_MSAT(0);
	if(!amount_msat_sub(&new_b,ce->half[scidd->dir].known_max,x))
		new_b = AMOUNT_MSAT(0);

	ce->half[scidd->dir].known_min = new_a;
	ce->half[scidd->dir].known_max = new_b;

	chan_extra_adjust_half(ce,!scidd->dir);
}
/* Forget a bit about this (channel,direction) state. */
static void chan_extra_relax_(
		struct chan_extra *ce,
		int dir,
		struct amount_msat down,
		struct amount_msat up)
{
	struct amount_msat new_a, new_b;

	if(!amount_msat_sub(&new_a,ce->half[dir].known_min,down))
		new_a = AMOUNT_MSAT(0);
	if(!amount_msat_add(&new_b,ce->half[dir].known_max,up))
		new_b = ce->capacity;
	new_b = amount_msat_min(new_b,ce->capacity);

	ce->half[dir].known_min = new_a;
	ce->half[dir].known_max = new_b;

	chan_extra_adjust_half(ce,!dir);
}
void chan_extra_relax(
		struct chan_extra_map *chan_extra_map,
		const struct short_channel_id_dir *scidd,
		struct amount_msat x,
		struct amount_msat y)
{
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
						   scidd->scid);
	if(!ce)
	{
		plugin_err(pay_plugin->plugin,"%s unexpected chan_extra ce is NULL",
			__PRETTY_FUNCTION__);
	}
	chan_extra_relax_(ce,scidd->dir,x,y);
}

/* Forget the channel information by a fraction of the capacity. */
void chan_extra_relax_fraction(
		struct chan_extra* ce,
		double fraction)
{
	fraction = fabs(fraction); // this number is always non-negative
	fraction = MIN(1.0,fraction); // this number cannot be greater than 1.
	struct amount_msat delta = amount_msat(ce->capacity.millisatoshis * fraction); /* Raw: get a fraction of the capacity */

	/* The direction here is not important because the 'down' and the 'up'
	 * limits are changed by the same amount.
	 * Notice that if chan[0] with capacity C changes from (a,b) to (a-d,b+d)
	 * then its counterpart chan[1] changes from (C-b,C-a) to (C-b-d,C-a+d),
	 * hence both dirs are applied the same transformation. */
	chan_extra_relax_(ce,/*dir=*/0,delta,delta);
}


/* Returns either NULL, or an entry from the hash */
struct chan_extra_half *
get_chan_extra_half_by_scid(struct chan_extra_map *chan_extra_map,
			    const struct short_channel_id_dir *scidd)
{
	struct chan_extra *ce;

	ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce)
		return NULL;
	return &ce->half[scidd->dir];
}
/* Helper if we have a gossmap_chan */
struct chan_extra_half *
get_chan_extra_half_by_chan(const struct gossmap *gossmap,
			    struct chan_extra_map *chan_extra_map,
			    const struct gossmap_chan *chan,
			    int dir)
{
	struct short_channel_id_dir scidd;

	scidd.scid = gossmap_chan_scid(gossmap, chan);
	scidd.dir = dir;
	return get_chan_extra_half_by_scid(chan_extra_map, &scidd);
}


// static void destroy_chan_extra(struct chan_extra *ce,
// 			       struct chan_extra_map *chan_extra_map)
// {
// 	chan_extra_map_del(chan_extra_map, ce);
// }
/* Helper to get the chan_extra_half. If it doesn't exist create a new one. */
struct chan_extra_half *
get_chan_extra_half_by_chan_verify(
		const struct gossmap *gossmap,
		struct chan_extra_map *chan_extra_map,
		const struct gossmap_chan *chan,
		int dir)
{

	struct short_channel_id_dir scidd;

	scidd.scid = gossmap_chan_scid(gossmap,chan);
	scidd.dir = dir;
	struct chan_extra_half *h = get_chan_extra_half_by_scid(
					chan_extra_map,&scidd);
	if (!h) {
		struct amount_sat cap;
		struct amount_msat cap_msat;

		if (!gossmap_chan_get_capacity(gossmap,chan, &cap) ||
		    !amount_sat_to_msat(&cap_msat, cap))
		{
			plugin_err(pay_plugin->plugin,"%s (line %d) unable convert sat to msat or "
				"get channel capacity",
				__PRETTY_FUNCTION__,
				__LINE__);
		}
		h = & new_chan_extra(chan_extra_map,scidd.scid,cap_msat)->half[scidd.dir];

	}
	return h;
}

/* Assuming a uniform distribution, what is the chance this f gets through?
 * Here we compute the conditional probability of success for a flow f, given
 * the knowledge that the liquidity is in the range [a,b) and some amount
 * x is already committed on another part of the payment.
 *
 * The probability equation for x=0 is:
 *
 * 	prob(f) =
 *
 * 	for f<a:	1.
 * 	for b>=f>=a:	(b-f)/(b-a)
 * 	for b<f:	0.
 *
 * When x>0 the prob. of success for passing x and f is:
 *
 * 	prob(f and x) = prob(x) * prob(f|x)
 *
 * and it can be shown to be equal to
 *
 * 	prob(f and x) = prob(f+x)
 *
 * The purpose of this function is to obtain prob(f|x), i.e. the probability of
 * getting f through provided that we already succeeded in getting x.
 * This conditional probability comes with 4 cases:
 *
 * 	prob(f|x) =
 *
 * 	for x<a and f<a-x: 	1.
 * 	for x<a and f>=a-x:	(b-x-f)/(b-a)
 * 	for x>=a:		(b-x-f)/(b-x)
 * 	for f>b-x:		0.
 *
 * This is the same as the probability of success of f when the bounds are
 * shifted by x amount, the new bounds be [MAX(0,a-x),b-x).
 */
static double edge_probability(struct amount_msat min, struct amount_msat max,
			       struct amount_msat in_flight,
			       struct amount_msat f)
{
	assert(amount_msat_less_eq(min,max));
	assert(amount_msat_less_eq(in_flight,max));

	const tal_t *this_ctx = tal(tmpctx,tal_t);

	const struct amount_msat one = AMOUNT_MSAT(1);
	struct amount_msat B=max; // =  max +1 - in_flight

	// one past the last known value, makes computations simpler
	if(!amount_msat_add(&B,B,one))
	{
		plugin_err(pay_plugin->plugin,"%s (line %d) cannot add B=%s and %s",
			__PRETTY_FUNCTION__,
			__LINE__,
			type_to_string(this_ctx, struct amount_msat, &B),
			type_to_string(this_ctx, struct amount_msat, &one));
	}
	// in_flight cannot be greater than max
	if(!amount_msat_sub(&B,B,in_flight))
	{
		plugin_err(pay_plugin->plugin,"%s (line %d) in_flight=%s cannot be greater than B=%s",
			__PRETTY_FUNCTION__,
			__LINE__,
			type_to_string(this_ctx, struct amount_msat, &in_flight),
			type_to_string(this_ctx, struct amount_msat, &B));
	}
	struct amount_msat A=min; // = MAX(0,min-in_flight);

	if(!amount_msat_sub(&A,A,in_flight))
		A = AMOUNT_MSAT(0);

	struct amount_msat denominator; // = B-A

	// B cannot be smaller than or equal A
	if(!amount_msat_sub(&denominator,B,A) || amount_msat_less_eq(B,A))
	{
		plugin_err(pay_plugin->plugin,"%s (line %d) B=%s must be greater than A=%s",
			__PRETTY_FUNCTION__,
			__LINE__,
			type_to_string(this_ctx, struct amount_msat, &B),
			type_to_string(this_ctx, struct amount_msat, &A));
	}
	struct amount_msat numerator; // MAX(0,B-f)

	if(!amount_msat_sub(&numerator,B,f))
		numerator = AMOUNT_MSAT(0);

	tal_free(this_ctx);
	return amount_msat_less_eq(f,A) ? 1.0 : amount_msat_ratio(numerator,denominator);
}






// TODO(eduardo): remove this function, is a duplicate
void remove_completed_flow(const struct gossmap *gossmap,
			   struct chan_extra_map *chan_extra_map,
			   struct flow *flow)
{
	for (size_t i = 0; i < tal_count(flow->path); i++) {
		struct chan_extra_half *h = get_chan_extra_half_by_chan(gossmap,
							       chan_extra_map,
							       flow->path[i],
							       flow->dirs[i]);
		if (!amount_msat_sub(&h->htlc_total, h->htlc_total, flow->amounts[i]))
		{
			plugin_err(pay_plugin->plugin,"%s could not substract HTLC amounts, "
				   "half total htlc amount = %s, "
				   "flow->amounts[%lld] = %s.",
				   __PRETTY_FUNCTION__,
				   type_to_string(tmpctx, struct amount_msat, &h->htlc_total),
				   i,
				   type_to_string(tmpctx, struct amount_msat, &flow->amounts[i]));
		}
		if (h->num_htlcs == 0)
		{
			plugin_err(pay_plugin->plugin,"%s could not decrease HTLC count.",
				   __PRETTY_FUNCTION__);
		}
		h->num_htlcs--;
	}
}
// TODO(eduardo): remove this function, is a duplicate
void remove_completed_flow_set(
		const struct gossmap *gossmap,
		struct chan_extra_map *chan_extra_map,
		struct flow **flows)
{
	for(size_t i=0;i<tal_count(flows);++i)
	{
		remove_completed_flow(gossmap,chan_extra_map,flows[i]);
	}
}

// TODO(eduardo): remove this function, is a duplicate
void commit_flow(
		const struct gossmap *gossmap,
		struct chan_extra_map *chan_extra_map,
		struct flow *flow)
{
	for (size_t i = 0; i < tal_count(flow->path); i++) {
		struct chan_extra_half *h = get_chan_extra_half_by_chan(gossmap,
							       chan_extra_map,
							       flow->path[i],
							       flow->dirs[i]);
		if (!amount_msat_add(&h->htlc_total, h->htlc_total, flow->amounts[i]))
		{
			plugin_err(pay_plugin->plugin,"%s could not add HTLC amounts, "
				   "flow->amounts[%lld] = %s.",
				   __PRETTY_FUNCTION__,
				   i,
				   type_to_string(tmpctx, struct amount_msat, &flow->amounts[i]));
		}
		h->num_htlcs++;
	}
}
// TODO(eduardo): remove this function, is a duplicate
void commit_flow_set(
		const struct gossmap *gossmap,
		struct chan_extra_map *chan_extra_map,
		struct flow **flows)
{
	for(size_t i=0;i<tal_count(flows);++i)
	{
		commit_flow(gossmap,chan_extra_map,flows[i]);
	}
}

/* Helper function to fill in amounts and success_prob for flow
 *
 * IMPORTANT: here we do not commit flows to chan_extra, flows are commited
 * after we send those htlc.
 *
 * IMPORTANT: flow->success_prob is misleading, because that's the prob. of
 * success provided that there are no other flows in the current MPP flow set.
 * */
void flow_complete(struct flow *flow,
		   const struct gossmap *gossmap,
		   struct chan_extra_map *chan_extra_map,
		   struct amount_msat delivered)
{
	flow->success_prob = 1.0;
	flow->amounts = tal_arr(flow, struct amount_msat, tal_count(flow->path));
	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct chan_extra_half *h
			= get_chan_extra_half_by_chan(gossmap,
							chan_extra_map,
							flow->path[i],
							flow->dirs[i]);

		if(!h)
		{
			plugin_err(pay_plugin->plugin,"%s unexpected chan_extra_half is NULL",
				__PRETTY_FUNCTION__);
		}

		flow->amounts[i] = delivered;
		flow->success_prob
			*= edge_probability(h->known_min, h->known_max,
					    h->htlc_total,
					    delivered);

		if (!amount_msat_add_fee(&delivered,
					 flow_edge(flow, i)->base_fee,
					 flow_edge(flow, i)->proportional_fee))
		{
			plugin_err(pay_plugin->plugin,"%s fee overflow",
				__PRETTY_FUNCTION__);
		}
	}
}

/* Compute the prob. of success of a set of concurrent set of flows.
 *
 * IMPORTANT: this is not simply the multiplication of the prob. of success of
 * all of them, because they're not independent events. A flow that passes
 * through a channel c changes that channel's liquidity and then if another flow
 * passes through that same channel the previous liquidity change must be taken
 * into account.
 *
 * 	P(A and B) != P(A) * P(B),
 *
 * but
 *
 * 	P(A and B) = P(A) * P(B | A)
 *
 * also due to the linear form of P() we have
 *
 * 	P(A and B) = P(A + B)
 * 	*/
struct chan_inflight_flow
{
	struct amount_msat half[2];
};

// TODO(eduardo): here chan_extra_map should be const
// TODO(eduardo): here flows should be const
double flow_set_probability(
		struct flow ** flows,
		const struct gossmap *const gossmap,
		struct chan_extra_map * chan_extra_map)
{
	tal_t *this_ctx = tal(tmpctx,tal_t);
	double prob = 1.0;

	// TODO(eduardo): should it be better to use a map instead of an array
	// here?
	const size_t max_num_chans= gossmap_max_chan_idx(gossmap);
	struct chan_inflight_flow *in_flight
		= tal_arr(this_ctx,struct chan_inflight_flow,max_num_chans);

	for(size_t i=0;i<max_num_chans;++i)
	{
		in_flight[i].half[0]=in_flight[i].half[1]=AMOUNT_MSAT(0);
	}

	for(size_t i=0;i<tal_count(flows);++i)
	{
		const struct flow* f = flows[i];
		for(size_t j=0;j<tal_count(f->path);++j)
		{
			const struct chan_extra_half *h
				= get_chan_extra_half_by_chan(
						gossmap,
						chan_extra_map,
						f->path[j],
						f->dirs[j]);
			assert(h);

			const u32 c_idx = gossmap_chan_idx(gossmap,f->path[j]);
			const int c_dir = f->dirs[j];

			const struct amount_msat deliver = f->amounts[j];

			struct amount_msat prev_flow;
			if(!amount_msat_add(&prev_flow,h->htlc_total,in_flight[c_idx].half[c_dir]))
			{
				plugin_err(pay_plugin->plugin,"%s (line %d) in-flight amount_msat overflow",
					__PRETTY_FUNCTION__,
					__LINE__);
			}

			prob *= edge_probability(h->known_min,h->known_max,
						 prev_flow,deliver);

			if(!amount_msat_add(&in_flight[c_idx].half[c_dir],
					in_flight[c_idx].half[c_dir],
					deliver))
			{
				plugin_err(pay_plugin->plugin,"%s (line %d) in-flight amount_msat overflow",
					__PRETTY_FUNCTION__,
					__LINE__);
			}
		}
	}
	tal_free(this_ctx);
	return prob;
}

static int cmp_amount_msat(const struct amount_msat *a,
			   const struct amount_msat *b,
			   void *unused)
{
	if (amount_msat_less(*a, *b))
		return -1;
	if (amount_msat_greater(*a, *b))
		return 1;
	return 0;
}

static int cmp_amount_sat(const struct amount_sat *a,
			  const struct amount_sat *b,
			  void *unused)
{
	if (amount_sat_less(*a, *b))
		return -1;
	if (amount_sat_greater(*a, *b))
		return 1;
	return 0;
}

/* Get median feerates and capacities. */
static void get_medians(const struct gossmap *gossmap,
			struct amount_msat amount,
			struct amount_msat *median_capacity,
			struct amount_msat *median_fee)
{
	size_t num_caps, num_fees;
	struct amount_sat *caps;
	struct amount_msat *fees;

	caps = tal_arr(tmpctx, struct amount_sat,
		       gossmap_max_chan_idx(gossmap));
	fees = tal_arr(tmpctx, struct amount_msat,
		       gossmap_max_chan_idx(gossmap) * 2);
	num_caps = num_fees = 0;

	for (struct gossmap_chan *c = gossmap_first_chan(gossmap);
	     c;
	     c = gossmap_next_chan(gossmap, c)) {

		/* If neither feerate is set, it's not useful */
		if (!gossmap_chan_set(c, 0) && !gossmap_chan_set(c, 1))
			continue;

		/* Insufficient capacity?  Not useful */
		if (!gossmap_chan_get_capacity(gossmap, c, &caps[num_caps]))
			continue;
		if (amount_msat_greater_sat(amount, caps[num_caps]))
			continue;
		num_caps++;

		for (int dir = 0; dir <= 1; dir++) {
			if (!gossmap_chan_set(c, dir))
				continue;
			if (!amount_msat_fee(&fees[num_fees],
					     amount,
					     c->half[dir].base_fee,
					     c->half[dir].proportional_fee))
				continue;
			num_fees++;
		}
	}

	asort(caps, num_caps, cmp_amount_sat, NULL);
	/* If there are no channels, it doesn't really matter, but
	 * this avoids div by 0 */
	if (!num_caps)
		*median_capacity = amount;
	else if (!amount_sat_to_msat(median_capacity, caps[num_caps / 2]))
	{
		plugin_err(pay_plugin->plugin,"%s (line %d) amount_msat overflow",
			__PRETTY_FUNCTION__,
			__LINE__);
	}
	asort(fees, num_fees, cmp_amount_msat, NULL);
	if (!num_caps)
		*median_fee = AMOUNT_MSAT(0);
	else
		*median_fee = fees[num_fees / 2];
}

double derive_mu(const struct gossmap *gossmap,
		 struct amount_msat amount,
		 double frugality)
{
	struct amount_msat median_capacity, median_fee;
	double cap_plus_one;

	get_medians(gossmap, amount, &median_capacity, &median_fee);

	cap_plus_one = median_capacity.millisatoshis + 1; /* Raw: derive_mu */
	return -log((cap_plus_one - amount.millisatoshis) /* Raw: derive_mu */
		    / cap_plus_one)
		* frugality
		/* +1 in case median fee is zero... */
		/ (median_fee.millisatoshis + 1); /* Raw: derive_mu */
}

/* Get the fee cost associated to this directed channel.
 * Cost is expressed as PPM of the payment.
 *
 * Choose and integer `c_fee` to linearize the following fee function
 *
 *  	fee_msat = base_msat + floor(millionths*x_msat / 10^6)
 *
 * into
 *
 *  	fee_microsat = c_fee * x_sat
 *
 *  use `base_fee_penalty` to weight the base fee and `delay_feefactor` to
 *  weight the CLTV delay.
 *  */
s64 linear_fee_cost(
		const struct gossmap_chan *c,
		const int dir,
		double base_fee_penalty,
		double delay_feefactor)
{
	s64 pfee = c->half[dir].proportional_fee,
	    bfee = c->half[dir].base_fee,
	    delay = c->half[dir].delay;

	return pfee + bfee* base_fee_penalty+ delay*delay_feefactor;
}

struct amount_msat flow_set_fee(struct flow **flows)
{
	struct amount_msat fee = AMOUNT_MSAT(0);

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat this_fee;
		size_t n = tal_count(flows[i]->amounts);

		if (!amount_msat_sub(&this_fee,
				     flows[i]->amounts[0],
				     flows[i]->amounts[n-1]))
		{
			plugin_err(pay_plugin->plugin,"%s (line %d) amount_msat overflow",
				__PRETTY_FUNCTION__,
				__LINE__);
		}
		if(!amount_msat_add(&fee, this_fee,fee))
		{
			plugin_err(pay_plugin->plugin,"%s (line %d) amount_msat overflow",
				__PRETTY_FUNCTION__,
				__LINE__);
		}
	}
	return fee;
}

/* Helper to access the half chan at flow index idx */
const struct half_chan *flow_edge(const struct flow *flow, size_t idx)
{
	assert(idx < tal_count(flow->path));
	return &flow->path[idx]->half[flow->dirs[idx]];
}

#ifndef SUPERVERBOSE_ENABLED
#undef SUPERVERBOSE
#endif
