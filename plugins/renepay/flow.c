#include "config.h"
#include <assert.h>
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

static char *chan_extra_not_found_error(const tal_t *ctx,
					const struct short_channel_id *scid)
{
	return tal_fmt(ctx,
		       "chan_extra for scid=%s not found in chan_extra_map",
		       type_to_string(ctx, struct short_channel_id, scid));
}

bool chan_extra_is_busy(const struct chan_extra *const ce)
{
	if(ce==NULL)return false;
	return ce->half[0].num_htlcs || ce->half[1].num_htlcs;
}

const char *fmt_chan_extra_map(const tal_t *ctx,
			       struct chan_extra_map *chan_extra_map)
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
				   const struct chan_extra_map* chan_extra_map,
				   const struct short_channel_id_dir *scidd)
{
	const tal_t *this_ctx = tal(ctx,tal_t);
	const struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
							 scidd->scid);
	const struct chan_extra_half *ch;
	char *str = tal_strdup(ctx, "");
	char sep = '(';

	if (!ce) {
		// we have no information on this channel
		tal_append_fmt(&str, "()");
		goto finished;
	}

	ch = &ce->half[scidd->dir];
	if (ch->num_htlcs != 0) {
		tal_append_fmt(&str, "%c%s in %zu htlcs",
			       sep,
			       fmt_amount_msat(this_ctx, ch->htlc_total),
			       ch->num_htlcs);
		sep = ',';
	}
	/* Happens with local channels, where we're certain. */
	if (amount_msat_eq(ch->known_min, ch->known_max)) {
		tal_append_fmt(&str, "%cmin=max=%s",
			       sep,
			       fmt_amount_msat(this_ctx, ch->known_min));
		sep = ',';
	} else {
		if (amount_msat_greater(ch->known_min, AMOUNT_MSAT(0))) {
			tal_append_fmt(&str, "%cmin=%s",
				       sep,
				       fmt_amount_msat(this_ctx, ch->known_min));
			sep = ',';
	}
		if (!amount_msat_eq(ch->known_max, ce->capacity)) {
			tal_append_fmt(&str, "%cmax=%s",
				       sep,
				       fmt_amount_msat(this_ctx, ch->known_max));
			sep = ',';
		}
	}
	if (!streq(str, ""))
		tal_append_fmt(&str, ")");

	finished:
	tal_free(this_ctx);
	return str;
}

struct chan_extra *new_chan_extra(struct chan_extra_map *chan_extra_map,
				  const struct short_channel_id scid,
				  struct amount_msat capacity)
{
	assert(chan_extra_map);
	struct chan_extra *ce = tal(chan_extra_map, struct chan_extra);
	if (!ce)
		return ce;

	ce->scid = scid;
	ce->capacity=capacity;
	for (size_t i = 0; i <= 1; i++) {
		ce->half[i].num_htlcs = 0;
		ce->half[i].htlc_total = AMOUNT_MSAT(0);
		ce->half[i].known_min = AMOUNT_MSAT(0);
		ce->half[i].known_max = capacity;
	}
	if (!chan_extra_map_add(chan_extra_map, ce)) {
		return tal_free(ce);
	}

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
static bool chan_extra_adjust_half(const tal_t *ctx, struct chan_extra *ce,
				   int dir, char **fail)
{
	assert(ce);
	assert(dir==0 || dir==1);

	struct amount_msat new_known_max, new_known_min;

	if (!amount_msat_sub(&new_known_max, ce->capacity,
			     ce->half[!dir].known_min)) {
		if(fail)
		*fail = tal_fmt(
		    ctx, "cannot substract capacity=%s and known_min=%s",
		    type_to_string(ctx, struct amount_msat, &ce->capacity),
		    type_to_string(ctx, struct amount_msat,
				   &ce->half[!dir].known_min));
		goto function_fail;
	}
	if (!amount_msat_sub(&new_known_min, ce->capacity,
			     ce->half[!dir].known_max)) {
		if(fail)
		*fail = tal_fmt(
		    ctx, "cannot substract capacity=%s and known_max=%s",
		    type_to_string(ctx, struct amount_msat, &ce->capacity),
		    type_to_string(ctx, struct amount_msat,
				   &ce->half[!dir].known_max));
		goto function_fail;
	}

	ce->half[dir].known_max = new_known_max;
	ce->half[dir].known_min = new_known_min;
	return true;

	function_fail:
	return false;
}

/* Update the knowledge that this (channel,direction) can send x msat.*/
static bool chan_extra_can_send_(const tal_t *ctx, struct chan_extra *ce,
				 int dir, struct amount_msat x, char **fail)
{
	assert(ce);
	assert(dir==0 || dir==1);
	const tal_t *this_ctx = tal(ctx,tal_t);
	char *errmsg;
	if (amount_msat_greater(x, ce->capacity)) {
		if(fail)
		*fail = tal_fmt(
		    ctx,
		    "can send amount (%s) is larger than the "
		    "channel's capacity (%s)",
		    type_to_string(ctx, struct amount_msat, &x),
		    type_to_string(ctx, struct amount_msat, &ce->capacity));
		goto function_fail;
	}

	struct amount_msat known_min, known_max;

	// in case we fail, let's remember the original state
	known_min = ce->half[dir].known_min;
	known_max = ce->half[dir].known_max;

	ce->half[dir].known_min = amount_msat_max(ce->half[dir].known_min, x);
	ce->half[dir].known_max = amount_msat_max(ce->half[dir].known_max, x);

	if (!chan_extra_adjust_half(this_ctx, ce, !dir, &errmsg)) {
		if(fail)
		*fail = tal_fmt(ctx, "chan_extra_adjust_half failed: %s",
				errmsg);

		goto restore_and_fail;
	}
	return true;

	restore_and_fail:
	// we fail, thus restore the original state
	ce->half[dir].known_min = known_min;
	ce->half[dir].known_max = known_max;

	function_fail:
	return false;
}

bool chan_extra_can_send(const tal_t *ctx,
			 struct chan_extra_map *chan_extra_map,
			 const struct short_channel_id_dir *scidd,
			 char **fail)
{
	assert(scidd);
	assert(chan_extra_map);
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce) {
		if(fail)
		*fail = chan_extra_not_found_error(ctx, &scidd->scid);
		goto function_fail;
	}
	if (!chan_extra_can_send_(ctx, ce, scidd->dir,
				  ce->half[scidd->dir].htlc_total, fail)) {
		goto function_fail;
	}
	return true;

	function_fail:
	return false;
}

/* Update the knowledge that this (channel,direction) cannot send.*/
bool chan_extra_cannot_send(const tal_t *ctx,
			    struct chan_extra_map *chan_extra_map,
			    const struct short_channel_id_dir *scidd,
			    char **fail)
{
	assert(scidd);
	assert(chan_extra_map);
	const tal_t *this_ctx = tal(ctx,tal_t);
	char *errmsg;
	struct amount_msat x;
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map,
						   scidd->scid);
	if(!ce)
	{
		if(fail)
		*fail = chan_extra_not_found_error(ctx, &scidd->scid);
		goto function_fail;
	}

	/* Note: sent is already included in htlc_total! */
	if (!amount_msat_sub(&x, ce->half[scidd->dir].htlc_total,
			     AMOUNT_MSAT(1))) {
		if(fail)
		*fail = tal_fmt(
		    ctx, "htlc_total=%s is less than 0msats in channel %s",
		    type_to_string(this_ctx, struct amount_msat,
				   &ce->half[scidd->dir].htlc_total),
		    type_to_string(this_ctx, struct short_channel_id,
				   &scidd->scid));
		goto function_fail;
	}

	struct amount_msat known_min, known_max;
	// in case we fail, let's remember the original state
	known_min = ce->half[scidd->dir].known_min;
	known_max = ce->half[scidd->dir].known_max;

	/* If we "knew" the capacity was at least this, we just showed we're wrong! */
	if (amount_msat_less(x, ce->half[scidd->dir].known_min)) {
		/* Skip to half of x, since we don't know (rounds down) */
		ce->half[scidd->dir].known_min = amount_msat_div(x, 2);
	}

	ce->half[scidd->dir].known_max = amount_msat_min(ce->half[scidd->dir].known_max,x);

	if(!chan_extra_adjust_half(this_ctx, ce,!scidd->dir,&errmsg))
	{
		if(fail)
		*fail = tal_fmt(ctx, "chan_extra_adjust_half failed: %s",
				errmsg);
		goto restore_and_fail;
	}
	tal_free(this_ctx);
	return true;

	restore_and_fail:
	// we fail, thus restore the original state
	ce->half[scidd->dir].known_min = known_min;
	ce->half[scidd->dir].known_max = known_max;

	function_fail:
	tal_free(this_ctx);
	return false;
}
/* Update the knowledge that this (channel,direction) has liquidity x.*/
static bool chan_extra_set_liquidity_(const tal_t *ctx, struct chan_extra *ce,
				      int dir, struct amount_msat x,
				      char **fail)
{
	assert(ce);
	assert(dir==0 || dir==1);
	const tal_t *this_ctx = tal(ctx,tal_t);
	char *errmsg;
	if (amount_msat_greater(x, ce->capacity)) {
		if(fail)
		*fail = tal_fmt(
		    ctx,
		    "tried to set liquidity (%s) to a value greater than "
		    "channel's capacity (%s)",
		    type_to_string(this_ctx, struct amount_msat, &x),
		    type_to_string(this_ctx, struct amount_msat, &ce->capacity));
		goto function_fail;
	}

	// in case we fail, let's remember the original state
	struct amount_msat known_min, known_max;
	known_min = ce->half[dir].known_min;
	known_max = ce->half[dir].known_max;

	ce->half[dir].known_min = x;
	ce->half[dir].known_max = x;

	if (!chan_extra_adjust_half(this_ctx, ce, !dir, &errmsg)) {
		if(fail)
		*fail = tal_fmt(ctx, "chan_extra_adjust_half failed: %s",
				errmsg);
		goto restore_and_fail;
	}
	tal_free(this_ctx);
	return true;

	restore_and_fail:
	// we fail, thus restore the original state
	ce->half[dir].known_min = known_min;
	ce->half[dir].known_max = known_max;

	function_fail:
	tal_free(this_ctx);
	return false;
}
bool chan_extra_set_liquidity(const tal_t *ctx,
			      struct chan_extra_map *chan_extra_map,
			      const struct short_channel_id_dir *scidd,
			      struct amount_msat x, char **fail)
{
	assert(scidd);
	assert(chan_extra_map);
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce) {
		if(fail)
		*fail = chan_extra_not_found_error(ctx, &scidd->scid);
		goto function_fail;
	}
	if (!chan_extra_set_liquidity_(ctx, ce, scidd->dir, x, fail)) {
		goto function_fail;
	}
	return true;

	function_fail:
	return false;
}
/* Update the knowledge that this (channel,direction) has sent x msat.*/
bool chan_extra_sent_success(const tal_t *ctx,
			     struct chan_extra_map *chan_extra_map,
			     const struct short_channel_id_dir *scidd,
			     struct amount_msat x, char **fail)
{
	assert(scidd);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	char *errmsg;

	// if we sent amount x, it first means that all htlcs on this channel fit
	// in the liquidity
	if (!chan_extra_can_send(this_ctx, chan_extra_map, scidd, &errmsg)) {
		if (fail)
		*fail = tal_fmt(ctx, "chan_extra_can_send failed: %s",
				errmsg);
		goto function_fail;
	}

	struct chan_extra *ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce) {
		if(fail)
		*fail = chan_extra_not_found_error(ctx, &scidd->scid);
		goto function_fail;
	}

	if (amount_msat_greater(x, ce->capacity)) {
		if(fail)
		*fail = tal_fmt(
		    ctx,
		    "sent success (%s) is larger than the "
		    "channel's capacity (%s)",
		    type_to_string(this_ctx, struct amount_msat, &x),
		    type_to_string(this_ctx, struct amount_msat, &ce->capacity));
		goto function_fail;
	}

	// in case we fail, let's remember the original state
	struct amount_msat known_min, known_max;
	known_min = ce->half[scidd->dir].known_min;
	known_max = ce->half[scidd->dir].known_max;

	struct amount_msat new_a, new_b;

	if (!amount_msat_sub(&new_a, ce->half[scidd->dir].known_min, x))
		new_a = AMOUNT_MSAT(0);
	if (!amount_msat_sub(&new_b, ce->half[scidd->dir].known_max, x))
		new_b = AMOUNT_MSAT(0);

	ce->half[scidd->dir].known_min = new_a;
	ce->half[scidd->dir].known_max = new_b;

	if (!chan_extra_adjust_half(this_ctx, ce, !scidd->dir, &errmsg)) {
		if(fail)
		*fail =
		    tal_fmt(ctx, "chan_extra_adjust_half failed: %s", errmsg);
		goto restore_and_fail;
	}
	tal_free(this_ctx);
	return true;

	// we fail, thus restore the original state
	restore_and_fail:
	ce->half[scidd->dir].known_min = known_min;
	ce->half[scidd->dir].known_max = known_max;

	function_fail:
	tal_free(this_ctx);
	return false;
}
/* Forget a bit about this (channel,direction) state. */
static bool chan_extra_relax(const tal_t *ctx, struct chan_extra *ce, int dir,
			     struct amount_msat down, struct amount_msat up,
			     char **fail)
{
	assert(ce);
	assert(dir==0 || dir==1);
	const tal_t *this_ctx = tal(ctx,tal_t);
	char *errmsg;
	struct amount_msat new_a, new_b;

	if (!amount_msat_sub(&new_a, ce->half[dir].known_min, down))
		new_a = AMOUNT_MSAT(0);
	if (!amount_msat_add(&new_b, ce->half[dir].known_max, up))
		new_b = ce->capacity;
	new_b = amount_msat_min(new_b, ce->capacity);

	// in case we fail, let's remember the original state
	struct amount_msat known_min, known_max;
	known_min = ce->half[dir].known_min;
	known_max = ce->half[dir].known_max;

	ce->half[dir].known_min = new_a;
	ce->half[dir].known_max = new_b;

	if (!chan_extra_adjust_half(this_ctx,ce, !dir, &errmsg)) {
		if(fail)
		*fail = tal_fmt(ctx, "chan_extra_adjust_half failed: %s",
				errmsg);
		goto restore_and_fail;
	}
	tal_free(this_ctx);
	return true;

	// we fail, thus restore the original state
	restore_and_fail:
	ce->half[dir].known_min = known_min;
	ce->half[dir].known_max = known_max;

	tal_free(this_ctx);
	return false;
}

/* Forget the channel information by a fraction of the capacity. */
bool chan_extra_relax_fraction(const tal_t *ctx, struct chan_extra *ce,
			       double fraction, char **fail)
{
	assert(ce);
	assert(fraction>=0);
	/* Allow to have values greater than 1 to indicate full relax. */
	// assert(fraction<=1);
	const tal_t *this_ctx = tal(ctx,tal_t);
	char *errmsg;
	fraction = fabs(fraction);     // this number is always non-negative
	fraction = MIN(1.0, fraction); // this number cannot be greater than 1.
	struct amount_msat delta =
	    amount_msat(ce->capacity.millisatoshis * fraction); /* Raw: get a fraction of the capacity */

	/* The direction here is not important because the 'down' and the 'up'
	 * limits are changed by the same amount.
	 * Notice that if chan[0] with capacity C changes from (a,b) to
	 * (a-d,b+d) then its counterpart chan[1] changes from (C-b,C-a) to
	 * (C-b-d,C-a+d), hence both dirs are applied the same transformation.
	 */
	if (!chan_extra_relax(this_ctx, ce, /*dir=*/0, delta, delta, &errmsg)) {
		if(fail)
		*fail = tal_fmt(ctx, "chan_extra_relax failed: %s", errmsg);
		goto function_fail;
	}
	tal_free(this_ctx);
	return true;

	function_fail:
	tal_free(this_ctx);
	return false;
}

/* Returns either NULL, or an entry from the hash */
struct chan_extra_half *
get_chan_extra_half_by_scid(struct chan_extra_map *chan_extra_map,
			    const struct short_channel_id_dir *scidd)
{
	assert(scidd);
	assert(chan_extra_map);
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
	assert(chan);
	assert(dir==0 || dir==1);
	assert(gossmap);
	assert(chan_extra_map);
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
get_chan_extra_half_by_chan_verify(const struct gossmap *gossmap,
				   struct chan_extra_map *chan_extra_map,
				   const struct gossmap_chan *chan, int dir)
{
	assert(chan);
	assert(dir==0 || dir==1);
	assert(gossmap);
	assert(chan_extra_map);
	struct short_channel_id_dir scidd;

	scidd.scid = gossmap_chan_scid(gossmap, chan);
	scidd.dir = dir;
	struct chan_extra_half *h =
	    get_chan_extra_half_by_scid(chan_extra_map, &scidd);
	if (!h) {
		struct amount_sat cap;
		struct amount_msat cap_msat;

		if (!gossmap_chan_get_capacity(gossmap, chan, &cap) ||
		    !amount_sat_to_msat(&cap_msat, cap)) {
			return NULL;
		}
		h = &new_chan_extra(chan_extra_map, scidd.scid, cap_msat)
			 ->half[scidd.dir];
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
static double edge_probability(const tal_t *ctx, struct amount_msat min,
			       struct amount_msat max,
			       struct amount_msat in_flight,
			       struct amount_msat f, char **fail)
{
	assert(amount_msat_less_eq(min,max));
	assert(amount_msat_less_eq(in_flight,max));

	const tal_t *this_ctx = tal(ctx, tal_t);

	const struct amount_msat one = AMOUNT_MSAT(1);
	struct amount_msat B=max; // =  max +1 - in_flight

	// one past the last known value, makes computations simpler
	if(!amount_msat_add(&B,B,one))
	{
		if(fail)
		*fail = tal_fmt(ctx,"addition overflow");
		goto function_fail;
	}
	// in_flight cannot be greater than max
	if(!amount_msat_sub(&B,B,in_flight))
	{
		if(fail)
		*fail = tal_fmt(ctx,
			"in_flight=%s cannot be greater than known_max+1=%s",
			type_to_string(this_ctx, struct amount_msat, &in_flight),
			type_to_string(this_ctx, struct amount_msat, &B)
		);
		goto function_fail;
	}
	struct amount_msat A=min; // = MAX(0,min-in_flight);

	if(!amount_msat_sub(&A,A,in_flight))
		A = AMOUNT_MSAT(0);

	struct amount_msat denominator; // = B-A

	// B cannot be smaller than or equal A
	if(!amount_msat_sub(&denominator,B,A) || amount_msat_less_eq(B,A))
	{
		if(fail)
		*fail = tal_fmt(ctx,"known_max+1=%s must be greater than known_min=%s",
			type_to_string(this_ctx, struct amount_msat, &B),
			type_to_string(this_ctx, struct amount_msat, &A));
		goto function_fail;
	}
	struct amount_msat numerator; // MAX(0,B-f)

	if(!amount_msat_sub(&numerator,B,f))
		numerator = AMOUNT_MSAT(0);

	tal_free(this_ctx);
	return amount_msat_less_eq(f,A) ? 1.0 : amount_msat_ratio(numerator,denominator);

	function_fail:
	tal_free(this_ctx);
	return -1;
}


// TODO(eduardo): remove this function, is a duplicate
/* If this function fails it means there is a bad data inconsistency and the
 * program should stop. */
bool remove_completed_flow(const tal_t *ctx, const struct gossmap *gossmap,
			   struct chan_extra_map *chan_extra_map,
			   struct flow *flow, char **fail)
{
	assert(flow);
	assert(gossmap);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	for (size_t i = 0; i < tal_count(flow->path); i++) {
		struct chan_extra_half *h = get_chan_extra_half_by_chan(gossmap,
							       chan_extra_map,
							       flow->path[i],
							       flow->dirs[i]);
		if (!amount_msat_sub(&h->htlc_total, h->htlc_total, flow->amounts[i]))
		{
			if(fail)
			*fail =
			    tal_fmt(ctx,
				    "could not substract HTLC amounts, "
				    "total htlc amount = %s, "
				    "flow->amounts[%zu] = %s.",
				    type_to_string(this_ctx, struct amount_msat,
						   &h->htlc_total),
				    i,
				    type_to_string(this_ctx, struct amount_msat,
						   &flow->amounts[i]));
			goto function_fail;
		}
		if (h->num_htlcs == 0)
		{
			if(fail)
			*fail =
			    tal_fmt(ctx, "could not decrease HTLC count.");
			goto function_fail;
		}
		h->num_htlcs--;
	}
	tal_free(this_ctx);
	return true;

	function_fail:
	tal_free(this_ctx);
	return false;
}
// TODO(eduardo): remove this function, is a duplicate
/* If this function fails it means there is a bad data inconsistency and the
 * program should stop. */
bool remove_completed_flowset(const tal_t *ctx, const struct gossmap *gossmap,
			      struct chan_extra_map *chan_extra_map,
			      struct flow **flows, char **fail)
{
	assert(flows);
	assert(gossmap);
	assert(chan_extra_map);
	for (size_t i = 0; i < tal_count(flows); ++i) {
		if (!remove_completed_flow(ctx, gossmap, chan_extra_map, flows[i],
					   fail)) {
			return false;
		}
	}
	return true;
}

// TODO(eduardo): remove this function, is a duplicate
bool commit_flow(const tal_t *ctx, const struct gossmap *gossmap,
		 struct chan_extra_map *chan_extra_map, struct flow *flow,
		 char **fail)
{
	assert(flow);
	assert(gossmap);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	for (size_t i = 0; i < tal_count(flow->path); i++) {
		struct chan_extra_half *h = get_chan_extra_half_by_chan(gossmap,
							       chan_extra_map,
							       flow->path[i],
							       flow->dirs[i]);
		if (!amount_msat_add(&h->htlc_total, h->htlc_total, flow->amounts[i]))
		{
			if (fail)
			*fail =
			    tal_fmt(ctx,
				    "could not add HTLC amounts, "
				    "flow->amounts[%zu] = %s.",
				    i,
				    type_to_string(this_ctx, struct amount_msat,
						   &flow->amounts[i]));
			goto function_fail;
		}
		h->num_htlcs++;
	}
	tal_free(this_ctx);
	return true;

	function_fail:
	tal_free(this_ctx);
	return false;
}
// TODO(eduardo): remove this function, is a duplicate
/* Returns the number of flows successfully commited. */
size_t commit_flowset(const tal_t *ctx, const struct gossmap *gossmap,
		    struct chan_extra_map *chan_extra_map, struct flow **flows,
		    char **fail)
{
	assert(flows);
	assert(gossmap);
	assert(chan_extra_map);
	const size_t N = tal_count(flows);
	for(size_t i=0; i<N; ++i)
	{
		if (!commit_flow(ctx, gossmap, chan_extra_map, flows[i],
				 fail)) {
			return i;
		}
	}
	return N;
}

/* Helper function to fill in amounts and success_prob for flow
 *
 * IMPORTANT: here we do not commit flows to chan_extra, flows are commited
 * after we send those htlc.
 *
 * IMPORTANT: flow->success_prob is misleading, because that's the prob. of
 * success provided that there are no other flows in the current MPP flow set.
 * */
bool flow_complete(const tal_t *ctx, struct flow *flow,
		   const struct gossmap *gossmap,
		   struct chan_extra_map *chan_extra_map,
		   struct amount_msat delivered, char **fail)
{
	assert(flow);
	assert(gossmap);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	char *errmsg;

	flow->success_prob = 1.0;
	flow->amounts =
	    tal_arr(flow, struct amount_msat, tal_count(flow->path));

	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		const struct chan_extra_half *h = get_chan_extra_half_by_chan(
		    gossmap, chan_extra_map, flow->path[i], flow->dirs[i]);

		if (!h) {
			if (fail)
			*fail = tal_fmt(ctx,
					"channel not found in chan_extra_map");
			goto function_fail;
		}

		flow->amounts[i] = delivered;
		double prob =
		    edge_probability(this_ctx, h->known_min, h->known_max,
				     h->htlc_total, delivered, &errmsg);
		if(prob<0){
			if (fail)
			*fail = tal_fmt(ctx,"edge_probability failed: %s",
				errmsg);
			goto function_fail;
		}
		flow->success_prob *= prob;

		if (!amount_msat_add_fee(
			&delivered, flow_edge(flow, i)->base_fee,
			flow_edge(flow, i)->proportional_fee)) {
			if (fail)
			*fail = tal_fmt(ctx, "fee overflow");
			goto function_fail;
		}
	}
	tal_free(this_ctx);
	return true;

	function_fail:
	tal_free(this_ctx);
	return false;
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
double flowset_probability(const tal_t *ctx, struct flow **flows,
			   const struct gossmap *const gossmap,
			   struct chan_extra_map *chan_extra_map, char **fail)
{
	assert(flows);
	assert(gossmap);
	assert(chan_extra_map);
	tal_t *this_ctx = tal(ctx, tal_t);
	char *errmsg;
	double prob = 1.0;

	// TODO(eduardo): should it be better to use a map instead of an array
	// here?
	const size_t max_num_chans = gossmap_max_chan_idx(gossmap);
	struct chan_inflight_flow *in_flight =
	    tal_arr(this_ctx, struct chan_inflight_flow, max_num_chans);

	for (size_t i = 0; i < max_num_chans; ++i) {
		in_flight[i].half[0] = in_flight[i].half[1] = AMOUNT_MSAT(0);
	}

	for (size_t i = 0; i < tal_count(flows); ++i) {
		const struct flow *f = flows[i];
		for (size_t j = 0; j < tal_count(f->path); ++j) {
			const struct chan_extra_half *h =
			    get_chan_extra_half_by_chan(gossmap, chan_extra_map,
							f->path[j], f->dirs[j]);
			if (!h) {
				if (fail)
				*fail = tal_fmt(
				    ctx,
				    "channel not found in chan_extra_map");
				goto function_fail;
			}
			const u32 c_idx = gossmap_chan_idx(gossmap, f->path[j]);
			const int c_dir = f->dirs[j];

			const struct amount_msat deliver = f->amounts[j];

			struct amount_msat prev_flow;
			if (!amount_msat_add(&prev_flow, h->htlc_total,
					     in_flight[c_idx].half[c_dir])) {
				if (fail)
				*fail = tal_fmt(
				    ctx, "in-flight amount_msat overflow");
				goto function_fail;
			}

			double edge_prob =
			    edge_probability(this_ctx, h->known_min, h->known_max,
					     prev_flow, deliver, &errmsg);
			if (edge_prob < 0) {
				if (fail)
				*fail = tal_fmt(ctx,
						"edge_probability failed: %s",
						errmsg);
				goto function_fail;
			}
			prob *= edge_prob;

			if (!amount_msat_add(&in_flight[c_idx].half[c_dir],
					     in_flight[c_idx].half[c_dir],
					     deliver)) {
				if (fail)
				*fail = tal_fmt(
				    ctx, "in-flight amount_msat overflow");
				goto function_fail;
			}
		}
	}
	tal_free(this_ctx);
	return prob;

	function_fail:
	tal_free(this_ctx);
	return -1;
}

bool flowset_fee(struct amount_msat *ret, struct flow **flows)
{
	assert(ret);
	assert(flows);
	struct amount_msat fee = AMOUNT_MSAT(0);

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat this_fee;
		size_t n = tal_count(flows[i]->amounts);

		if (!amount_msat_sub(&this_fee, flows[i]->amounts[0],
				     flows[i]->amounts[n - 1])) {
			return false;
		}
		if (!amount_msat_add(&fee, this_fee, fee)) {
			return false;
		}
	}
	*ret = fee;
	return true;
}

/* Helper to access the half chan at flow index idx */
const struct half_chan *flow_edge(const struct flow *flow, size_t idx)
{
	assert(flow);
	assert(idx < tal_count(flow->path));
	return &flow->path[idx]->half[flow->dirs[idx]];
}

#ifndef SUPERVERBOSE_ENABLED
#undef SUPERVERBOSE
#endif
