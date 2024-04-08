#include "config.h"
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <common/overflows.h>
#include <common/utils.h>
#include <math.h>
#include <plugins/renepay/chan_extra.h>

bool chan_extra_is_busy(const struct chan_extra *const ce)
{
	if (ce == NULL)
		return false;
	return ce->half[0].num_htlcs || ce->half[1].num_htlcs;
}

const char *fmt_chan_extra_map(const tal_t *ctx,
			       struct chan_extra_map *chan_extra_map)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	char *buff = tal_fmt(ctx, "Uncertainty network:\n");
	struct chan_extra_map_iter it;
	for (struct chan_extra *ch = chan_extra_map_first(chan_extra_map, &it);
	     ch; ch = chan_extra_map_next(chan_extra_map, &it)) {
		const char *scid_str = fmt_short_channel_id(this_ctx, ch->scid);
		for (int dir = 0; dir < 2; ++dir) {
			tal_append_fmt(
			    &buff, "%s[%d]:(%s,%s)\n", scid_str, dir,
			    fmt_amount_msat(this_ctx, ch->half[dir].known_min),
			    fmt_amount_msat(this_ctx, ch->half[dir].known_max));
		}
	}
	tal_free(this_ctx);
	return buff;
}

const char *fmt_chan_extra_details(const tal_t *ctx,
				   const struct chan_extra_map *chan_extra_map,
				   const struct short_channel_id_dir *scidd)
{
	const tal_t *this_ctx = tal(ctx, tal_t);
	const struct chan_extra *ce =
	    chan_extra_map_get(chan_extra_map, scidd->scid);
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
		tal_append_fmt(&str, "%c%s in %zu htlcs", sep,
			       fmt_amount_msat(this_ctx, ch->htlc_total),
			       ch->num_htlcs);
		sep = ',';
	}
	/* Happens with local channels, where we're certain. */
	if (amount_msat_eq(ch->known_min, ch->known_max)) {
		tal_append_fmt(&str, "%cmin=max=%s", sep,
			       fmt_amount_msat(this_ctx, ch->known_min));
		sep = ',';
	} else {
		if (amount_msat_greater(ch->known_min, AMOUNT_MSAT(0))) {
			tal_append_fmt(
			    &str, "%cmin=%s", sep,
			    fmt_amount_msat(this_ctx, ch->known_min));
			sep = ',';
		}
		if (!amount_msat_eq(ch->known_max, ce->capacity)) {
			tal_append_fmt(
			    &str, "%cmax=%s", sep,
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
	ce->capacity = capacity;
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

/* Based on the knowledge that we have and HTLCs, returns the greatest
 * amount that we can send through this channel. */
enum renepay_errorcode channel_liquidity(struct amount_msat *liquidity,
					 const struct gossmap *gossmap,
					 struct chan_extra_map *chan_extra_map,
					 const struct gossmap_chan *chan,
					 const int dir)
{
	const struct chan_extra_half *h =
	    get_chan_extra_half_by_chan(gossmap, chan_extra_map, chan, dir);
	if (!h)
		return RENEPAY_CHANNEL_NOT_FOUND;
	struct amount_msat value_liquidity = h->known_max;
	if (!amount_msat_sub(&value_liquidity, value_liquidity, h->htlc_total))
		return RENEPAY_AMOUNT_OVERFLOW;
	*liquidity = value_liquidity;
	return RENEPAY_NOERROR;
}

/* Checks BOLT 7 HTLC fee condition:
 *	recv >= base_fee + (send*proportional_fee)/1000000 */
bool check_fee_inequality(struct amount_msat recv, struct amount_msat send,
			  u64 base_fee, u64 proportional_fee)
{
	// nothing to forward, any incoming amount is good
	if (amount_msat_zero(send))
		return true;
	// FIXME If this addition fails we return false. The caller will not be
	// able to know that there was an addition overflow, he will just assume
	// that the fee inequality was not satisfied.
	if (!amount_msat_add_fee(&send, base_fee, proportional_fee))
		return false;
	return amount_msat_greater_eq(recv, send);
}

/* Let `recv` be the maximum amount this channel can receive, this function
 * computes the maximum amount this channel can forward `send`.
 * From BOLT7 specification wee need to satisfy the following inequality:
 *
 *	recv-send >= base_fee + floor(send*proportional_fee/1000000)
 *
 * That is equivalent to have
 *
 *	send <= Bound(recv,send)
 *
 * where
 *
 *	Bound(recv, send) = ((recv - base_fee)*1000000 + (send*proportional_fee)
 *% 1000000)/(proportional_fee+1000000)
 *
 * However the quantity we want to determine, `send`, appears on both sides of
 * the equation. However the term `send*proportional_fee) % 1000000` only
 * contributes by increasing the bound by at most one so that we can neglect
 * the extra term and use instead
 *
 *	Bound_simple(recv) = ((recv -
 *base_fee)*1000000)/(proportional_fee+1000000)
 *
 * as the upper bound for `send`. Formally one can check that
 *
 *	Bound_simple(recv) <= Bound(recv, send) < Bound_simple(recv) + 2
 *
 * So that if one wishes to find the very highest value of `send` that
 * satisfies
 *
 *	send <= Bound(recv, send)
 *
 * it is enough to compute
 *
 *	send = Bound_simple(recv)
 *
 *  which already satisfies the fee equation and then try to go higher
 *  with send+1, send+2, etc. But we know that it is enough to try up to
 *  send+1 because Bound(recv, send) < Bound_simple(recv) + 2.
 * */
enum renepay_errorcode channel_maximum_forward(struct amount_msat *max_forward,
					       const struct gossmap_chan *chan,
					       const int dir,
					       struct amount_msat recv)
{
	const u64 b = chan->half[dir].base_fee,
		  p = chan->half[dir].proportional_fee;

	const u64 one_million = 1000000;
	u64 x_msat =
	    recv.millisatoshis; /* Raw: need to invert the fee equation */

	// special case, when recv - base_fee <= 0, we cannot forward anything
	if (x_msat <= b) {
		*max_forward = amount_msat(0);
		return RENEPAY_NOERROR;
	}

	x_msat -= b;

	if (mul_overflows_u64(one_million, x_msat))
		return RENEPAY_AMOUNT_OVERFLOW;

	struct amount_msat best_send =
	    AMOUNT_MSAT_INIT((one_million * x_msat) / (one_million + p));

	/* Try to increase the value we send (up tp the last millisat) until we
	 * fail to fulfill the fee inequality. It takes only one iteration
	 * though. */
	for (size_t i = 0; i < 10; ++i) {
		struct amount_msat next_send;
		if (!amount_msat_add(&next_send, best_send, amount_msat(1)))
			return RENEPAY_AMOUNT_OVERFLOW;

		if (check_fee_inequality(recv, next_send, b, p))
			best_send = next_send;
		else
			break;
	}
	*max_forward = best_send;
	return RENEPAY_NOERROR;
}

/* This helper function preserves the uncertainty network invariant after the
 * knowledge is updated. It assumes that the (channel,!dir) knowledge is
 * correct. */
static enum renepay_errorcode chan_extra_adjust_half(struct chan_extra *ce,
						     int dir)
{
	assert(ce);
	assert(dir == 0 || dir == 1);

	struct amount_msat new_known_max, new_known_min;

	if (!amount_msat_sub(&new_known_max, ce->capacity,
			     ce->half[!dir].known_min) ||
	    !amount_msat_sub(&new_known_min, ce->capacity,
			     ce->half[!dir].known_max))
		return RENEPAY_AMOUNT_OVERFLOW;

	ce->half[dir].known_max = new_known_max;
	ce->half[dir].known_min = new_known_min;
	return RENEPAY_NOERROR;
}

/* Update the knowledge that this (channel,direction) can send x msat.*/
static enum renepay_errorcode
chan_extra_can_send_(struct chan_extra *ce, int dir, struct amount_msat x)
{
	assert(ce);
	assert(dir == 0 || dir == 1);
	enum renepay_errorcode err;

	if (amount_msat_greater(x, ce->capacity))
		return RENEPAY_PRECONDITION_ERROR;

	struct amount_msat known_min, known_max;

	// in case we fail, let's remember the original state
	known_min = ce->half[dir].known_min;
	known_max = ce->half[dir].known_max;

	ce->half[dir].known_min = amount_msat_max(ce->half[dir].known_min, x);
	ce->half[dir].known_max = amount_msat_max(ce->half[dir].known_max, x);

	err = chan_extra_adjust_half(ce, !dir);
	if (err != RENEPAY_NOERROR)
		goto restore_and_fail;

	return RENEPAY_NOERROR;

restore_and_fail:
	// we fail, thus restore the original state
	ce->half[dir].known_min = known_min;
	ce->half[dir].known_max = known_max;
	return err;
}

enum renepay_errorcode
chan_extra_can_send(struct chan_extra_map *chan_extra_map,
		    const struct short_channel_id_dir *scidd)
{
	assert(scidd);
	assert(chan_extra_map);
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce)
		return RENEPAY_CHANNEL_NOT_FOUND;
	return chan_extra_can_send_(ce, scidd->dir,
				    ce->half[scidd->dir].htlc_total);
}

/* Update the knowledge that this (channel,direction) cannot send.*/
enum renepay_errorcode
chan_extra_cannot_send(struct chan_extra_map *chan_extra_map,
		       const struct short_channel_id_dir *scidd)
{
	assert(scidd);
	assert(chan_extra_map);
	struct amount_msat x;
	enum renepay_errorcode err;
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce)
		return RENEPAY_CHANNEL_NOT_FOUND;

	/* Note: sent is already included in htlc_total! */
	if (!amount_msat_sub(&x, ce->half[scidd->dir].htlc_total,
			     AMOUNT_MSAT(1)))
		return RENEPAY_AMOUNT_OVERFLOW;

	struct amount_msat known_min, known_max;
	// in case we fail, let's remember the original state
	known_min = ce->half[scidd->dir].known_min;
	known_max = ce->half[scidd->dir].known_max;

	/* If we "knew" the capacity was at least this, we just showed we're
	 * wrong! */
	if (amount_msat_less(x, ce->half[scidd->dir].known_min)) {
		/* Skip to half of x, since we don't know (rounds down) */
		ce->half[scidd->dir].known_min = amount_msat_div(x, 2);
	}

	ce->half[scidd->dir].known_max =
	    amount_msat_min(ce->half[scidd->dir].known_max, x);

	err = chan_extra_adjust_half(ce, !scidd->dir);
	if (err != RENEPAY_NOERROR)
		goto restore_and_fail;
	return err;

restore_and_fail:
	// we fail, thus restore the original state
	ce->half[scidd->dir].known_min = known_min;
	ce->half[scidd->dir].known_max = known_max;
	return err;
}

/* Update the knowledge that this (channel,direction) has liquidity x.*/
// FIXME for being this low level API, I thinkg it's too much to have verbose
// error messages
static enum renepay_errorcode
chan_extra_set_liquidity_(struct chan_extra *ce, int dir, struct amount_msat x)
{
	assert(ce);
	assert(dir == 0 || dir == 1);
	enum renepay_errorcode err;

	if (amount_msat_greater(x, ce->capacity))
		return RENEPAY_PRECONDITION_ERROR;

	// in case we fail, let's remember the original state
	struct amount_msat known_min, known_max;
	known_min = ce->half[dir].known_min;
	known_max = ce->half[dir].known_max;

	ce->half[dir].known_min = x;
	ce->half[dir].known_max = x;

	err = chan_extra_adjust_half(ce, !dir);
	if (err != RENEPAY_NOERROR)
		goto restore_and_fail;
	return err;

restore_and_fail:
	// we fail, thus restore the original state
	ce->half[dir].known_min = known_min;
	ce->half[dir].known_max = known_max;
	return err;
}

enum renepay_errorcode
chan_extra_set_liquidity(struct chan_extra_map *chan_extra_map,
			 const struct short_channel_id_dir *scidd,
			 struct amount_msat x)
{
	assert(scidd);
	assert(chan_extra_map);
	struct chan_extra *ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce)
		return RENEPAY_CHANNEL_NOT_FOUND;

	return chan_extra_set_liquidity_(ce, scidd->dir, x);
}

/* Update the knowledge that this (channel,direction) has sent x msat.*/
enum renepay_errorcode
chan_extra_sent_success(struct chan_extra_map *chan_extra_map,
			const struct short_channel_id_dir *scidd,
			struct amount_msat x)
{
	assert(scidd);
	assert(chan_extra_map);

	struct chan_extra *ce = chan_extra_map_get(chan_extra_map, scidd->scid);
	if (!ce)
		return RENEPAY_CHANNEL_NOT_FOUND;

	// if we sent amount x, it first means that all htlcs on this channel
	// fit in the liquidity
	enum renepay_errorcode err;
	err = chan_extra_can_send(chan_extra_map, scidd);
	if (err != RENEPAY_NOERROR)
		return err;

	if (amount_msat_greater(x, ce->capacity))
		return RENEPAY_PRECONDITION_ERROR;

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

	err = chan_extra_adjust_half(ce, !scidd->dir);
	if (err != RENEPAY_NOERROR)
		goto restore_and_fail;

	return err;

// we fail, thus restore the original state
restore_and_fail:
	ce->half[scidd->dir].known_min = known_min;
	ce->half[scidd->dir].known_max = known_max;
	return err;
}

/* Forget a bit about this (channel,direction) state. */
static enum renepay_errorcode chan_extra_relax(struct chan_extra *ce, int dir,
					       struct amount_msat down,
					       struct amount_msat up)
{
	assert(ce);
	assert(dir == 0 || dir == 1);
	struct amount_msat new_a, new_b;
	enum renepay_errorcode err;

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

	err = chan_extra_adjust_half(ce, !dir);
	if (err != RENEPAY_NOERROR)
		goto restore_and_fail;
	return err;

// we fail, thus restore the original state
restore_and_fail:
	ce->half[dir].known_min = known_min;
	ce->half[dir].known_max = known_max;
	return err;
}

/* Forget the channel information by a fraction of the capacity. */
enum renepay_errorcode chan_extra_relax_fraction(struct chan_extra *ce,
						 double fraction)
{
	assert(ce);
	assert(fraction >= 0);
	/* Allow to have values greater than 1 to indicate full relax. */
	// assert(fraction<=1);
	fraction = fabs(fraction);     // this number is always non-negative
	fraction = MIN(1.0, fraction); // this number cannot be greater than 1.
	struct amount_msat delta =
	    amount_msat(ce->capacity.millisatoshis*fraction); /* Raw: get a fraction of the capacity */

	/* The direction here is not important because the 'down' and the 'up'
	 * limits are changed by the same amount.
	 * Notice that if chan[0] with capacity C changes from (a,b) to
	 * (a-d,b+d) then its counterpart chan[1] changes from (C-b,C-a) to
	 * (C-b-d,C-a+d), hence both dirs are applied the same transformation.
	 */
	return chan_extra_relax(ce, /*dir=*/0, delta, delta);
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
			    const struct gossmap_chan *chan, int dir)
{
	assert(chan);
	assert(dir == 0 || dir == 1);
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
	assert(dir == 0 || dir == 1);
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
double edge_probability(struct amount_msat min, struct amount_msat max,
			struct amount_msat in_flight, struct amount_msat f)
{
	assert(amount_msat_less_eq(min, max));
	assert(amount_msat_less_eq(in_flight, max));

	const struct amount_msat one = AMOUNT_MSAT(1);
	struct amount_msat B = max; // =  max +1 - in_flight

	// one past the last known value, makes computations simpler
	if (!amount_msat_add(&B, B, one))
		goto function_fail;

	// in_flight cannot be greater than max
	if (!amount_msat_sub(&B, B, in_flight))
		goto function_fail;

	struct amount_msat A = min; // = MAX(0,min-in_flight);

	if (!amount_msat_sub(&A, A, in_flight))
		A = AMOUNT_MSAT(0);

	struct amount_msat denominator; // = B-A

	// B cannot be smaller than or equal A
	if (!amount_msat_sub(&denominator, B, A) || amount_msat_less_eq(B, A))
		goto function_fail;

	struct amount_msat numerator; // MAX(0,B-f)

	if (!amount_msat_sub(&numerator, B, f))
		numerator = AMOUNT_MSAT(0);

	return amount_msat_less_eq(f, A)
		   ? 1.0
		   : amount_msat_ratio(numerator, denominator);

function_fail:
	return -1;
}

enum renepay_errorcode
chan_extra_remove_htlc(struct chan_extra_map *chan_extra_map,
		       const struct short_channel_id_dir *scidd,
		       struct amount_msat amount)
{
	struct chan_extra_half *h =
	    get_chan_extra_half_by_scid(chan_extra_map, scidd);
	if (!h)
		return RENEPAY_CHANNEL_NOT_FOUND;
	if (h->num_htlcs <= 0)
		return RENEPAY_PRECONDITION_ERROR;

	if (!amount_msat_sub(&h->htlc_total, h->htlc_total, amount))
		return RENEPAY_AMOUNT_OVERFLOW;
	h->num_htlcs--;
	return RENEPAY_NOERROR;
}

enum renepay_errorcode
chan_extra_commit_htlc(struct chan_extra_map *chan_extra_map,
		       const struct short_channel_id_dir *scidd,
		       struct amount_msat amount)
{
	struct chan_extra_half *h =
	    get_chan_extra_half_by_scid(chan_extra_map, scidd);
	if (!h)
		return RENEPAY_CHANNEL_NOT_FOUND;
	if (!amount_msat_add(&h->htlc_total, h->htlc_total, amount))
		return RENEPAY_AMOUNT_OVERFLOW;
	h->num_htlcs++;
	return RENEPAY_NOERROR;
}
