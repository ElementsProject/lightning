#include "config.h"
#include <assert.h>
#include <ccan/asort/asort.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/err/err.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/utils.h>
#include <float.h>
#include <math.h>
#include <plugins/askrene/algorithm.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/dijkstra.h>
#include <plugins/askrene/explain_failure.h>
#include <plugins/askrene/flow.h>
#include <plugins/askrene/graph.h>
#include <plugins/askrene/mcf.h>
#include <plugins/askrene/refine.h>
#include <plugins/libplugin.h>
#include <stdint.h>

/* # Optimal payments
 *
 * In this module we reduce the routing optimization problem to a linear
 * cost optimization problem and find a solution using MCF algorithms.
 * The optimization of the routing itself doesn't need a precise numerical
 * solution, since we can be happy near optimal results; e.g. paying 100 msat or
 * 101 msat for fees doesn't make any difference if we wish to deliver 1M sats.
 * On the other hand, we are now also considering Pickhard's
 * [1] model to improve payment reliability,
 * hence our optimization moves to a 2D space: either we like to maximize the
 * probability of success of a payment or minimize the routing fees, or
 * alternatively we construct a function of the two that gives a good compromise.
 *
 * Therefore from now own, the definition of optimal is a matter of choice.
 * To simplify the API of this module, we think the best way to state the
 * problem is:
 *
 * 	Find a routing solution that pays the least of fees while keeping
 * 	the probability of success above a certain value `min_probability`.
 *
 *
 * # Fee Cost
 *
 * Routing fees is non-linear function of the payment flow x, that's true even
 * without the base fee:
 *
 * 	fee_msat = base_msat + floor(millionths*x_msat / 10^6)
 *
 * We approximate this fee into a linear function by computing a slope `c_fee` such
 * that:
 *
 * 	fee_microsat = c_fee * x_sat
 *
 * Function `linear_fee_cost` computes `c_fee` based on the base and
 * proportional fees of a channel.
 * The final product if microsat because if only
 * the proportional fee was considered we can have c_fee = millionths.
 * Moving to costs based in msats means we have to either truncate payments
 * below 1ksats or estimate as 0 cost for channels with less than 1000ppm.
 *
 * TODO(eduardo): shall we build a linear cost function in msats?
 *
 * # Probability cost
 *
 * The probability of success P of the payment is the product of the prob. of
 * success of forwarding parts of the payment over all routing channels. This
 * problem is separable if we log it, and since we would like to increase P,
 * then we can seek to minimize -log(P), and that's our prob. cost function [1].
 *
 * 	- log P = sum_{i} - log P_i
 *
 * The probability of success `P_i` of sending some flow `x` on a channel with
 * liquidity l in the range a<=l<b is
 *
 * 	P_{a,b}(x) = (b-x)/(b-a); for x > a
 * 		   = 1.         ; for x <= a
 *
 * Notice that unlike the similar formula in [1], the one we propose does not
 * contain the quantization shot noise for counting states. The formula remains
 * valid independently of the liquidity units (sats or msats).
 *
 * The cost associated to probability P is then -k log P, where k is some
 * constant. For k=1 we get the following table:
 *
 * 	prob | cost
 * 	-----------
 * 	0.01 | 4.6
 * 	0.02 | 3.9
 * 	0.05 | 3.0
 * 	0.10 | 2.3
 * 	0.20 | 1.6
 * 	0.50 | 0.69
 * 	0.80 | 0.22
 * 	0.90 | 0.10
 * 	0.95 | 0.05
 * 	0.98 | 0.02
 * 	0.99 | 0.01
 *
 * Clearly -log P(x) is non-linear; we try to linearize it piecewise:
 * split the channel into 4 arcs representing 4 liquidity regions:
 *
 * 	arc_0 -> [0, a)
 * 	arc_1 -> [a, a+(b-a)*f1)
 * 	arc_2 -> [a+(b-a)*f1, a+(b-a)*f2)
 * 	arc_3 -> [a+(b-a)*f2, a+(b-a)*f3)
 *
 * where f1 = 0.5, f2 = 0.8, f3 = 0.95;
 * We fill arc_0's capacity with complete certainty P=1, then if more flow is
 * needed we start filling the capacity in arc_1 until the total probability
 * of success reaches P=0.5, then arc_2 until P=1-0.8=0.2, and finally arc_3 until
 * P=1-0.95=0.05. We don't go further than 5% prob. of success per channel.

 * TODO(eduardo): this channel linearization is hard coded into
 * `CHANNEL_PIVOTS`, maybe we can parametrize this to take values from the config file.
 *
 * With this choice, the slope of the linear cost function becomes:
 *
 * 	m_0 = 0
 * 	m_1 = 1.38 k /(b-a)
 * 	m_2 = 3.05 k /(b-a)
 * 	m_3 = 9.24 k /(b-a)
 *
 * Notice that one of the assumptions in [2] for the MCF problem is that flows
 * and the slope of the costs functions are integer numbers. The only way we
 * have at hand to make it so, is to choose a universal value of `k` that scales
 * up the slopes so that floor(m_i) is not zero for every arc.
 *
 * # Combine fee and prob. costs
 *
 * We attempt to solve the original problem of finding the solution that
 * pays the least fees while keeping the prob. of success above a certain value,
 * by constructing a cost function which is a linear combination of fee and
 * prob. costs.
 * TODO(eduardo): investigate how this procedure is justified,
 * possibly with the use of Lagrange optimization theory.
 *
 * At first, prob. and fee costs live in different dimensions, they cannot be
 * summed, it's like comparing apples and oranges.
 * However we propose to scale the prob. cost by a global factor k that
 * translates into the monetization of prob. cost.
 *
 * This was chosen empirically from examination of typical network values.
 *
 * # References
 *
 * [1] Pickhardt and Richter, https://arxiv.org/abs/2107.05322
 * [2] R.K. Ahuja, T.L. Magnanti, and J.B. Orlin. Network Flows:
 * Theory, Algorithms, and Applications. Prentice Hall, 1993.
 *
 *
 * TODO(eduardo) it would be interesting to see:
 * how much do we pay for reliability?
 * Cost_fee(most reliable solution) - Cost_fee(cheapest solution)
 *
 * TODO(eduardo): it would be interesting to see:
 * how likely is the most reliable path with respect to the cheapest?
 * Prob(reliable)/Prob(cheapest) = Exp(Cost_prob(cheapest)-Cost_prob(reliable))
 *
 * */

#define PANIC(message)                                                         \
	errx(1, "Panic in function %s line %d: %s", __func__, __LINE__,        \
	     message);

#define PARTS_BITS 2
#define CHANNEL_PARTS (1 << PARTS_BITS)

// These are the probability intervals we use to decompose a channel into linear
// cost function arcs.
static const double CHANNEL_PIVOTS[]={0,0.5,0.8,0.95};

static const s64 INFINITE = INT64_MAX;
static const s64 MU_MAX = 100;

/* Let's try this encoding of arcs:
 * Each channel `c` has two possible directions identified by a bit
 * `half` or `!half`, and each one of them has to be
 * decomposed into 4 liquidity parts in order to
 * linearize the cost function, but also to solve MCF
 * problem we need to keep track of flows in the
 * residual network hence we need for each directed arc
 * in the network there must be another arc in the
 * opposite direction refered to as it's dual. In total
 * 1+2+1 additional bits of information:
 *
 * 	(chan_idx)(half)(part)(dual)
 *
 * That means, for each channel we need to store the
 * information of 16 arcs. If we implement a convex-cost
 * solver then we can reduce that number to size(half)size(dual)=4.
 *
 * In the adjacency of a `node` we are going to store
 * the outgoing arcs. If we ever need to loop over the
 * incoming arcs then we will define a reverse adjacency
 * API.
 * Then for each outgoing channel `(c,half)` there will
 * be 4 parts for the actual residual capacity, hence
 * with the dual bit set to 0:
 *
 * 	(c,half,0,0)
 * 	(c,half,1,0)
 * 	(c,half,2,0)
 * 	(c,half,3,0)
 *
 * and also we need to consider the dual arcs
 * corresponding to the channel direction `(c,!half)`
 * (the dual has reverse direction):
 *
 * 	(c,!half,0,1)
 * 	(c,!half,1,1)
 * 	(c,!half,2,1)
 * 	(c,!half,3,1)
 *
 * These are the 8 outgoing arcs relative to `node` and
 * associated with channel `c`. The incoming arcs will
 * be:
 *
 * 	(c,!half,0,0)
 * 	(c,!half,1,0)
 * 	(c,!half,2,0)
 * 	(c,!half,3,0)
 *
 * 	(c,half,0,1)
 * 	(c,half,1,1)
 * 	(c,half,2,1)
 * 	(c,half,3,1)
 *
 * but they will be stored as outgoing arcs on the peer
 * node `next`.
 *
 * I hope this will clarify my future self when I forget.
 *
 * */

/*
 * We want to use the whole number here for convenience, but
 * we can't us a union, since bit order is implementation-defined and
 * we want chanidx on the highest bits:
 *
 * [ 0       1 2     3            4 5 6 ... 31 ]
 *   dual    part    chandir      chanidx
 */
#define ARC_DUAL_BITOFF (0)
#define ARC_PART_BITOFF (1)
#define ARC_CHANDIR_BITOFF (1 + PARTS_BITS)
#define ARC_CHANIDX_BITOFF (1 + PARTS_BITS + 1)
#define ARC_CHANIDX_BITS  (32 - ARC_CHANIDX_BITOFF)

/* How many arcs can we have for a single channel?
 * linearization parts, both directions, and dual */
#define ARCS_PER_CHANNEL ((size_t)1 << (PARTS_BITS + 1 + 1))

static inline void arc_to_parts(struct arc arc,
				u32 *chanidx,
				int *chandir,
				u32 *part,
				bool *dual)
{
	if (chanidx)
		*chanidx = (arc.idx >> ARC_CHANIDX_BITOFF);
	if (chandir)
		*chandir = (arc.idx >> ARC_CHANDIR_BITOFF) & 1;
	if (part)
		*part = (arc.idx >> ARC_PART_BITOFF) & ((1 << PARTS_BITS)-1);
	if (dual)
		*dual = (arc.idx >> ARC_DUAL_BITOFF) & 1;
}

static inline struct arc arc_from_parts(u32 chanidx, int chandir, u32 part, bool dual)
{
	struct arc arc;

	assert(part < CHANNEL_PARTS);
	assert(chandir == 0 || chandir == 1);
	assert(chanidx < (1U << ARC_CHANIDX_BITS));
	arc.idx = ((u32)dual << ARC_DUAL_BITOFF)
		| (part << ARC_PART_BITOFF)
		| ((u32)chandir << ARC_CHANDIR_BITOFF)
		| (chanidx << ARC_CHANIDX_BITOFF);
	return arc;
}

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

struct pay_parameters {
	const struct route_query *rq;
	const struct gossmap_node *source;
	const struct gossmap_node *target;

	// how much we pay
	struct amount_msat amount;

	/* base unit for computation, ie. accuracy */
	struct amount_msat accuracy;

	// channel linearization parameters
	double cap_fraction[CHANNEL_PARTS],
	       cost_fraction[CHANNEL_PARTS];

	double delay_feefactor;
	double base_fee_penalty;
};

/* Helper function.
 * Given an arc of the network (not residual) give me the flow. */
static s64 get_arc_flow(
		const s64 *arc_residual_capacity,
		const struct graph *graph,
		const struct arc arc)
{
	assert(!arc_is_dual(graph, arc));
	struct arc dual = arc_dual(graph, arc);
	assert(dual.idx < tal_count(arc_residual_capacity));
	return arc_residual_capacity[dual.idx];
}

/* Set *capacity to value, up to *cap_on_capacity.  Reduce cap_on_capacity */
static void set_capacity(s64 *capacity, u64 value, u64 *cap_on_capacity)
{
	*capacity = MIN(value, *cap_on_capacity);
	*cap_on_capacity -= *capacity;
}

/* FIXME: unit test this */
/* The probability of forwarding a payment amount given a high and low liquidity
 * bounds.
 * @low: the liquidity is known to be greater or equal than "low"
 * @high: the liquidity is known to be less than "high"
 * @amount: how much is required to forward */
static double pickhardt_richter_probability(struct amount_msat low,
					    struct amount_msat high,
					    struct amount_msat amount)
{
	struct amount_msat all_states, good_states;
	if (amount_msat_greater_eq(amount, high))
		return 0.0;
	if (!amount_msat_sub(&amount, amount, low))
		return 1.0;
	if (!amount_msat_sub(&all_states, high, low))
		PANIC("we expect high > low");
	if (!amount_msat_sub(&good_states, all_states, amount))
		PANIC("we expect high > amount");
	return amount_msat_ratio(good_states, all_states);
}

// TODO(eduardo): unit test this
/* Split a directed channel into parts with linear cost function. */
static void linearize_channel(const struct pay_parameters *params,
			      const struct gossmap_chan *c, const int dir,
			      s64 *capacity, double *cost)
{
	struct amount_msat mincap, maxcap;

	/* This takes into account any payments in progress. */
	get_constraints(params->rq, c, dir, &mincap, &maxcap);

	/* Assume if min > max, min is wrong */
	if (amount_msat_greater(mincap, maxcap))
		mincap = maxcap;

	u64 a = amount_msat_ratio_floor(mincap, params->accuracy),
	    b = 1 + amount_msat_ratio_floor(maxcap, params->accuracy);

	/* An extra bound on capacity, here we use it to reduce the flow such
	 * that it does not exceed htlcmax.
	 * Also there is no need to keep track of more capacity than the payment
	 * amount, this can help us prune some arcs. */
	u64 cap_on_capacity =
	    MIN(amount_msat_ratio_floor(gossmap_chan_htlc_max(c, dir),
					params->accuracy),
		amount_msat_ratio_ceil(params->amount, params->accuracy));

	set_capacity(&capacity[0], a, &cap_on_capacity);
	cost[0]=0;
	for(size_t i=1;i<CHANNEL_PARTS;++i)
	{
		set_capacity(&capacity[i], params->cap_fraction[i]*(b-a), &cap_on_capacity);

		cost[i] = params->cost_fraction[i] * 1000
			  * amount_msat_ratio(params->amount, params->accuracy)
			  / (b - a);
	}
}

static int cmp_u64(const u64 *a, const u64 *b, void *unused)
{
	if (*a < *b)
		return -1;
	if (*a > *b)
		return 1;
	return 0;
}

static int cmp_double(const double *a, const double *b, void *unused)
{
	if (*a < *b)
		return -1;
	if (*a > *b)
		return 1;
	return 0;
}

static double get_median_ratio(const tal_t *working_ctx,
			       const struct graph *graph,
			       const double *arc_prob_cost,
			       const s64 *arc_fee_cost)
{
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	u64 *u64_arr = tal_arr(working_ctx, u64, max_num_arcs);
	double *double_arr = tal_arr(working_ctx, double, max_num_arcs);
	size_t n = 0;

	for (struct arc arc = {.idx=0};arc.idx < max_num_arcs; ++arc.idx) {
		/* scan real arcs, not unused id slots or dual arcs */
		if (arc_is_dual(graph, arc) || !arc_enabled(graph, arc))
			continue;
		assert(n < max_num_arcs/2);
		u64_arr[n] = arc_fee_cost[arc.idx];
		double_arr[n] = arc_prob_cost[arc.idx];
		n++;
	}
	asort(u64_arr, n, cmp_u64, NULL);
	asort(double_arr, n, cmp_double, NULL);

	/* Empty network, or tiny probability, nobody cares */
	if (n == 0 || double_arr[n/2] < 0.001)
		return 1;

	/* You need to scale arc_prob_cost by this to match arc_fee_cost */
	return u64_arr[n/2] / double_arr[n/2];
}

static void combine_cost_function(const tal_t *working_ctx,
				  const struct graph *graph,
				  const double *arc_prob_cost,
				  const s64 *arc_fee_cost, const s8 *biases,
				  s64 mu, s64 *arc_cost)
{
	/* probabilty and fee costs are not directly comparable!
	 * Scale by ratio of (positive) medians. */
	const double k =
	    get_median_ratio(working_ctx, graph, arc_prob_cost, arc_fee_cost);
	const double ln_30 = log(30);
	const size_t max_num_arcs = graph_max_num_arcs(graph);

	for(struct arc arc = {.idx=0};arc.idx < max_num_arcs; ++arc.idx)
	{
		if (arc_is_dual(graph, arc) || !arc_enabled(graph, arc))
			continue;

		const double pcost = arc_prob_cost[arc.idx];
		const s64 fcost = arc_fee_cost[arc.idx];
		double combined;
		u32 chanidx;
		int chandir;
		s32 bias;

		assert(fcost != INFINITE);
		assert(pcost != DBL_MAX);
		combined = fcost*mu + (MU_MAX-mu)*pcost*k;

		/* Bias is in human scale, where "bigger is better" */
		arc_to_parts(arc, &chanidx, &chandir, NULL, NULL);
		bias = biases[(chanidx << 1) | chandir];
		if (bias != 0) {
			/* After some trial and error, this gives a nice
			 * dynamic range (25 seems to be "infinite" in
			 * practice):
			 *    e^(-bias / (100/ln(30)))
			 */
			double bias_factor = exp(-bias / (100 / ln_30));
			arc_cost[arc.idx] = combined * bias_factor;
		} else {
			arc_cost[arc.idx] = combined;
		}
		/* and the respective dual */
		struct arc dual = arc_dual(graph, arc);
		arc_cost[dual.idx] = -combined;
	}
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
 *  	fee = c_fee/10^6 * x
 *
 *  use `base_fee_penalty` to weight the base fee and `delay_feefactor` to
 *  weight the CLTV delay.
 *  */
static s64 linear_fee_cost(u32 base_fee, u32 proportional_fee, u16 cltv_delta,
			   double base_fee_penalty,
			   double delay_feefactor)
{
	s64 pfee = proportional_fee,
	    bfee = base_fee,
	    delay = cltv_delta;

	return pfee + bfee* base_fee_penalty+ delay*delay_feefactor;
}

/* This is inversely proportional to the amount we expect to send.  Let's
 * assume we will send ~10th of the total amount per path.  But note
 * that it converts to parts per million! */
static double base_fee_penalty_estimate(struct amount_msat amount)
{
	return amount_msat_ratio(AMOUNT_MSAT(10000000), amount);
}

struct amount_msat linear_flow_cost(const struct flow *flow,
				    struct amount_msat total_amount,
				    double delay_feefactor)
{
	struct amount_msat msat_cost;
	s64 cost_ppm = 0;
	double base_fee_penalty = base_fee_penalty_estimate(total_amount);

	for (size_t i = 0; i < tal_count(flow->path); i++) {
		const struct half_chan *h = &flow->path[i]->half[flow->dirs[i]];

		cost_ppm +=
		    linear_fee_cost(h->base_fee, h->proportional_fee, h->delay,
				    base_fee_penalty, delay_feefactor);
	}
	if (!amount_msat_fee(&msat_cost, flow->delivers, 0, cost_ppm))
		abort();
	return msat_cost;
}

static void init_linear_network(const tal_t *ctx,
				const struct pay_parameters *params,
				struct graph **graph, double **arc_prob_cost,
				s64 **arc_fee_cost, s64 **arc_capacity)
{
	const struct gossmap *gossmap = params->rq->gossmap;
	const size_t max_num_chans = gossmap_max_chan_idx(gossmap);
	const size_t max_num_arcs = max_num_chans * ARCS_PER_CHANNEL;
	const size_t max_num_nodes = gossmap_max_node_idx(gossmap);

	*graph = graph_new(ctx, max_num_nodes, max_num_arcs, ARC_DUAL_BITOFF);
	*arc_prob_cost = tal_arr(ctx, double, max_num_arcs);
	for (size_t i = 0; i < max_num_arcs; ++i)
		(*arc_prob_cost)[i] = DBL_MAX;

	*arc_fee_cost = tal_arr(ctx, s64, max_num_arcs);
	for (size_t i = 0; i < max_num_arcs; ++i)
		(*arc_fee_cost)[i] = INT64_MAX;

	*arc_capacity = tal_arrz(ctx, s64, max_num_arcs);

	for(struct gossmap_node *node = gossmap_first_node(gossmap);
	    node;
	    node=gossmap_next_node(gossmap,node))
	{
		const u32 node_id = gossmap_node_idx(gossmap,node);

		for(size_t j=0;j<node->num_chans;++j)
		{
			int half;
			const struct gossmap_chan *c = gossmap_nth_chan(gossmap,
			                                                node, j, &half);

			if (!gossmap_chan_set(c, half) || !c->half[half].enabled)
				continue;

			/* If a channel insists on more than our total, remove it */
			if (amount_msat_less(params->amount, gossmap_chan_htlc_min(c, half)))
				continue;

			const u32 chan_id = gossmap_chan_idx(gossmap, c);

			const struct gossmap_node *next = gossmap_nth_node(gossmap,
									   c,!half);

			const u32 next_id = gossmap_node_idx(gossmap,next);

			if(node_id==next_id)
				continue;

			// `cost` is the word normally used to denote cost per
			// unit of flow in the context of MCF.
			double prob_cost[CHANNEL_PARTS];
			s64 capacity[CHANNEL_PARTS];

			// split this channel direction to obtain the arcs
			// that are outgoing to `node`
			linearize_channel(params, c, half, capacity, prob_cost);

			/* linear fee_cost per unit of flow */
			const s64 fee_cost = linear_fee_cost(
				c->half[half].base_fee,
				c->half[half].proportional_fee,
				c->half[half].delay,
				params->base_fee_penalty,
				params->delay_feefactor);

			// let's subscribe the 4 parts of the channel direction
			// (c,half), the dual of these guys will be subscribed
			// when the `i` hits the `next` node.
			for(size_t k=0;k<CHANNEL_PARTS;++k)
			{
				/* prune arcs with 0 capacity */
				if (capacity[k] == 0)
					continue;

				struct arc arc = arc_from_parts(chan_id, half, k, false);

				graph_add_arc(*graph, arc,
					      node_obj(node_id),
					      node_obj(next_id));

				(*arc_capacity)[arc.idx] = capacity[k];
				(*arc_prob_cost)[arc.idx] = prob_cost[k];
				(*arc_fee_cost)[arc.idx] = fee_cost;

				// + the respective dual
				struct arc dual = arc_dual(*graph, arc);

				(*arc_capacity)[dual.idx] = 0;
				(*arc_prob_cost)[dual.idx] = -prob_cost[k];
				(*arc_fee_cost)[dual.idx] = -fee_cost;
			}
		}
	}
}

// flow on directed channels
struct chan_flow
{
	s64 half[2];
};

/* Search in the network a path of positive flow until we reach a node with
 * positive balance (returns a node idx with positive balance)
 * or we discover a cycle (returns a node idx with 0 balance).
 * */
static struct node find_path_or_cycle(
		const tal_t *working_ctx,
		const struct gossmap *gossmap,
		const struct chan_flow *chan_flow,
		const struct node source,
		const s64 *balance,

		const struct gossmap_chan **prev_chan,
		int *prev_dir,
		u32 *prev_idx)
{
	const size_t max_num_nodes = gossmap_max_node_idx(gossmap);
	bitmap *visited =
	    tal_arrz(working_ctx, bitmap, BITMAP_NWORDS(max_num_nodes));
	u32 final_idx = source.idx;
	bitmap_set_bit(visited, final_idx);

	/* It is guaranteed to halt, because we either find a node with
	 * balance[]>0 or we hit a node twice and we stop. */
	while (balance[final_idx] <= 0) {
		u32 updated_idx = INVALID_INDEX;
		struct gossmap_node *cur =
		    gossmap_node_byidx(gossmap, final_idx);

		for (size_t i = 0; i < cur->num_chans; ++i) {
			int dir;
			const struct gossmap_chan *c =
			    gossmap_nth_chan(gossmap, cur, i, &dir);

			if (!gossmap_chan_set(c, dir) || !c->half[dir].enabled)
				continue;

			const u32 c_idx = gossmap_chan_idx(gossmap, c);

			/* follow the flow */
			if (chan_flow[c_idx].half[dir] > 0) {
				const struct gossmap_node *n =
				    gossmap_nth_node(gossmap, c, !dir);
				u32 next_idx = gossmap_node_idx(gossmap, n);

				prev_dir[next_idx] = dir;
				prev_chan[next_idx] = c;
				prev_idx[next_idx] = final_idx;

				updated_idx = next_idx;
				break;
			}
		}

		assert(updated_idx != INVALID_INDEX);
		assert(updated_idx != final_idx);
		final_idx = updated_idx;

		if (bitmap_test_bit(visited, updated_idx)) {
			/* We have seen this node before, we've found a cycle.
			 */
			assert(balance[updated_idx] <= 0);
			break;
		}
		bitmap_set_bit(visited, updated_idx);
	}
	return node_obj(final_idx);
}

struct list_data
{
	struct list_node list;
	struct flow *flow_path;
};

/* Given a path from a node with negative balance to a node with positive
 * balance, compute the bigest flow and substract it from the nodes balance and
 * the channels allocation. */
static struct flow *substract_flow(const tal_t *ctx,
				   const struct pay_parameters *params,
				   const struct node source,
				   const struct node sink,
				   s64 *balance, struct chan_flow *chan_flow,
				   const u32 *prev_idx, const int *prev_dir,
				   const struct gossmap_chan *const *prev_chan)
{
	const struct gossmap *gossmap = params->rq->gossmap;
	assert(balance[source.idx] < 0);
	assert(balance[sink.idx] > 0);
	s64 delta = -balance[source.idx];
	size_t length = 0;
	delta = MIN(delta, balance[sink.idx]);

	/* We can only walk backwards, now get me the legth of the path and the
	 * max flow we can send through this route. */
	for (u32 cur_idx = sink.idx; cur_idx != source.idx;
	     cur_idx = prev_idx[cur_idx]) {
		assert(cur_idx != INVALID_INDEX);
		const int dir = prev_dir[cur_idx];
		const struct gossmap_chan *const chan = prev_chan[cur_idx];

		/* we could optimize here by caching the idx of the channels in
		 * the path, but the bottleneck of the algorithm is the MCF
		 * computation not here. */
		const u32 chan_idx = gossmap_chan_idx(gossmap, chan);

		delta = MIN(delta, chan_flow[chan_idx].half[dir]);
		length++;
	}

	struct flow *f = tal(ctx, struct flow);
	f->path = tal_arr(f, const struct gossmap_chan *, length);
	f->dirs = tal_arr(f, int, length);

	/* Walk again and substract the flow value (delta). */
	assert(delta > 0);
	balance[source.idx] += delta;
	balance[sink.idx] -= delta;
	for (u32 cur_idx = sink.idx; cur_idx != source.idx;
	     cur_idx = prev_idx[cur_idx]) {
		const int dir = prev_dir[cur_idx];
		const struct gossmap_chan *const chan = prev_chan[cur_idx];
		const u32 chan_idx = gossmap_chan_idx(gossmap, chan);

		length--;
		/* f->path and f->dirs contain the channels in the path in the
		 * correct order. */
		f->path[length] = chan;
		f->dirs[length] = dir;

		chan_flow[chan_idx].half[dir] -= delta;
	}
	if (!amount_msat_mul(&f->delivers, params->accuracy, delta))
		abort();
	return f;
}

/* Substract a flow cycle from the channel allocation. */
static void substract_cycle(const struct gossmap *gossmap,
			    const struct node sink,
			    struct chan_flow *chan_flow, const u32 *prev_idx,
			    const int *prev_dir,
			    const struct gossmap_chan *const *prev_chan)
{
	s64 delta = INFINITE;
	u32 cur_idx;

	/* Compute greatest flow in this cycle. */
	for (cur_idx = sink.idx; cur_idx!=INVALID_INDEX;) {
		const int dir = prev_dir[cur_idx];
		const struct gossmap_chan *const chan = prev_chan[cur_idx];
		const u32 chan_idx = gossmap_chan_idx(gossmap, chan);

		delta = MIN(delta, chan_flow[chan_idx].half[dir]);

		cur_idx = prev_idx[cur_idx];
		if (cur_idx == sink.idx)
			/* we have come back full circle */
			break;
	}
	assert(cur_idx==sink.idx);

	/* Walk again and substract the flow value (delta). */
	assert(delta < INFINITE);
	assert(delta > 0);

	for (cur_idx = sink.idx;cur_idx!=INVALID_INDEX;) {
		const int dir = prev_dir[cur_idx];
		const struct gossmap_chan *const chan = prev_chan[cur_idx];
		const u32 chan_idx = gossmap_chan_idx(gossmap, chan);

		chan_flow[chan_idx].half[dir] -= delta;

		cur_idx = prev_idx[cur_idx];
		if (cur_idx == sink.idx)
			/* we have come back full circle */
			break;
	}
	assert(cur_idx==sink.idx);
}

/* Given a flow in the residual network, build a set of payment flows in the
 * gossmap that corresponds to this flow. */
static struct flow **
get_flow_paths(const tal_t *ctx,
	       const tal_t *working_ctx,
	       const struct pay_parameters *params,
	       const struct graph *graph,
	       const s64 *arc_residual_capacity)
{
	struct flow **flows = tal_arr(ctx,struct flow*,0);

	const size_t max_num_chans = gossmap_max_chan_idx(params->rq->gossmap);
	struct chan_flow *chan_flow = tal_arrz(working_ctx,struct chan_flow,max_num_chans);

	const size_t max_num_nodes = gossmap_max_node_idx(params->rq->gossmap);
	s64 *balance = tal_arrz(working_ctx,s64,max_num_nodes);

	const struct gossmap_chan **prev_chan
		= tal_arr(working_ctx,const struct gossmap_chan *,max_num_nodes);


	int *prev_dir = tal_arr(working_ctx,int,max_num_nodes);
	u32 *prev_idx = tal_arr(working_ctx, u32, max_num_nodes);

	for (u32 node_idx = 0; node_idx < max_num_nodes; node_idx++)
		prev_idx[node_idx] = INVALID_INDEX;

	// Convert the arc based residual network flow into a flow in the
	// directed channel network.
	// Compute balance on the nodes.
	for (struct node n = {.idx = 0}; n.idx < max_num_nodes; n.idx++) {
		for(struct arc arc = node_adjacency_begin(graph,n);
		        !node_adjacency_end(arc);
			arc = node_adjacency_next(graph,arc))
		{
			if(arc_is_dual(graph, arc))
				continue;
			struct node m = arc_head(graph,arc);
			s64 flow = get_arc_flow(arc_residual_capacity,
						graph, arc);
			u32 chanidx;
			int chandir;

			balance[n.idx] -= flow;
			balance[m.idx] += flow;

			arc_to_parts(arc, &chanidx, &chandir, NULL, NULL);
			chan_flow[chanidx].half[chandir] +=flow;
		}
	}

	// Select all nodes with negative balance and find a flow that reaches a
	// positive balance node.
	for (struct node source = {.idx = 0}; source.idx < max_num_nodes;
	     source.idx++) {
		// this node has negative balance, flows leaves from here
		while (balance[source.idx] < 0) {
			prev_chan[source.idx] = NULL;
			struct node sink = find_path_or_cycle(
			    working_ctx, params->rq->gossmap, chan_flow, source,
			    balance, prev_chan, prev_dir, prev_idx);

			if (balance[sink.idx] > 0)
			/* case 1. found a path */
			{
				struct flow *fp = substract_flow(
				    flows, params, source, sink, balance,
				    chan_flow, prev_idx, prev_dir, prev_chan);

				tal_arr_expand(&flows, fp);
			} else
			/* case 2. found a cycle */
			{
				substract_cycle(params->rq->gossmap, sink, chan_flow,
						prev_idx, prev_dir, prev_chan);
			}
		}
	}
	return flows;
}

/* Given a single path build a flow set. */
static struct flow **
get_flow_singlepath(const tal_t *ctx, const struct pay_parameters *params,
		    const struct graph *graph, const struct gossmap *gossmap,
		    const struct node source, const struct node destination,
		    const u64 pay_amount, const struct arc *prev)
{
	struct flow **flows = tal_arr(ctx, struct flow *, 0);

	size_t length = 0;

	for (u32 cur_idx = destination.idx; cur_idx != source.idx;) {
		assert(cur_idx != INVALID_INDEX);
		length++;
		struct arc arc = prev[cur_idx];
		struct node next = arc_tail(graph, arc);
		cur_idx = next.idx;
	}
	struct flow *f = tal(ctx, struct flow);
	f->path = tal_arr(f, const struct gossmap_chan *, length);
	f->dirs = tal_arr(f, int, length);

	for (u32 cur_idx = destination.idx; cur_idx != source.idx;) {
		int chandir;
		u32 chanidx;
		struct arc arc = prev[cur_idx];
		arc_to_parts(arc, &chanidx, &chandir, NULL, NULL);

		length--;
		f->path[length] = gossmap_chan_byidx(gossmap, chanidx);
		f->dirs[length] = chandir;

		struct node next = arc_tail(graph, arc);
		cur_idx = next.idx;
	}
	f->delivers = params->amount;
	tal_arr_expand(&flows, f);
	return flows;
}

// TODO(eduardo): choose some default values for the minflow parameters
/* eduardo: I think it should be clear that this module deals with linear
 * flows, ie. base fees are not considered. Hence a flow along a path is
 * described with a sequence of directed channels and one amount.
 * In the `pay_flow` module there are dedicated routes to compute the actual
 * amount to be forward on each hop.
 *
 * TODO(eduardo): notice that we don't pay fees to forward payments with local
 * channels and we can tell with absolute certainty the liquidity on them.
 * Check that local channels have fee costs = 0 and bounds with certainty (min=max). */
// TODO(eduardo): we should LOG_DBG the process of finding the MCF while
// adjusting the frugality factor.
struct flow **minflow(const tal_t *ctx,
		      const struct route_query *rq,
		      const struct gossmap_node *source,
		      const struct gossmap_node *target,
		      struct amount_msat amount,
		      u32 mu,
		      double delay_feefactor)
{
	struct flow **flow_paths;
	/* We allocate everything off this, and free it at the end,
	 * as we can be called multiple times without cleaning tmpctx! */
	tal_t *working_ctx = tal(NULL, char);
	struct pay_parameters *params = tal(working_ctx, struct pay_parameters);

	params->rq = rq;
	params->source = source;
	params->target = target;
	params->amount = amount;
	/* -> At most 1M units of flow are allowed, that reduces the
	 * computational burden for algorithms that depend on it, eg. "capacity
	 * scaling" and "successive shortest path".
	 * -> Using Ceil operation instead of Floor so that
	 *      accuracy x 1M >= amount
	 * */
	params->accuracy = amount_msat_max(
	    AMOUNT_MSAT(1), amount_msat_div_ceil(amount, 1000000));

	// template the channel partition into linear arcs
	params->cap_fraction[0]=0;
	params->cost_fraction[0]=0;
	for(size_t i =1;i<CHANNEL_PARTS;++i)
	{
		params->cap_fraction[i]=CHANNEL_PIVOTS[i]-CHANNEL_PIVOTS[i-1];
		params->cost_fraction[i]=
			log((1-CHANNEL_PIVOTS[i-1])/(1-CHANNEL_PIVOTS[i]))
			/params->cap_fraction[i];
	}

	params->delay_feefactor = delay_feefactor;
	params->base_fee_penalty = base_fee_penalty_estimate(amount);

	// build the uncertainty network with linearization and residual arcs
	struct graph *graph;
	double *arc_prob_cost;
	s64 *arc_fee_cost;
	s64 *arc_capacity;
	init_linear_network(working_ctx, params, &graph, &arc_prob_cost,
			    &arc_fee_cost, &arc_capacity);

	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);
	s64 *arc_cost;
	s64 *node_potential;
	s64 *node_excess;
	arc_cost = tal_arrz(working_ctx, s64, max_num_arcs);
	node_potential = tal_arrz(working_ctx, s64, max_num_nodes);
	node_excess = tal_arrz(working_ctx, s64, max_num_nodes);

	const struct node dst = {.idx = gossmap_node_idx(rq->gossmap, target)};
	const struct node src = {.idx = gossmap_node_idx(rq->gossmap, source)};


	/* Since we have constraint accuracy, ask to find a payment solution
	 * that can pay a bit more than the actual value rathen than undershoot it.
	 * That's why we use the ceil function here. */
	const u64 pay_amount =
	    amount_msat_ratio_ceil(params->amount, params->accuracy);

	if (!simple_feasibleflow(working_ctx, graph, src, dst,
				 arc_capacity, pay_amount)) {
		rq_log(tmpctx, rq, LOG_INFORM,
		       "%s failed: unable to find a feasible flow.", __func__);
		goto fail;
	}
	combine_cost_function(working_ctx, graph, arc_prob_cost, arc_fee_cost,
			      rq->biases, mu, arc_cost);

	/* We solve a linear MCF problem. */
	if (!mcf_refinement(working_ctx,
			    graph,
			    node_excess,
			    arc_capacity,
			    arc_cost,
			    node_potential)) {
		rq_log(tmpctx, rq, LOG_BROKEN,
		       "%s: MCF optimization step failed", __func__);
		goto fail;
	}

	/* We dissect the solution of the MCF into payment routes.
	 * Actual amounts considering fees are computed for every
	 * channel in the routes. */
	flow_paths = get_flow_paths(ctx, working_ctx, params,
				    graph, arc_capacity);
	if(!flow_paths){
		rq_log(tmpctx, rq, LOG_BROKEN,
		       "%s: failed to extract flow paths from the MCF solution",
		       __func__);
		goto fail;
	}
	tal_free(working_ctx);
	return flow_paths;

fail:
	tal_free(working_ctx);
	return NULL;
}

static struct amount_msat linear_flows_cost(struct flow **flows,
					    struct amount_msat total_amount,
					    double delay_feefactor)
{
	struct amount_msat total = AMOUNT_MSAT(0);

	for (size_t i = 0; i < tal_count(flows); i++) {
		if (!amount_msat_accumulate(&total,
					    linear_flow_cost(flows[i],
							     total_amount,
							     delay_feefactor)))
			abort();
	}
	return total;
}

/* Initialize the data vectors for the single-path solver. */
static void init_linear_network_single_path(
    const tal_t *ctx, const struct pay_parameters *params, struct graph **graph,
    double **arc_prob_cost, s64 **arc_fee_cost, s64 **arc_capacity)
{
	const size_t max_num_chans = gossmap_max_chan_idx(params->rq->gossmap);
	const size_t max_num_arcs = max_num_chans * ARCS_PER_CHANNEL;
	const size_t max_num_nodes = gossmap_max_node_idx(params->rq->gossmap);

	*graph = graph_new(ctx, max_num_nodes, max_num_arcs, ARC_DUAL_BITOFF);
	*arc_prob_cost = tal_arr(ctx, double, max_num_arcs);
	for (size_t i = 0; i < max_num_arcs; ++i)
		(*arc_prob_cost)[i] = DBL_MAX;

	*arc_fee_cost = tal_arr(ctx, s64, max_num_arcs);
	for (size_t i = 0; i < max_num_arcs; ++i)
		(*arc_fee_cost)[i] = INT64_MAX;
	*arc_capacity = tal_arrz(ctx, s64, max_num_arcs);

	const struct gossmap *gossmap = params->rq->gossmap;

	for (struct gossmap_node *node = gossmap_first_node(gossmap); node;
	     node = gossmap_next_node(gossmap, node)) {
		const u32 node_id = gossmap_node_idx(gossmap, node);

		for (size_t j = 0; j < node->num_chans; ++j) {
			int half;
			const struct gossmap_chan *c =
			    gossmap_nth_chan(gossmap, node, j, &half);
                        struct amount_msat mincap, maxcap;

			if (!gossmap_chan_set(c, half) ||
			    !c->half[half].enabled)
				continue;

			/* If a channel cannot forward the total amount we don't
			 * use it. */
			if (amount_msat_less(params->amount,
					     gossmap_chan_htlc_min(c, half)) ||
			    amount_msat_greater(params->amount,
						gossmap_chan_htlc_max(c, half)))
				continue;

			get_constraints(params->rq, c, half, &mincap, &maxcap);
			/* Assume if min > max, min is wrong */
			if (amount_msat_greater(mincap, maxcap))
				mincap = maxcap;
			/* It is preferable to work on 1msat past the known
			 * bound. */
			if (!amount_msat_accumulate(&maxcap, amount_msat(1)))
				PANIC("maxcap + 1msat overflows");

			/* If amount is greater than the known liquidity upper
			 * bound we get infinite probability cost. */
			if (amount_msat_greater_eq(params->amount, maxcap))
				continue;

			const u32 chan_id = gossmap_chan_idx(gossmap, c);

			const struct gossmap_node *next =
			    gossmap_nth_node(gossmap, c, !half);

			const u32 next_id = gossmap_node_idx(gossmap, next);

			/* channel to self? */
			if (node_id == next_id)
				continue;

			struct arc arc =
			    arc_from_parts(chan_id, half, 0, false);

			graph_add_arc(*graph, arc, node_obj(node_id),
				      node_obj(next_id));

			(*arc_capacity)[arc.idx] = 1;
			(*arc_prob_cost)[arc.idx] =
			    (-1.0) * log(pickhardt_richter_probability(
					 mincap, maxcap, params->amount));

			struct amount_msat fee;
			if (!amount_msat_fee(&fee, params->amount,
					     c->half[half].base_fee,
					     c->half[half].proportional_fee))
				PANIC("fee overflow");
			u32 fee_msat;
			if (!amount_msat_to_u32(fee, &fee_msat))
				PANIC("fee does not fit in u32");
			(*arc_fee_cost)[arc.idx] =
			    fee_msat +
			    params->delay_feefactor * c->half[half].delay;
		}
	}
}

/* Similar to minflow but computes routes that have a single path. */
struct flow **single_path_flow(const tal_t *ctx, const struct route_query *rq,
			       const struct gossmap_node *source,
			       const struct gossmap_node *target,
			       struct amount_msat amount, u32 mu,
			       double delay_feefactor)
{
	struct flow **flow_paths;
	/* We allocate everything off this, and free it at the end,
	 * as we can be called multiple times without cleaning tmpctx! */
	tal_t *working_ctx = tal(NULL, char);
	struct pay_parameters *params = tal(working_ctx, struct pay_parameters);

	params->rq = rq;
	params->source = source;
	params->target = target;
	params->amount = amount;
	/* for the single-path solver the accuracy does not detriment
	 * performance */
	params->accuracy = amount;
	params->delay_feefactor = delay_feefactor;
	params->base_fee_penalty = base_fee_penalty_estimate(amount);

	struct graph *graph;
	double *arc_prob_cost;
	s64 *arc_fee_cost;
	s64 *arc_capacity;

	init_linear_network_single_path(working_ctx, params, &graph,
					&arc_prob_cost, &arc_fee_cost,
					&arc_capacity);

	const struct node dst = {.idx = gossmap_node_idx(rq->gossmap, target)};
	const struct node src = {.idx = gossmap_node_idx(rq->gossmap, source)};

	const size_t max_num_nodes = graph_max_num_nodes(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);

	s64 *potential = tal_arrz(working_ctx, s64, max_num_nodes);
	s64 *distance = tal_arrz(working_ctx, s64, max_num_nodes);
	s64 *arc_cost = tal_arrz(working_ctx, s64, max_num_arcs);
	struct arc *prev = tal_arrz(working_ctx, struct arc, max_num_nodes);

	combine_cost_function(working_ctx, graph, arc_prob_cost, arc_fee_cost,
			      rq->biases, mu, arc_cost);

	/* We solve a linear cost flow problem. */
	if (!dijkstra_path(working_ctx, graph, src, dst,
			   /* prune = */ true, arc_capacity,
			   /*threshold = */ 1, arc_cost, potential, prev,
			   distance)) {
                /* This might fail if we are unable to find a suitable route, it
                 * doesn't mean the plugin is broken, that's why we LOG_INFORM. */
		rq_log(tmpctx, rq, LOG_INFORM,
		       "%s: could not find a feasible single path", __func__);
		goto fail;
	}
	const u64 pay_amount =
	    amount_msat_ratio_ceil(params->amount, params->accuracy);

	/* We dissect the flow into payment routes.
	 * Actual amounts considering fees are computed for every
	 * channel in the routes. */
	flow_paths = get_flow_singlepath(ctx, params, graph, rq->gossmap,
					 src, dst, pay_amount, prev);
	if (!flow_paths) {
		rq_log(tmpctx, rq, LOG_BROKEN,
		       "%s: failed to extract flow paths from the single-path "
		       "solution",
		       __func__);
		goto fail;
	}
	if (tal_count(flow_paths) != 1) {
		rq_log(
		    tmpctx, rq, LOG_BROKEN,
		    "%s: single-path solution returned a multi route solution",
		    __func__);
		goto fail;
	}
	tal_free(working_ctx);
	return flow_paths;

fail:
	tal_free(working_ctx);
	return NULL;
}

static const char *
linear_routes(const tal_t *ctx, struct route_query *rq,
	      const struct gossmap_node *srcnode,
	      const struct gossmap_node *dstnode, struct amount_msat amount,
	      struct amount_msat maxfee, u32 finalcltv, u32 maxdelay,
	      struct flow ***flows, double *probability,
	      struct flow **(*solver)(const tal_t *, const struct route_query *,
				      const struct gossmap_node *,
				      const struct gossmap_node *,
				      struct amount_msat, u32, double))
{
	*flows = NULL;
	const char *ret;
	double delay_feefactor = 1.0 / 1000000;

	/* First up, don't care about fees (well, just enough to tiebreak!) */
	u32 mu = 1;
	tal_free(*flows);
	*flows = solver(ctx, rq, srcnode, dstnode, amount, mu, delay_feefactor);
	if (!*flows) {
		ret = explain_failure(ctx, rq, srcnode, dstnode, amount);
		goto fail;
	}

	/* Too much delay? */
	while (finalcltv + flows_worst_delay(*flows) > maxdelay) {
		delay_feefactor *= 2;
		rq_log(tmpctx, rq, LOG_UNUSUAL,
		       "The worst flow delay is %" PRIu64
		       " (> %i), retrying with delay_feefactor %f...",
		       flows_worst_delay(*flows), maxdelay - finalcltv,
		       delay_feefactor);
		tal_free(*flows);
		*flows = solver(ctx, rq, srcnode, dstnode, amount, mu,
				delay_feefactor);
		if (!*flows || delay_feefactor > 10) {
			ret = rq_log(
			    ctx, rq, LOG_UNUSUAL,
			    "Could not find route without excessive delays");
			goto fail;
		}
	}

	/* Too expensive? */
too_expensive:
	while (amount_msat_greater(flowset_fee(rq->plugin, *flows), maxfee)) {
		struct flow **new_flows;

		if (mu == 1)
			mu = 10;
		else
			mu += 10;
		rq_log(tmpctx, rq, LOG_UNUSUAL,
		       "The flows had a fee of %s, greater than max of %s, "
		       "retrying with mu of %u%%...",
		       fmt_amount_msat(tmpctx, flowset_fee(rq->plugin, *flows)),
		       fmt_amount_msat(tmpctx, maxfee), mu);
		new_flows = solver(ctx, rq, srcnode, dstnode, amount,
				   mu > 100 ? 100 : mu, delay_feefactor);
		if (!*flows || mu >= 100) {
			ret = rq_log(
			    ctx, rq, LOG_UNUSUAL,
			    "Could not find route without excessive cost");
			goto fail;
		}

		/* This is possible, because MCF's linear fees are not the same.
		 */
		if (amount_msat_greater(flowset_fee(rq->plugin, new_flows),
					flowset_fee(rq->plugin, *flows))) {
			struct amount_msat old_cost =
			    linear_flows_cost(*flows, amount, delay_feefactor);
			struct amount_msat new_cost = linear_flows_cost(
			    new_flows, amount, delay_feefactor);
			if (amount_msat_greater_eq(new_cost, old_cost)) {
				rq_log(tmpctx, rq, LOG_BROKEN,
				       "Old flows cost %s:",
				       fmt_amount_msat(tmpctx, old_cost));
				for (size_t i = 0; i < tal_count(*flows); i++) {
					rq_log(
					    tmpctx, rq, LOG_BROKEN,
					    "Flow %zu/%zu: %s (linear cost %s)",
					    i, tal_count(*flows),
					    fmt_flow_full(tmpctx, rq, (*flows)[i]),
					    fmt_amount_msat(
						tmpctx, linear_flow_cost(
							    (*flows)[i], amount,
							    delay_feefactor)));
				}
				rq_log(tmpctx, rq, LOG_BROKEN,
				       "Old flows cost %s:",
				       fmt_amount_msat(tmpctx, new_cost));
				for (size_t i = 0; i < tal_count(new_flows);
				     i++) {
					rq_log(
					    tmpctx, rq, LOG_BROKEN,
					    "Flow %zu/%zu: %s (linear cost %s)",
					    i, tal_count(new_flows),
					    fmt_flow_full(tmpctx, rq,
							  new_flows[i]),
					    fmt_amount_msat(
						tmpctx,
						linear_flow_cost(
						    new_flows[i], amount,
						    delay_feefactor)));
				}
			}
		}
		tal_free(*flows);
		*flows = new_flows;
	}

	if (finalcltv + flows_worst_delay(*flows) > maxdelay) {
		ret = rq_log(
		    ctx, rq, LOG_UNUSUAL,
		    "Could not find route without excessive cost or delays");
		goto fail;
	}

	/* The above did not take into account the extra funds to pay
	 * fees, so we try to adjust now.  We could re-run MCF if this
	 * fails, but failure basically never happens where payment is
	 * still possible */
	ret = refine_with_fees_and_limits(ctx, rq, amount, flows, probability);
	if (ret)
		goto fail;

	/* Again, a tiny corner case: refine step can make us exceed maxfee */
	if (amount_msat_greater(flowset_fee(rq->plugin, *flows), maxfee)) {
		rq_log(tmpctx, rq, LOG_UNUSUAL,
		       "After final refinement, fee was excessive: retrying");
		goto too_expensive;
	}

	return NULL;
fail:
	assert(ret != NULL);
	return ret;
}

const char *default_routes(const tal_t *ctx, struct route_query *rq,
			   const struct gossmap_node *srcnode,
			   const struct gossmap_node *dstnode,
			   struct amount_msat amount, struct amount_msat maxfee,
			   u32 finalcltv, u32 maxdelay, struct flow ***flows,
			   double *probability)
{
	return linear_routes(ctx, rq, srcnode, dstnode, amount, maxfee,
			     finalcltv, maxdelay, flows, probability, minflow);
}

const char *single_path_routes(const tal_t *ctx, struct route_query *rq,
			       const struct gossmap_node *srcnode,
			       const struct gossmap_node *dstnode,
			       struct amount_msat amount,
			       struct amount_msat maxfee, u32 finalcltv,
			       u32 maxdelay, struct flow ***flows,
			       double *probability)
{
	return linear_routes(ctx, rq, srcnode, dstnode, amount, maxfee,
			     finalcltv, maxdelay, flows, probability,
			     single_path_flow);
}
