#include "config.h"
#include <assert.h>
#include <ccan/asort/asort.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/utils.h>
#include <float.h>
#include <inttypes.h>
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

#define PARTS_BITS 2
#define CHANNEL_PARTS (1 << PARTS_BITS)

// These are the probability intervals we use to decompose a channel into linear
// cost function arcs.
static const double CHANNEL_PIVOTS[]={0,0.5,0.8,0.95};

static const s64 INFINITE = INT64_MAX;
static const s64 MU_MAX = 100;

/* every payment under 1000sat will be routed through a single path */
static const struct amount_msat SINGLE_PATH_THRESHOLD = AMOUNT_MSAT(1000000);

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

/* Helper to check whether a channel is available */
static bool channel_is_available(const struct route_query *rq,
				 const struct gossmap_chan *chan, const int dir)
{
	const u32 c_idx = gossmap_chan_idx(rq->gossmap, chan);
	return gossmap_chan_set(chan, dir) && chan->half[dir].enabled &&
	       !bitmap_test_bit(rq->disabled_chans, c_idx * 2 + dir);
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
		abort(); // we expect high > low
	if (!amount_msat_sub(&good_states, all_states, amount))
		abort(); // we expect high > amount
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
	 * The cap con capacity is not greater than the amount of payment units
	 * (msat/accuracy). The way a channel is decomposed into linear cost
	 * arcs (code below) in ascending cost order ensures that the only the
	 * necessary capacity to forward the payment is allocated in the lower
	 * cost arcs. This may lead to some arcs in the decomposition (at the
	 * high cost end) to have a capacity of 0, and we can prune them while
	 * keeping the solution optimal. */
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

			if (!channel_is_available(params->rq, c, half))
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
		const struct route_query *rq,
		const struct chan_flow *chan_flow,
		const struct node source,
		const s64 *balance,

		const struct gossmap_chan **prev_chan,
		int *prev_dir,
		u32 *prev_idx)
{
	const struct gossmap *gossmap = rq->gossmap;
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

			if (!channel_is_available(rq, c, dir))
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
			    working_ctx, params->rq, chan_flow, source,
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
	struct flow **flows, *f;
	flows = tal_arr(ctx, struct flow *, 1);
	f = flows[0] = tal(flows, struct flow);

	size_t length = 0;

	for (u32 cur_idx = destination.idx; cur_idx != source.idx;) {
		assert(cur_idx != INVALID_INDEX);
		length++;
		struct arc arc = prev[cur_idx];
		struct node next = arc_tail(graph, arc);
		cur_idx = next.idx;
	}
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
	/* -> We reduce the granularity of the flow by limiting the subdivision
	 * of the payment amount into 1000 units of flow. That reduces the
	 * computational burden for algorithms that depend on it, eg. "capacity
	 * scaling" and "successive shortest path".
	 * -> Using Ceil operation instead of Floor so that
	 *      accuracy x 1000 >= amount
	 * */
	params->accuracy =
	    amount_msat_max(AMOUNT_MSAT(1), amount_msat_div_ceil(amount, 1000));

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

			if (!channel_is_available(params->rq, c, half))
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
				abort();

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
				abort();
			u32 fee_msat;
			if (!amount_msat_to_u32(fee, &fee_msat))
				continue;
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

/* Get the scidd for the i'th hop in flow */
static void get_scidd(const struct gossmap *gossmap, const struct flow *flow,
		      size_t i, struct short_channel_id_dir *scidd)
{
	scidd->scid = gossmap_chan_scid(gossmap, flow->path[i]);
	scidd->dir = flow->dirs[i];
}

/* We use an fp16_t approximatin for htlc_max/min: this gets the exact value. */
static struct amount_msat
get_chan_htlc_max(const struct route_query *rq, const struct gossmap_chan *c,
		  const struct short_channel_id_dir *scidd)
{
	struct amount_msat htlc_max;

	gossmap_chan_get_update_details(rq->gossmap, c, scidd->dir, NULL, NULL,
					NULL, NULL, NULL, NULL, NULL,
					&htlc_max);
	return htlc_max;
}

static struct amount_msat
get_chan_htlc_min(const struct route_query *rq, const struct gossmap_chan *c,
		  const struct short_channel_id_dir *scidd)
{
	struct amount_msat htlc_min;

	gossmap_chan_get_update_details(rq->gossmap, c, scidd->dir, NULL, NULL,
					NULL, NULL, NULL, NULL, &htlc_min,
					NULL);
	return htlc_min;
}

static bool check_htlc_min_limits(struct route_query *rq, struct flow **flows)
{

	for (size_t k = 0; k < tal_count(flows); k++) {
		struct flow *flow = flows[k];
		size_t pathlen = tal_count(flow->path);
		struct amount_msat hop_amt = flow->delivers;
		for (size_t i = pathlen - 1; i < pathlen; i--) {
			const struct half_chan *h = flow_edge(flow, i);
			struct short_channel_id_dir scidd;

			get_scidd(rq->gossmap, flow, i, &scidd);
			struct amount_msat htlc_min =
			    get_chan_htlc_min(rq, flow->path[i], &scidd);
			if (amount_msat_less(hop_amt, htlc_min))
				return false;

			if (!amount_msat_add_fee(&hop_amt, h->base_fee,
						 h->proportional_fee))
				abort();
		}
	}
	return true;
}

static bool check_htlc_max_limits(struct route_query *rq, struct flow **flows)
{

	for (size_t k = 0; k < tal_count(flows); k++) {
		struct flow *flow = flows[k];
		size_t pathlen = tal_count(flow->path);
		struct amount_msat hop_amt = flow->delivers;
		for (size_t i = pathlen - 1; i < pathlen; i--) {
			const struct half_chan *h = flow_edge(flow, i);
			struct short_channel_id_dir scidd;

			get_scidd(rq->gossmap, flow, i, &scidd);
			struct amount_msat htlc_max =
			    get_chan_htlc_max(rq, flow->path[i], &scidd);
			if (amount_msat_greater(hop_amt, htlc_max))
				return false;

			if (!amount_msat_add_fee(&hop_amt, h->base_fee,
						 h->proportional_fee))
				abort();
		}
	}
	return true;
}

/* FIXME: add extra constraint maximum route length, use an activation
 * probability cost for each channel. Recall that every activation cost, eg.
 * base fee and activation probability can only be properly added modifying the
 * graph topology by creating an activation node for every half channel. */
/* FIXME: add extra constraint maximum number of routes, fixes issue 8331. */
/* FIXME: add a boolean option to make recipient pay for fees, fixes issue 8353.
 */
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
	const tal_t *working_ctx = tal(ctx, tal_t);
	const char *error_message;
	struct amount_msat amount_to_deliver = amount;
	struct amount_msat feebudget = maxfee;

	/* FIXME: mu is an integer from 0 to MU_MAX that we use to combine fees
	 * and probability costs, but I think we can make it a real number from
	 * 0 to 1. */
	u32 mu = 1;
	/* we start at 1e-6 and increase it exponentially (x2) up to 10. */
	double delay_feefactor = 1e-6;

	struct flow **new_flows = NULL;
	struct amount_msat all_deliver;

	*flows = tal_arr(working_ctx, struct flow *, 0);

	/* Re-use the reservation system to make flows aware of each other. */
	struct reserve_hop *reservations = new_reservations(working_ctx, rq);

	while (!amount_msat_is_zero(amount_to_deliver)) {
		size_t num_parts, parts_slots, excess_parts;
		u32 bottleneck_idx;

                /* FIXME: This algorithm to limit the number of parts is dumb
                 * for two reasons:
                 *      1. it does not take into account that several loop
                 *      iterations here may produce two flows along the same
                 *      path that after "squash_flows" become a single flow.
                 *      2. limiting the number of "slots" to 1 makes us fail to
                 *      see some solutions that use more than one of those
                 *      existing paths.
                 *
                 * A better approach could be to run MCF, remove the excess
                 * paths and then recompute a MCF on a network where each arc is
                 * one of the previously remaining paths, ie. redistributing the
                 * payment amount among the selected paths in a cost-efficient
                 * way. */
		new_flows = tal_free(new_flows);
		num_parts = tal_count(*flows);
		assert(num_parts < rq->maxparts);
		parts_slots = rq->maxparts - num_parts;

		/* If the amount_to_deliver is very small we better use a single
		 * path computation because:
		 * 1. we save cpu cycles
		 * 2. we have better control over htlc_min violations.
                 * We need to make the distinction here because after
                 * refine_with_fees_and_limits we might have a set of flows that
                 * do not deliver the entire payment amount by just a small
                 * amount. */
		if (amount_msat_less_eq(amount_to_deliver,
					SINGLE_PATH_THRESHOLD) ||
		    parts_slots == 1) {
			new_flows = single_path_flow(working_ctx, rq, srcnode,
						     dstnode, amount_to_deliver,
						     mu, delay_feefactor);
		} else {
			new_flows =
			    solver(working_ctx, rq, srcnode, dstnode,
				   amount_to_deliver, mu, delay_feefactor);
		}

		if (!new_flows) {
			error_message = explain_failure(
			    ctx, rq, srcnode, dstnode, amount_to_deliver);
			goto fail;
		}

		error_message =
			refine_flows(ctx, rq, amount_to_deliver, &new_flows, &bottleneck_idx);
		if (error_message)
			goto fail;

		/* we finished removing flows and excess */
		all_deliver = flowset_delivers(rq->plugin, new_flows);
		if (amount_msat_is_zero(all_deliver)) {
			/* We removed all flows and we have not modified the
			 * MCF parameters. We will not have an infinite loop
			 * here because at least we have disabled some channels.
			 */
			continue;
		}

		/* We might want to overpay sometimes, eg. shadow routing, but
		 * right now if all_deliver > amount_to_deliver means a bug. */
		assert(amount_msat_greater_eq(amount_to_deliver, all_deliver));

		/* no flows should send 0 amount */
		for (size_t i = 0; i < tal_count(new_flows); i++) {
                        // FIXME: replace all assertions with LOG_BROKEN
			assert(!amount_msat_is_zero(new_flows[i]->delivers));
		}

		if (tal_count(new_flows) > parts_slots) {
			/* Remove the excees of parts and leave one slot for the
			 * next round of computations. */
			excess_parts = 1 + tal_count(new_flows) - parts_slots;
		} else if (tal_count(new_flows) == parts_slots &&
			   amount_msat_less(all_deliver, amount_to_deliver)) {
			/* Leave exactly 1 slot for the next round of
			 * computations. */
			excess_parts = 1;
		} else
			excess_parts = 0;
		if (excess_parts > 0) {
			/* If we removed all the flows we found, avoid selecting them again,
			 * by disabling one. */
			if (excess_parts == tal_count(new_flows))
				bitmap_set_bit(rq->disabled_chans, bottleneck_idx);
			if (!remove_flows(&new_flows, excess_parts)) {
				error_message = rq_log(ctx, rq, LOG_BROKEN,
						       "%s: failed to remove %zu"
						       " flows from a set of %zu",
						       __func__, excess_parts,
						       tal_count(new_flows));
				goto fail;
			}
		}

		/* Is this set of flows too expensive?
		 * We can check if the new flows are within the fee budget,
		 * however in some cases we have discarded some flows at this
		 * point and the new flows do not deliver all the value we need
		 * so that a further solver iteration is needed. Hence we
		 * check if the fees paid by these new flows are below the
		 * feebudget proportionally adjusted by the amount this set of
		 * flows deliver with respect to the total remaining amount,
		 * ie. we avoid "consuming" all the feebudget if we still need
		 * to run MCF again for some remaining amount. */
		struct amount_msat all_fees =
		    flowset_fee(rq->plugin, new_flows);
		const double deliver_fraction =
		    amount_msat_ratio(all_deliver, amount_to_deliver);
		struct amount_msat partial_feebudget;
		if (!amount_msat_scale(&partial_feebudget, feebudget,
				       deliver_fraction)) {
			error_message =
			    rq_log(ctx, rq, LOG_BROKEN,
				   "%s: failed to scale the fee budget (%s) by "
				   "fraction (%lf)",
				   __func__, fmt_amount_msat(tmpctx, feebudget),
				   deliver_fraction);
			goto fail;
		}
		if (amount_msat_greater(all_fees, partial_feebudget)) {
			if (mu < MU_MAX) {
				/* all_fees exceed the strong budget limit, try
				 * to fix it increasing mu. */
				if (mu == 1)
					mu = 10;
				else
					mu += 10;
				mu = MIN(mu, MU_MAX);
				rq_log(
				    tmpctx, rq, LOG_INFORM,
				    "The flows had a fee of %s, greater than "
				    "max of %s, retrying with mu of %u%%...",
				    fmt_amount_msat(tmpctx, all_fees),
				    fmt_amount_msat(tmpctx, partial_feebudget),
				    mu);
				continue;
			} else if (amount_msat_greater(all_fees, feebudget)) {
				/* we cannot increase mu anymore and all_fees
				 * already exceeds feebudget we fail. */
				error_message =
				    rq_log(ctx, rq, LOG_UNUSUAL,
					   "Could not find route without "
					   "excessive cost");
				goto fail;
			} else {
				/* mu cannot be increased but at least all_fees
				 * does not exceed feebudget, we give it a shot.
				 */
				rq_log(
				    tmpctx, rq, LOG_UNUSUAL,
				    "The flows had a fee of %s, greater than "
				    "max of %s, but still within the fee "
				    "budget %s, we accept those flows.",
				    fmt_amount_msat(tmpctx, all_fees),
				    fmt_amount_msat(tmpctx, partial_feebudget),
				    fmt_amount_msat(tmpctx, feebudget));
			}
		}

		/* Too much delay? */
		if (finalcltv + flows_worst_delay(new_flows) > maxdelay) {
			if (delay_feefactor > 10) {
				error_message =
				    rq_log(ctx, rq, LOG_UNUSUAL,
					   "Could not find route without "
					   "excessive delays");
				goto fail;
			}

			delay_feefactor *= 2;
			rq_log(tmpctx, rq, LOG_INFORM,
			       "The worst flow delay is %" PRIu64
			       " (> %i), retrying with delay_feefactor %f...",
			       flows_worst_delay(new_flows), maxdelay - finalcltv,
			       delay_feefactor);
                        continue;
		}

		all_fees = AMOUNT_MSAT(0);
		all_deliver = AMOUNT_MSAT(0);
		/* add the new flows to the final solution */
		for (size_t i = 0; i < tal_count(new_flows); i++) {
			/* last check: every time we add a new reservation to a
			 * local channel we remove some amount to pay for fees
			 * on the additional HTLC. */
			if (create_flow_reservations_verify(rq, &reservations,
							    new_flows[i])) {
				tal_arr_expand(flows, new_flows[i]);
				tal_steal(*flows, new_flows[i]);
				if (!amount_msat_accumulate(
					&all_deliver, new_flows[i]->delivers) ||
				    !amount_msat_accumulate(
					&all_fees,
					flow_fee(rq->plugin, new_flows[i])))
					abort();
			}
		}

		if (!amount_msat_sub(&feebudget, feebudget, all_fees) ||
		    !amount_msat_sub(&amount_to_deliver, amount_to_deliver,
				     all_deliver)) {
			error_message =
			    rq_log(ctx, rq, LOG_BROKEN,
				   "%s: unexpected arithmetic operation "
				   "failure on amount_msat",
				   __func__);
			goto fail;
		}
	}
	/* transfer ownership */
	*flows = tal_steal(ctx, *flows);

	/* cleanup */
	tal_free(working_ctx);

	/* all set! Now squash flows that use the same path */
	squash_flows(ctx, rq, flows);

	/* flows_probability re-does a temporary reservation so we need to call
	 * it after we have cleaned the reservations we used to build the flows
	 * hence after we freed working_ctx. */
	*probability = flows_probability(ctx, rq, flows);

	/* we should have fixed all htlc violations, "don't trust,
	 * verify" */
	if (!check_htlc_min_limits(rq, *flows)) {
		error_message =
		    rq_log(rq, rq, LOG_BROKEN,
			   "%s: check_htlc_min_limits failed", __func__);
		*flows = tal_free(*flows);
		goto fail;
	}
	if (!check_htlc_max_limits(rq, *flows)) {
		error_message =
		    rq_log(rq, rq, LOG_BROKEN,
			   "%s: check_htlc_max_limits failed", __func__);
		*flows = tal_free(*flows);
		goto fail;
	}
	if (tal_count(*flows) > rq->maxparts) {
		error_message = rq_log(
		    rq, rq, LOG_BROKEN,
		    "%s: the number of flows (%zu) exceeds the limit set "
		    "on payment parts (%" PRIu32
		    "), please submit a bug report",
		    __func__, tal_count(*flows), rq->maxparts);
		*flows = tal_free(*flows);
		goto fail;
	}

	return NULL;
fail:
	/* cleanup */
	tal_free(working_ctx);

	assert(error_message != NULL);
	return error_message;
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
