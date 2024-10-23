#include "config.h"
#include <assert.h>
#include <ccan/asort/asort.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/utils.h>
#include <float.h>
#include <math.h>
#include <plugins/askrene/algorithm.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/dijkstra.h>
#include <plugins/askrene/flow.h>
#include <plugins/askrene/graph.h>
#include <plugins/askrene/mcf.h>
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

/* Representation of the linear MCF network.
 * This contains the topology of the extended network (after linearization and
 * addition of arc duality).
 * This contains also the arc probability and linear fee cost, as well as
 * capacity; these quantities remain constant during MCF execution. */
struct linear_network
{
	struct graph *graph;

	// probability and fee cost associated to an arc
	double *arc_prob_cost;
	s64 *arc_fee_cost;
	s64 *capacity;
};

/* This is the structure that keeps track of the network properties while we
 * seek for a solution. */
struct residual_network {
	/* residual capacity on arcs */
	s64 *cap;

	/* some combination of prob. cost and fee cost on arcs */
	s64 *cost;

	/* potential function on nodes */
	s64 *potential;

	/* auxiliary data, the excess of flow on nodes */
	s64 *excess;
};

/* Helper function.
 * Given an arc of the network (not residual) give me the flow. */
static s64 get_arc_flow(
		const struct residual_network *network,
		const struct graph *graph,
		const struct arc arc)
{
	assert(!arc_is_dual(graph, arc));
	struct arc dual = arc_dual(graph, arc);
	assert(dual.idx < tal_count(network->cap));
	return network->cap[dual.idx];
}

/* Set *capacity to value, up to *cap_on_capacity.  Reduce cap_on_capacity */
static void set_capacity(s64 *capacity, u64 value, u64 *cap_on_capacity)
{
	*capacity = MIN(value, *cap_on_capacity);
	*cap_on_capacity -= *capacity;
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
	 * that it does not exceed htlcmax. */
	u64 cap_on_capacity =
	    amount_msat_ratio_floor(gossmap_chan_htlc_max(c, dir), params->accuracy);

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

static struct residual_network *
alloc_residual_network(const tal_t *ctx, const size_t max_num_nodes,
		      const size_t max_num_arcs)
{
	struct residual_network *residual_network =
	    tal(ctx, struct residual_network);

	residual_network->cap = tal_arrz(residual_network, s64, max_num_arcs);
	residual_network->cost = tal_arrz(residual_network, s64, max_num_arcs);
	residual_network->potential =
	    tal_arrz(residual_network, s64, max_num_nodes);
	residual_network->excess =
	    tal_arrz(residual_network, s64, max_num_nodes);

	return residual_network;
}

static void init_residual_network(
		const struct linear_network * linear_network,
		struct residual_network* residual_network)
{
	const struct graph *graph = linear_network->graph;
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	for (struct arc arc = {.idx = 0}; arc.idx < max_num_arcs; ++arc.idx) {
		if (arc_is_dual(graph, arc) || !arc_enabled(graph, arc))
			continue;

		struct arc dual = arc_dual(graph, arc);
		residual_network->cap[arc.idx] =
		    linear_network->capacity[arc.idx];
		residual_network->cap[dual.idx] = 0;

		residual_network->cost[arc.idx] =
		    residual_network->cost[dual.idx] = 0;
	}
	for (u32 i = 0; i < max_num_nodes; ++i) {
		residual_network->potential[i] = 0;
		residual_network->excess[i] = 0;
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
			       const struct linear_network* linear_network)
{
	const struct graph *graph = linear_network->graph;
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	u64 *u64_arr = tal_arr(working_ctx, u64, max_num_arcs);
	double *double_arr = tal_arr(working_ctx, double, max_num_arcs);
	size_t n = 0;

	for (struct arc arc = {.idx=0};arc.idx < max_num_arcs; ++arc.idx) {
		/* scan real arcs, not unused id slots or dual arcs */
		if (arc_is_dual(graph, arc) || !arc_enabled(graph, arc))
			continue;
		assert(n < max_num_arcs/2);
		u64_arr[n] = linear_network->arc_fee_cost[arc.idx];
		double_arr[n] = linear_network->arc_prob_cost[arc.idx];
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

static void combine_cost_function(
		const tal_t *working_ctx,
		const struct linear_network* linear_network,
		struct residual_network *residual_network,
		const s8 *biases,
		s64 mu)
{
	/* probabilty and fee costs are not directly comparable!
	 * Scale by ratio of (positive) medians. */
	const double k = get_median_ratio(working_ctx, linear_network);
	const double ln_30 = log(30);
	const struct graph *graph = linear_network->graph;
	const size_t max_num_arcs = graph_max_num_arcs(graph);

	for(struct arc arc = {.idx=0};arc.idx < max_num_arcs; ++arc.idx)
	{
		if (arc_is_dual(graph, arc) || !arc_enabled(graph, arc))
			continue;

		const double pcost = linear_network->arc_prob_cost[arc.idx];
		const s64 fcost = linear_network->arc_fee_cost[arc.idx];
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
			residual_network->cost[arc.idx] = combined * bias_factor;
		} else {
			residual_network->cost[arc.idx] = combined;
		}
		/* and the respective dual */
		struct arc dual = arc_dual(graph, arc);
		residual_network->cost[dual.idx] = -combined;
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

/* FIXME: Instead of mapping one-to-one the indexes in the gossmap, try to
 * reduce the number of nodes and arcs used by taking only those that are
 * enabled. We might save some cpu if the work with a pruned network. */
static struct linear_network *
init_linear_network(const tal_t *ctx, const struct pay_parameters *params)
{
	struct linear_network * linear_network = tal(ctx, struct linear_network);
	const struct gossmap *gossmap = params->rq->gossmap;

	const size_t max_num_chans = gossmap_max_chan_idx(gossmap);
	const size_t max_num_arcs = max_num_chans * ARCS_PER_CHANNEL;
	const size_t max_num_nodes = gossmap_max_node_idx(gossmap);

	linear_network->graph =
	    graph_new(ctx, max_num_nodes, max_num_arcs, ARC_DUAL_BITOFF);

	linear_network->arc_prob_cost = tal_arr(linear_network,double,max_num_arcs);
	for(size_t i=0;i<max_num_arcs;++i)
		linear_network->arc_prob_cost[i]=DBL_MAX;

	linear_network->arc_fee_cost = tal_arr(linear_network,s64,max_num_arcs);
	for(size_t i=0;i<max_num_arcs;++i)
		linear_network->arc_fee_cost[i]=INFINITE;

	linear_network->capacity = tal_arrz(linear_network,s64,max_num_arcs);

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
				/* FIXME: Can we prune arcs with 0 capacity?
				 * if(capacity[k]==0)continue; */

				struct arc arc = arc_from_parts(chan_id, half, k, false);

				graph_add_arc(linear_network->graph, arc,
					      node_obj(node_id),
					      node_obj(next_id));

				linear_network->capacity[arc.idx] = capacity[k];
				linear_network->arc_prob_cost[arc.idx] = prob_cost[k];
				linear_network->arc_fee_cost[arc.idx] = fee_cost;

				// + the respective dual
				struct arc dual = arc_dual(linear_network->graph, arc);

				linear_network->capacity[dual.idx] = 0;
				linear_network->arc_prob_cost[dual.idx] = -prob_cost[k];
				linear_network->arc_fee_cost[dual.idx] = -fee_cost;
			}
		}
	}

	return linear_network;
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
	       const struct linear_network *linear_network,
	       const struct residual_network *residual_network)
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
	const struct graph *graph = linear_network->graph;
	for (struct node n = {.idx = 0}; n.idx < max_num_nodes; n.idx++) {
		for(struct arc arc = node_adjacency_begin(graph,n);
		        !node_adjacency_end(arc);
			arc = node_adjacency_next(graph,arc))
		{
			if(arc_is_dual(graph, arc))
				continue;
			struct node m = arc_head(graph,arc);
			s64 flow = get_arc_flow(residual_network,
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
	params->accuracy = AMOUNT_MSAT(1000);
	/* FIXME: params->accuracy = amount_msat_max(amount_msat_div(amount,
	 * 1000), AMOUNT_MSAT(1));
	 * */

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
	struct linear_network *linear_network= init_linear_network(working_ctx, params);
	const struct graph *graph = linear_network->graph;
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);
	struct residual_network *residual_network =
	    alloc_residual_network(working_ctx, max_num_nodes, max_num_arcs);

	const struct node dst = {.idx = gossmap_node_idx(rq->gossmap, target)};
	const struct node src = {.idx = gossmap_node_idx(rq->gossmap, source)};

	init_residual_network(linear_network,residual_network);

	/* Since we have constraint accuracy, ask to find a payment solution
	 * that can pay a bit more than the actual value rathen than undershoot it.
	 * That's why we use the ceil function here. */
	const u64 pay_amount =
	    amount_msat_ratio_ceil(params->amount, params->accuracy);

	if (!simple_feasibleflow(working_ctx, linear_network->graph, src, dst,
				 residual_network->cap, pay_amount)) {
		rq_log(tmpctx, rq, LOG_INFORM,
		       "%s failed: unable to find a feasible flow.", __func__);
		goto fail;
	}
	combine_cost_function(working_ctx, linear_network, residual_network,
			      rq->biases, mu);

	/* We solve a linear MCF problem. */
	if (!mcf_refinement(working_ctx,
			    linear_network->graph,
			    residual_network->excess,
			    residual_network->cap,
			    residual_network->cost,
			    residual_network->potential)) {
		rq_log(tmpctx, rq, LOG_BROKEN,
		       "%s: MCF optimization step failed", __func__);
		goto fail;
	}

	/* We dissect the solution of the MCF into payment routes.
	 * Actual amounts considering fees are computed for every
	 * channel in the routes. */
	flow_paths = get_flow_paths(ctx, working_ctx, params,
				    linear_network, residual_network);
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
