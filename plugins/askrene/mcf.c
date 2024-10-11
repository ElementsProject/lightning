#include "config.h"
#include <assert.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/utils.h>
#include <math.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/dijkstra.h>
#include <plugins/askrene/flow.h>
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
 * k/1000, for instance, becomes the equivalent monetary cost
 * of increasing the probability of success by 0.1% for P~100%.
 *
 * The input parameter `prob_cost_factor` in the function `minflow` is defined
 * as the PPM from the delivery amount `T` we are *willing to pay* to increase the
 * prob. of success by 0.1%:
 *
 * 	k_microsat = floor(1000*prob_cost_factor * T_sat)
 *
 * Is this enough to make integer prob. cost per unit flow?
 * For `prob_cost_factor=10`; i.e. we pay 10ppm for increasing the prob. by
 * 0.1%, we get that
 *
 * 	-> any arc with (b-a) > 10000 T, will have zero prob. cost, which is
 * 	reasonable because even if all the flow passes through that arc, we get
 * 	a 1.3 T/(b-a) ~ 0.01% prob. of failure at most.
 *
 * 	-> if (b-a) ~ 10000 T, then the arc will have unit cost, or just that we
 * 	pay 1 microsat for every sat we send through this arc.
 *
 * 	-> it would be desirable to have a high proportional fee when (b-a)~T,
 * 	because prob. of failure start to become very high.
 * 	In this case we get to pay 10000 microsats for every sat.
 *
 * Once `k` is fixed then we can combine the linear prob. and fee costs, both
 * are in monetary units.
 *
 * Note: with costs in microsats, because slopes represent ppm and flows are in
 * sats, then our integer bounds with 64 bits are such that we can move as many
 * as 10'000 BTC without overflow:
 *
 * 	10^6 (max ppm) * 10^8 (sats per BTC) * 10^4 = 10^18
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
static const u32 INVALID_INDEX = 0xffffffff;
static const s64 MU_MAX = 101;

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
struct arc {
	u32 idx;
};

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

	// channel linearization parameters
	double cap_fraction[CHANNEL_PARTS],
	       cost_fraction[CHANNEL_PARTS];

	double delay_feefactor;
	double base_fee_penalty;
	u32 prob_cost_factor;
};

/* Representation of the linear MCF network.
 * This contains the topology of the extended network (after linearization and
 * addition of arc duality).
 * This contains also the arc probability and linear fee cost, as well as
 * capacity; these quantities remain constant during MCF execution. */
struct linear_network
{
	u32 *arc_tail_node;
	// notice that a tail node is not needed,
	// because the tail of arc is the head of dual(arc)

	struct arc *node_adjacency_next_arc;
	struct arc *node_adjacency_first_arc;

	// probability and fee cost associated to an arc
	s64 *arc_prob_cost, *arc_fee_cost;
	s64 *capacity;

	size_t max_num_arcs,max_num_nodes;
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
};

/* Helper function.
 * Given an arc idx, return the dual's idx in the residual network. */
static struct arc arc_dual(struct arc arc)
{
	arc.idx ^= (1U << ARC_DUAL_BITOFF);
	return arc;
}
/* Helper function. */
static bool arc_is_dual(struct arc arc)
{
	bool dual;
	arc_to_parts(arc, NULL, NULL, NULL, &dual);
	return dual;
}

/* Helper function.
 * Given an arc of the network (not residual) give me the flow. */
static s64 get_arc_flow(
		const struct residual_network *network,
		const struct arc arc)
{
	assert(!arc_is_dual(arc));
	assert(arc_dual(arc).idx < tal_count(network->cap));
	return network->cap[ arc_dual(arc).idx ];
}

/* Helper function.
 * Given an arc idx, return the node from which this arc emanates in the residual network. */
static u32 arc_tail(const struct linear_network *linear_network,
                    const struct arc arc)
{
	assert(arc.idx < linear_network->max_num_arcs);
	return linear_network->arc_tail_node[ arc.idx ];
}
/* Helper function.
 * Given an arc idx, return the node that this arc is pointing to in the residual network. */
static u32 arc_head(const struct linear_network *linear_network,
                    const struct arc arc)
{
	const struct arc dual = arc_dual(arc);
	assert(dual.idx < linear_network->max_num_arcs);
	return linear_network->arc_tail_node[dual.idx];
}

/* Helper function.
 * Given node idx `node`, return the idx of the first arc whose tail is `node`.
 * */
static struct arc node_adjacency_begin(
		const struct linear_network * linear_network,
		const u32 node)
{
	assert(node < linear_network->max_num_nodes);
	return linear_network->node_adjacency_first_arc[node];
}

/* Helper function.
 * Is this the end of the adjacency list. */
static bool node_adjacency_end(const struct arc arc)
{
	return arc.idx == INVALID_INDEX;
}

/* Helper function.
 * Given node idx `node` and `arc`, returns the idx of the next arc whose tail is `node`. */
static struct arc node_adjacency_next(
		const struct linear_network *linear_network,
		const struct arc arc)
{
	assert(arc.idx < linear_network->max_num_arcs);
	return linear_network->node_adjacency_next_arc[arc.idx];
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
			      s64 *capacity, s64 *cost)
{
	struct amount_msat mincap, maxcap;

	/* This takes into account any payments in progress. */
	get_constraints(params->rq, c, dir, &mincap, &maxcap);

	/* Assume if min > max, min is wrong */
	if (amount_msat_greater(mincap, maxcap))
		mincap = maxcap;

	u64 a = mincap.millisatoshis/1000, /* Raw: linearize_channel */
	    b = 1 + maxcap.millisatoshis/1000; /* Raw: linearize_channel */

	/* An extra bound on capacity, here we use it to reduce the flow such
	 * that it does not exceed htlcmax. */
	u64 cap_on_capacity = fp16_to_u64(c->half[dir].htlc_max) / 1000;

	set_capacity(&capacity[0], a, &cap_on_capacity);
	cost[0]=0;
	for(size_t i=1;i<CHANNEL_PARTS;++i)
	{
		set_capacity(&capacity[i], params->cap_fraction[i]*(b-a), &cap_on_capacity);

		cost[i] = params->cost_fraction[i]
		          *params->amount.millisatoshis /* Raw: linearize_channel */
		          *params->prob_cost_factor*1.0/(b-a);
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

	return residual_network;
}

static void init_residual_network(
		const struct linear_network * linear_network,
		struct residual_network* residual_network)
{
	const size_t max_num_arcs = linear_network->max_num_arcs;
	const size_t max_num_nodes = linear_network->max_num_nodes;

	for(struct arc arc = {0};arc.idx < max_num_arcs; ++arc.idx)
	{
		if(arc_is_dual(arc))
			continue;

		struct arc dual = arc_dual(arc);
		residual_network->cap[arc.idx]=linear_network->capacity[arc.idx];
		residual_network->cap[dual.idx]=0;

		residual_network->cost[arc.idx]=residual_network->cost[dual.idx]=0;
	}
	for(u32 i=0;i<max_num_nodes;++i)
	{
		residual_network->potential[i]=0;
	}
}

static void combine_cost_function(
		const struct linear_network* linear_network,
		struct residual_network *residual_network,
		s64 mu)
{
	for(struct arc arc = {0};arc.idx < linear_network->max_num_arcs; ++arc.idx)
	{
		if(arc_tail(linear_network,arc)==INVALID_INDEX)
			continue;

		const s64 pcost = linear_network->arc_prob_cost[arc.idx],
		          fcost = linear_network->arc_fee_cost[arc.idx];

		const s64 combined = pcost==INFINITE || fcost==INFINITE ? INFINITE :
		                     mu*fcost + (MU_MAX-1-mu)*pcost;

		residual_network->cost[arc.idx]
			= mu==0 ? pcost :
			          (mu==(MU_MAX-1) ? fcost : combined);
	}
}

static void linear_network_add_adjacenct_arc(
		struct linear_network *linear_network,
		const u32 node_idx,
		const struct arc arc)
{
	assert(arc.idx < linear_network->max_num_arcs);
	linear_network->arc_tail_node[arc.idx] = node_idx;

	assert(node_idx < linear_network->max_num_nodes);
	const struct arc first_arc = linear_network->node_adjacency_first_arc[node_idx];

	linear_network->node_adjacency_next_arc[arc.idx]=first_arc;
	linear_network->node_adjacency_first_arc[node_idx]=arc;
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
static s64 linear_fee_cost(
		const struct gossmap_chan *c,
		const int dir,
		double base_fee_penalty,
		double delay_feefactor)
{
	assert(c);
	assert(dir==0 || dir==1);
	s64 pfee = c->half[dir].proportional_fee,
	    bfee = c->half[dir].base_fee,
	    delay = c->half[dir].delay;

	return pfee + bfee* base_fee_penalty+ delay*delay_feefactor;
}

static struct linear_network *
init_linear_network(const tal_t *ctx, const struct pay_parameters *params)
{
	struct linear_network * linear_network = tal(ctx, struct linear_network);
	const struct gossmap *gossmap = params->rq->gossmap;

	const size_t max_num_chans = gossmap_max_chan_idx(gossmap);
	const size_t max_num_arcs = max_num_chans * ARCS_PER_CHANNEL;
	const size_t max_num_nodes = gossmap_max_node_idx(gossmap);

	linear_network->max_num_arcs = max_num_arcs;
	linear_network->max_num_nodes = max_num_nodes;

	linear_network->arc_tail_node = tal_arr(linear_network,u32,max_num_arcs);
	for(size_t i=0;i<max_num_arcs;++i)
		linear_network->arc_tail_node[i]=INVALID_INDEX;

	linear_network->node_adjacency_next_arc = tal_arr(linear_network,struct arc,max_num_arcs);
	for(size_t i=0;i<max_num_arcs;++i)
		linear_network->node_adjacency_next_arc[i].idx=INVALID_INDEX;

	linear_network->node_adjacency_first_arc = tal_arr(linear_network,struct arc,max_num_nodes);
	for(size_t i=0;i<max_num_nodes;++i)
		linear_network->node_adjacency_first_arc[i].idx=INVALID_INDEX;

	linear_network->arc_prob_cost = tal_arr(linear_network,s64,max_num_arcs);
	for(size_t i=0;i<max_num_arcs;++i)
		linear_network->arc_prob_cost[i]=INFINITE;

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
			s64 prob_cost[CHANNEL_PARTS], capacity[CHANNEL_PARTS];

			// split this channel direction to obtain the arcs
			// that are outgoing to `node`
			linearize_channel(params, c, half, capacity, prob_cost);

			const s64 fee_cost = linear_fee_cost(c,half,
						params->base_fee_penalty,
						params->delay_feefactor);

			// let's subscribe the 4 parts of the channel direction
			// (c,half), the dual of these guys will be subscribed
			// when the `i` hits the `next` node.
			for(size_t k=0;k<CHANNEL_PARTS;++k)
			{
				// if(capacity[k]==0)continue;

				struct arc arc = arc_from_parts(chan_id, half, k, false);

				linear_network_add_adjacenct_arc(linear_network,node_id,arc);

				linear_network->capacity[arc.idx] = capacity[k];
				linear_network->arc_prob_cost[arc.idx] = prob_cost[k];

				linear_network->arc_fee_cost[arc.idx] = fee_cost;

				// + the respective dual
				struct arc dual = arc_dual(arc);

				linear_network_add_adjacenct_arc(linear_network,next_id,dual);

				linear_network->capacity[dual.idx] = 0;
				linear_network->arc_prob_cost[dual.idx] = -prob_cost[k];

				linear_network->arc_fee_cost[dual.idx] = -fee_cost;
			}
		}
	}

	return linear_network;
}

// TODO(eduardo): unit test this
/* Finds an admissible path from source to target, traversing arcs in the
 * residual network with capacity greater than 0.
 * The path is encoded into prev, which contains the idx of the arcs that are
 * traversed. */
static bool
find_admissible_path(const struct linear_network *linear_network,
		     const struct residual_network *residual_network,
		     const u32 source, const u32 target, struct arc *prev)
{
	bool target_found = false;
	/* Simple linear queue of node indexes */
	u32 *queue = tal_arr(tmpctx, u32, linear_network->max_num_arcs);
	size_t qstart, qend, prev_len = tal_count(prev);

	for(size_t i=0;i<prev_len;++i)
		prev[i].idx=INVALID_INDEX;

	// The graph is dense, and the farthest node is just a few hops away,
	// hence let's BFS search.
	queue[0] = source;
	qstart = 0;
	qend = 1;

	while (qstart < qend) {
		u32 cur = queue[qstart++];

		if(cur==target)
		{
			target_found = true;
			break;
		}

		for(struct arc arc = node_adjacency_begin(linear_network,cur);
		        !node_adjacency_end(arc);
			arc = node_adjacency_next(linear_network,arc))
		{
			// check if this arc is traversable
			if(residual_network->cap[arc.idx] <= 0)
				continue;

			u32 next = arc_head(linear_network,arc);

			assert(next < prev_len);

			// if that node has been seen previously
			if(prev[next].idx!=INVALID_INDEX)
				continue;

			prev[next] = arc;
			assert(qend < linear_network->max_num_arcs);
			queue[qend++] = next;
		}
	}
	return target_found;
}

/* Get the max amount of flow one can send from source to target along the path
 * encoded in `prev`. */
static s64 get_augmenting_flow(
		const struct linear_network* linear_network,
		const struct residual_network *residual_network,
	        const u32 source,
		const u32 target,
		const struct arc *prev)
{
	s64 flow = INFINITE;

	u32 cur = target;
	while(cur!=source)
	{
		assert(cur<tal_count(prev));
		const struct arc arc = prev[cur];
		flow = MIN(flow , residual_network->cap[arc.idx]);

		// we are traversing in the opposite direction to the flow,
		// hence the next node is at the tail of the arc.
		cur = arc_tail(linear_network,arc);
	}

	assert(flow<INFINITE && flow>0);
	return flow;
}

/* Augment a `flow` amount along the path defined by `prev`.*/
static void augment_flow(
		const struct linear_network *linear_network,
		struct residual_network *residual_network,
	        const u32 source,
		const u32 target,
		const struct arc *prev,
		s64 flow)
{
	u32 cur = target;

	while(cur!=source)
	{
		assert(cur < tal_count(prev));
		const struct arc arc = prev[cur];
		const struct arc dual = arc_dual(arc);

		assert(arc.idx < tal_count(residual_network->cap));
		assert(dual.idx < tal_count(residual_network->cap));

		residual_network->cap[arc.idx] -= flow;
		residual_network->cap[dual.idx] += flow;

		assert(residual_network->cap[arc.idx] >=0 );

		// we are traversing in the opposite direction to the flow,
		// hence the next node is at the tail of the arc.
		cur = arc_tail(linear_network,arc);
	}
}


// TODO(eduardo): unit test this
/* Finds any flow that satisfy the capacity and balance constraints of the
 * uncertainty network. For the balance function condition we have:
 * 	balance(source) = - balance(target) = amount
 * 	balance(node) = 0 , for every other node
 * Returns an error code if no feasible flow is found.
 *
 * 13/04/2023 This implementation uses a simple augmenting path approach.
 * */
static bool find_feasible_flow(const struct linear_network *linear_network,
			       struct residual_network *residual_network,
			       const u32 source, const u32 target, s64 amount)
{
	assert(amount>=0);

	/* path information
	 * prev: is the id of the arc that lead to the node. */
	struct arc *prev = tal_arr(tmpctx,struct arc,linear_network->max_num_nodes);

	while(amount>0)
	{
		// find a path from source to target
		if (!find_admissible_path(linear_network,
					  residual_network, source, target,
					  prev)) {
			return false;
		}

		// traverse the path and see how much flow we can send
		s64 delta = get_augmenting_flow(linear_network,
						residual_network,
						source,target,prev);

		// commit that flow to the path
		delta = MIN(amount,delta);
		assert(delta>0 && delta<=amount);

		augment_flow(linear_network,residual_network,source,target,prev,delta);
		amount -= delta;
	}

	return true;
}

// TODO(eduardo): unit test this
/* Similar to `find_admissible_path` but use Dijkstra to optimize the distance
 * label. Stops when the target is hit. */
static bool find_optimal_path(struct dijkstra *dijkstra,
			      const struct linear_network *linear_network,
			      const struct residual_network *residual_network,
			      const u32 source, const u32 target,
			      struct arc *prev)
{
	bool target_found = false;

	bitmap *visited = tal_arrz(tmpctx, bitmap,
				   BITMAP_NWORDS(linear_network->max_num_nodes));
	for(size_t i=0;i<tal_count(prev);++i)
		prev[i].idx=INVALID_INDEX;

	const s64 *const distance=dijkstra_distance_data(dijkstra);

	dijkstra_init(dijkstra);
	dijkstra_update(dijkstra,source,0);

	while(!dijkstra_empty(dijkstra))
	{
		u32 cur = dijkstra_top(dijkstra);
		dijkstra_pop(dijkstra);

		if(bitmap_test_bit(visited,cur))
			continue;

		bitmap_set_bit(visited,cur);

		if(cur==target)
		{
			target_found = true;
			break;
		}

		for(struct arc arc = node_adjacency_begin(linear_network,cur);
		        !node_adjacency_end(arc);
			arc = node_adjacency_next(linear_network,arc))
		{
			// check if this arc is traversable
			if(residual_network->cap[arc.idx] <= 0)
				continue;

			u32 next = arc_head(linear_network,arc);

			s64 cij = residual_network->cost[arc.idx]
					- residual_network->potential[cur]
					+ residual_network->potential[next];

			// Dijkstra only works with non-negative weights
			assert(cij>=0);

			if(distance[next]<=distance[cur]+cij)
				continue;

			dijkstra_update(dijkstra,next,distance[cur]+cij);
			prev[next]=arc;
		}
	}

	return target_found;
}

/* Set zero flow in the residual network. */
static void zero_flow(
		const struct linear_network *linear_network,
		struct residual_network *residual_network)
{
	for(u32 node=0;node<linear_network->max_num_nodes;++node)
	{
		residual_network->potential[node]=0;
		for(struct arc arc=node_adjacency_begin(linear_network,node);
			  !node_adjacency_end(arc);
			  arc = node_adjacency_next(linear_network,arc))
		{
			if(arc_is_dual(arc))continue;

			struct arc dual = arc_dual(arc);

			residual_network->cap[arc.idx] = linear_network->capacity[arc.idx];
			residual_network->cap[dual.idx] = 0;
		}
	}
}

// TODO(eduardo): unit test this
/* Starting from a feasible flow (satisfies the balance and capacity
 * constraints), find a solution that minimizes the network->cost function.
 *
 * TODO(eduardo) The MCF must be called several times until we get a good
 * compromise between fees and probabilities. Instead of re-computing the MCF at
 * each step, we might use the previous flow result, which is not optimal in the
 * current iteration but I might be not too far from the truth.
 * It comes to mind to use cycle cancelling. */
static bool optimize_mcf(struct dijkstra *dijkstra,
			 const struct linear_network *linear_network,
			 struct residual_network *residual_network,
			 const u32 source, const u32 target, const s64 amount)
{
	assert(amount>=0);

	zero_flow(linear_network,residual_network);
	struct arc *prev = tal_arr(tmpctx,struct arc,linear_network->max_num_nodes);

	const s64 *const distance = dijkstra_distance_data(dijkstra);

	s64 remaining_amount = amount;

	while(remaining_amount>0)
	{
		if (!find_optimal_path(dijkstra, linear_network,
				       residual_network, source, target, prev)) {
			return false;
		}

		// traverse the path and see how much flow we can send
		s64 delta = get_augmenting_flow(linear_network,residual_network,source,target,prev);

		// commit that flow to the path
		delta = MIN(remaining_amount,delta);
		assert(delta>0 && delta<=remaining_amount);

		augment_flow(linear_network,residual_network,source,target,prev,delta);
		remaining_amount -= delta;

		// update potentials
		for(u32 n=0;n<linear_network->max_num_nodes;++n)
		{
			// see page 323 of Ahuja-Magnanti-Orlin
			residual_network->potential[n] -= MIN(distance[target],distance[n]);

			/* Notice:
			 * if node i is permanently labeled we have
			 * 	d_i<=d_t
			 * which implies
			 * 	MIN(d_i,d_t) = d_i
			 * if node i is temporarily labeled we have
			 * 	d_i>=d_t
			 * which implies
			 * 	MIN(d_i,d_t) = d_t
			 * */
		}
	}
	return true;
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
static u32 find_path_or_cycle(
		const struct gossmap *gossmap,
		const struct chan_flow *chan_flow,
		const u32 start_idx,
		const s64 *balance,

		const struct gossmap_chan **prev_chan,
		int *prev_dir,
		u32 *prev_idx)
{
	const size_t max_num_nodes = gossmap_max_node_idx(gossmap);
	bitmap *visited =
	    tal_arrz(tmpctx, bitmap, BITMAP_NWORDS(max_num_nodes));
	u32 final_idx = start_idx;
	bitmap_set_bit(visited, start_idx);

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
				const struct gossmap_node *next =
				    gossmap_nth_node(gossmap, c, !dir);
				u32 next_idx = gossmap_node_idx(gossmap, next);

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
	return final_idx;
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
				   const struct gossmap *gossmap,
				   const u32 start_idx, const u32 final_idx,
				   s64 *balance, struct chan_flow *chan_flow,
				   const u32 *prev_idx, const int *prev_dir,
				   const struct gossmap_chan *const *prev_chan)
{
	assert(balance[start_idx] < 0);
	assert(balance[final_idx] > 0);
	s64 delta = -balance[start_idx];
	size_t length = 0;
	delta = MIN(delta, balance[final_idx]);

	/* We can only walk backwards, now get me the legth of the path and the
	 * max flow we can send through this route. */
	for (u32 cur_idx = final_idx; cur_idx != start_idx;
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
	balance[start_idx] += delta;
	balance[final_idx] -= delta;
	for (u32 cur_idx = final_idx; cur_idx != start_idx;
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
	f->delivers = amount_msat(delta * 1000);
	return f;
}

/* Substract a flow cycle from the channel allocation. */
static void substract_cycle(const struct gossmap *gossmap, const u32 final_idx,
			    struct chan_flow *chan_flow, const u32 *prev_idx,
			    const int *prev_dir,
			    const struct gossmap_chan *const *prev_chan)
{
	s64 delta = INFINITE;
	u32 cur_idx;

	/* Compute greatest flow in this cycle. */
	for (cur_idx = final_idx; cur_idx!=INVALID_INDEX;) {
		const int dir = prev_dir[cur_idx];
		const struct gossmap_chan *const chan = prev_chan[cur_idx];
		const u32 chan_idx = gossmap_chan_idx(gossmap, chan);

		delta = MIN(delta, chan_flow[chan_idx].half[dir]);

		cur_idx = prev_idx[cur_idx];
		if (cur_idx == final_idx)
			/* we have come back full circle */
			break;
	}
	assert(cur_idx==final_idx);

	/* Walk again and substract the flow value (delta). */
	assert(delta < INFINITE);
	assert(delta > 0);

	for (cur_idx = final_idx;cur_idx!=INVALID_INDEX;) {
		const int dir = prev_dir[cur_idx];
		const struct gossmap_chan *const chan = prev_chan[cur_idx];
		const u32 chan_idx = gossmap_chan_idx(gossmap, chan);

		chan_flow[chan_idx].half[dir] -= delta;

		cur_idx = prev_idx[cur_idx];
		if (cur_idx == final_idx)
			/* we have come back full circle */
			break;
	}
	assert(cur_idx==final_idx);
}

/* Given a flow in the residual network, build a set of payment flows in the
 * gossmap that corresponds to this flow. */
static struct flow **
get_flow_paths(const tal_t *ctx,
	       const struct route_query *rq,
	       const struct linear_network *linear_network,
	       const struct residual_network *residual_network)
{
	struct flow **flows = tal_arr(ctx,struct flow*,0);

	const size_t max_num_chans = gossmap_max_chan_idx(rq->gossmap);
	struct chan_flow *chan_flow = tal_arrz(tmpctx,struct chan_flow,max_num_chans);

	const size_t max_num_nodes = gossmap_max_node_idx(rq->gossmap);
	s64 *balance = tal_arrz(tmpctx,s64,max_num_nodes);

	const struct gossmap_chan **prev_chan
		= tal_arr(tmpctx,const struct gossmap_chan *,max_num_nodes);


	int *prev_dir = tal_arr(tmpctx,int,max_num_nodes);
	u32 *prev_idx = tal_arr(tmpctx,u32,max_num_nodes);

	for (u32 node_idx = 0; node_idx < max_num_nodes; node_idx++)
		prev_idx[node_idx] = INVALID_INDEX;

	// Convert the arc based residual network flow into a flow in the
	// directed channel network.
	// Compute balance on the nodes.
	for(u32 n = 0;n<max_num_nodes;++n)
	{
		for(struct arc arc = node_adjacency_begin(linear_network,n);
		        !node_adjacency_end(arc);
			arc = node_adjacency_next(linear_network,arc))
		{
			if(arc_is_dual(arc))
				continue;
			u32 m = arc_head(linear_network,arc);
			s64 flow = get_arc_flow(residual_network,arc);
			u32 chanidx;
			int chandir;

			balance[n] -= flow;
			balance[m] += flow;

			arc_to_parts(arc, &chanidx, &chandir, NULL, NULL);
			chan_flow[chanidx].half[chandir] +=flow;
		}

	}

	// Select all nodes with negative balance and find a flow that reaches a
	// positive balance node.
	for(u32 node_idx=0;node_idx<max_num_nodes;++node_idx)
	{
		// this node has negative balance, flows leaves from here
		while(balance[node_idx]<0)
		{
			prev_chan[node_idx] = NULL;
			u32 final_idx = find_path_or_cycle(
			    rq->gossmap, chan_flow, node_idx, balance,
			    prev_chan, prev_dir, prev_idx);

			if (balance[final_idx] > 0)
			/* case 1. found a path */
			{
				struct flow *fp = substract_flow(
				    flows, rq->gossmap, node_idx, final_idx,
				    balance, chan_flow, prev_idx, prev_dir,
				    prev_chan);

				tal_arr_expand(&flows, fp);
			} else
			/* case 2. found a cycle */
			{
				substract_cycle(rq->gossmap, final_idx,
						chan_flow, prev_idx, prev_dir,
						prev_chan);
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
		      double delay_feefactor, double base_fee_penalty,
		      u32 prob_cost_factor)
{
	struct flow **flow_paths;

	struct pay_parameters *params = tal(tmpctx,struct pay_parameters);
	struct dijkstra *dijkstra;

	params->rq = rq;
	params->source = source;
	params->target = target;
	params->amount = amount;

	// template the channel partition into linear arcs
	params->cap_fraction[0]=0;
	params->cost_fraction[0]=0;
	for(size_t i =1;i<CHANNEL_PARTS;++i)
	{
		params->cap_fraction[i]=CHANNEL_PIVOTS[i]-CHANNEL_PIVOTS[i-1];
		params->cost_fraction[i]=
			log((1-CHANNEL_PIVOTS[i-1])/(1-CHANNEL_PIVOTS[i]))
			/params->cap_fraction[i];

		// printf("channel part: %ld, fraction: %lf, cost_fraction: %lf\n",
		//	i,params->cap_fraction[i],params->cost_fraction[i]);
	}

	params->delay_feefactor = delay_feefactor;
	params->base_fee_penalty = base_fee_penalty;
	params->prob_cost_factor = prob_cost_factor;

	// build the uncertainty network with linearization and residual arcs
	struct linear_network *linear_network= init_linear_network(tmpctx, params);
	struct residual_network *residual_network =
	    alloc_residual_network(tmpctx, linear_network->max_num_nodes,
				  linear_network->max_num_arcs);
	dijkstra = dijkstra_new(tmpctx, gossmap_max_node_idx(rq->gossmap));

	const u32 target_idx = gossmap_node_idx(rq->gossmap,target);
	const u32 source_idx = gossmap_node_idx(rq->gossmap,source);

	init_residual_network(linear_network,residual_network);

	/* TODO(eduardo):
	 * Some MCF algorithms' performance depend on the size of maxflow. If we
	 * were to work in units of msats we 1. risking overflow when computing
	 * costs and 2. we risk a performance overhead for no good reason.
	 *
	 * Working in units of sats was my first choice, but maybe working in
	 * units of 10, or 100 sats could be even better.
	 *
	 * IDEA: define the size of our precision as some parameter got at
	 * runtime that depends on the size of the payment and adjust the MCF
	 * accordingly.
	 * For example if we are trying to pay 1M sats our precision could be
	 * set to 1000sat, then channels that had capacity for 3M sats become 3k
	 * flow units. */
	const u64 pay_amount_sats = (params->amount.millisatoshis + 999)/1000; /* Raw: minflow */

	if (!find_feasible_flow(linear_network, residual_network,
				source_idx, target_idx, pay_amount_sats)) {
		return NULL;
	}
	combine_cost_function(linear_network, residual_network, mu);

	/* We solve a linear MCF problem. */
	if(!optimize_mcf(dijkstra,linear_network,residual_network,
			 source_idx,target_idx,pay_amount_sats))
	{
		return NULL;
	}

	/* We dissect the solution of the MCF into payment routes.
	 * Actual amounts considering fees are computed for every
	 * channel in the routes. */
	flow_paths = get_flow_paths(tmpctx, rq,
				    linear_network, residual_network);
	return flow_paths;
}
