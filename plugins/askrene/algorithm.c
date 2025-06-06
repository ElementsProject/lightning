#include "config.h"
#include <ccan/bitmap/bitmap.h>
#include <ccan/tal/tal.h>
#include <plugins/askrene/algorithm.h>
#include <plugins/askrene/priorityqueue.h>
#include <plugins/askrene/queue.h>

static const s64 INFINITE = INT64_MAX;

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

bool BFS_path(const tal_t *ctx, const struct graph *graph,
	      const struct node source, const struct node destination,
	      const s64 *capacity, const s64 cap_threshold, struct arc *prev)
{
	const tal_t *this_ctx = tal(ctx, tal_t);
	bool target_found = false;
	assert(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	/* check preconditions */
	assert(source.idx < max_num_nodes);
	assert(capacity);
	assert(prev);
	assert(tal_count(capacity) == max_num_arcs);
	assert(tal_count(prev) == max_num_nodes);

	for (size_t i = 0; i < max_num_nodes; i++)
		prev[i].idx = INVALID_INDEX;

	/* A minimalistic queue is implemented here. Nodes are not visited more
	 * than once, therefore a maximum size of max_num_nodes is sufficient.
	 * max_num_arcs would work as well but we expect max_num_arcs to be a
	 * factor >10 greater than max_num_nodes. */
	u32 *queue = tal_arr(this_ctx, u32, max_num_nodes);
	size_t queue_start = 0, queue_end = 0;

	queue[queue_end++] = source.idx;

	while (queue_start < queue_end) {
		struct node cur = {.idx = queue[queue_start++]};

		if (cur.idx == destination.idx) {
			target_found = true;
			break;
		}

		for (struct arc arc = node_adjacency_begin(graph, cur);
		     !node_adjacency_end(arc);
		     arc = node_adjacency_next(graph, arc)) {
			/* check if this arc is traversable */
			if (capacity[arc.idx] < cap_threshold)
				continue;

			const struct node next = arc_head(graph, arc);

			/* if that node has been seen previously */
			if (prev[next.idx].idx != INVALID_INDEX ||
			    next.idx == source.idx)
				continue;

			prev[next.idx] = arc;

			assert(queue_end < max_num_nodes);
			queue[queue_end++] = next.idx;
		}
	}

	tal_free(this_ctx);
	return target_found;
}

bool dijkstra_path(const tal_t *ctx, const struct graph *graph,
		   const struct node source, const struct node destination,
		   bool prune, const s64 *capacity, const s64 cap_threshold,
		   const s64 *cost, const s64 *potential, struct arc *prev,
		   s64 *distance)
{
	bool target_found = false;
	assert(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);
	const tal_t *this_ctx = tal(ctx, tal_t);

	/* check preconditions */
	assert(source.idx<max_num_nodes);
	assert(cost);
	assert(capacity);
	assert(prev);
	assert(distance);

	/* if prune is true then the destination cannot be invalid */
	assert(destination.idx < max_num_nodes || !prune);

	assert(tal_count(cost) == max_num_arcs);
	assert(tal_count(capacity) == max_num_arcs);
	assert(tal_count(prev) == max_num_nodes);
	assert(tal_count(distance) == max_num_nodes);

	/* FIXME: maybe this is unnecessary */
	bitmap *visited = tal_arrz(this_ctx, bitmap,
				   BITMAP_NWORDS(max_num_nodes));

	for (size_t i = 0; i < max_num_nodes; ++i)
		prev[i].idx = INVALID_INDEX;

	struct priorityqueue *q;
	q = priorityqueue_new(this_ctx, max_num_nodes);
	const s64 *const dijkstra_distance = priorityqueue_value(q);

	priorityqueue_init(q);
	priorityqueue_update(q, source.idx, 0);

	while (!priorityqueue_empty(q)) {
		const u32 cur = priorityqueue_top(q);
		priorityqueue_pop(q);

		/* FIXME: maybe this is unnecessary */
		if (bitmap_test_bit(visited, cur))
			continue;
		bitmap_set_bit(visited, cur);

		if (cur == destination.idx) {
			target_found = true;
			if (prune)
				break;
		}

		for (struct arc arc =
			 node_adjacency_begin(graph, node_obj(cur));
		     !node_adjacency_end(arc);
		     arc = node_adjacency_next(graph, arc)) {
			/* check if this arc is traversable */
			if (capacity[arc.idx] < cap_threshold)
				continue;

			const struct node next = arc_head(graph, arc);

			const s64 cij = cost[arc.idx] - potential[cur] +
					potential[next.idx];

			/* Dijkstra only works with non-negative weights */
			assert(cij >= 0);

			if (dijkstra_distance[next.idx] <=
			    dijkstra_distance[cur] + cij)
				continue;

			priorityqueue_update(q, next.idx,
					     dijkstra_distance[cur] + cij);
			prev[next.idx] = arc;
		}
	}
	for (size_t i = 0; i < max_num_nodes; i++)
		distance[i] = dijkstra_distance[i];

	tal_free(this_ctx);
	return target_found;
}

/* Get the max amount of flow one can send from source to target along the path
 * encoded in `prev`. */
static s64 get_augmenting_flow(const struct graph *graph,
			       const struct node source,
			       const struct node target, const s64 *capacity,
			       const struct arc *prev)
{
	const size_t max_num_nodes = graph_max_num_nodes(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	assert(max_num_nodes == tal_count(prev));
	assert(max_num_arcs == tal_count(capacity));

	/* count the number of arcs in the path */
	int path_length = 0;
	s64 flow = INFINITE;

	struct node cur = target;
	while (cur.idx != source.idx) {
		assert(cur.idx < max_num_nodes);
		const struct arc arc = prev[cur.idx];
		assert(arc.idx < max_num_arcs);
		flow = MIN(flow, capacity[arc.idx]);

		/* we are traversing in the opposite direction to the flow,
		 * hence the next node is at the tail of the arc. */
		cur = arc_tail(graph, arc);

		/* We may never have a path exceeds the number of nodes, it this
		 * happens it means we have an infinite loop. */
		path_length++;
		if(path_length >= max_num_nodes){
			flow = -1;
			break;
		}
	}

	assert(flow < INFINITE && flow > 0);
	return flow;
}


/* Helper.
 * Sends an amount of flow through an arc, changing the flow balance of the
 * nodes connected by the arc and the [residual] capacity of the arc and its
 * dual. */
static void sendflow(const struct graph *graph, const struct arc arc,
		     const s64 flow, s64 *arc_capacity, s64 *node_balance)
{
	const struct arc dual = arc_dual(graph, arc);

	arc_capacity[arc.idx] -= flow;
	arc_capacity[dual.idx] += flow;

	if (node_balance) {
		const struct node src = arc_tail(graph, arc),
				  dst = arc_tail(graph, dual);

		node_balance[src.idx] -= flow;
		node_balance[dst.idx] += flow;
	}
}

/* Augment a `flow` amount along the path defined by `prev`.*/
static void augment_flow(const struct graph *graph,
			 const struct node source,
			 const struct node target,
			 const struct arc *prev,
			 s64 *excess,
			 s64 *capacity,
			 s64 flow)
{
	const size_t max_num_nodes = graph_max_num_nodes(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	assert(max_num_nodes == tal_count(prev));
	assert(max_num_arcs == tal_count(capacity));

	struct node cur = target;
	/* count the number of arcs in the path */
	int path_length = 0;

	while (cur.idx != source.idx) {
		assert(cur.idx < max_num_nodes);
		const struct arc arc = prev[cur.idx];

		sendflow(graph, arc, flow, capacity, excess);

		/* we are traversing in the opposite direction to the flow,
		 * hence the next node is at the tail of the arc. */
		cur = arc_tail(graph, arc);

		/* We may never have a path exceeds the number of nodes, it this
		 * happens it means we have an infinite loop. */
		path_length++;
		if (path_length >= max_num_nodes)
			break;
	}
	assert(path_length < max_num_nodes);
}

bool simple_feasibleflow(const tal_t *ctx,
			 const struct graph *graph,
			 const struct node source,
			 const struct node destination,
			 s64 *capacity,
			 s64 amount)
{
	const tal_t *this_ctx = tal(ctx, tal_t);
	assert(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	/* check preconditions */
	assert(amount > 0);
	assert(source.idx < max_num_nodes);
	assert(destination.idx < max_num_nodes);
	assert(capacity);
	assert(tal_count(capacity) == max_num_arcs);

	/* path information
	 * prev: is the id of the arc that lead to the node. */
	struct arc *prev = tal_arr(this_ctx, struct arc, max_num_nodes);
	if (!prev)
		goto finish;

	while (amount > 0) {
		/* find a path from source to target */
		if (!BFS_path(this_ctx, graph, source, destination, capacity, 1,
			      prev))
			goto finish;

		/* traverse the path and see how much flow we can send */
		s64 delta = get_augmenting_flow(graph, source, destination,
						capacity, prev);

		/* commit that flow to the path */
		delta = MIN(amount, delta);
		assert(delta > 0 && delta <= amount);

		augment_flow(graph, source, destination, prev, NULL, capacity,
			     delta);
		amount -= delta;
	}
finish:
	tal_free(this_ctx);
	return amount == 0;
}

s64 node_balance(const struct graph *graph,
		 const struct node node,
		 const s64 *capacity)
{
	s64 balance = 0;

	for (struct arc arc = node_adjacency_begin(graph, node);
	     !node_adjacency_end(arc); arc = node_adjacency_next(graph, arc)) {
		struct arc dual = arc_dual(graph, arc);

		if (arc_is_dual(graph, arc))
			balance += capacity[arc.idx];
		else
			balance -= capacity[dual.idx];
	}
	return balance;
}

/* Helper.
 * Compute the reduced cost of an arc. */
static s64 reduced_cost(const struct graph *graph, const struct arc arc,
			const s64 *cost, const s64 *potential)
{
	struct node src = arc_tail(graph, arc);
	struct node dst = arc_head(graph, arc);
	return cost[arc.idx] - potential[src.idx] + potential[dst.idx];
}

/* Finds an optimal path from the source to the nearest sink node, by definition
 * a node i is a sink if node_balance[i]<0. It uses a reduced cost:
 *	reduced_cost[i,j] = cost[i,j] - potential[i] + potential[j]
 *
 * */
static struct node dijkstra_nearest_sink(const tal_t *ctx,
					 const struct graph *graph,
					 const struct node source,
					 const s64 *node_balance,
					 const s64 *capacity,
					 const s64 cap_threshold,
					 const s64 *cost,
					 const s64 *potential,
					 struct arc *prev,
					 s64 *distance)
{
	struct node target = {.idx = INVALID_INDEX};
	const tal_t *this_ctx = tal(ctx, tal_t);

	/* check preconditions */
	assert(graph);
	assert(node_balance);
	assert(capacity);
	assert(cost);
	assert(potential);
	assert(prev);
	assert(distance);

	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	assert(source.idx < max_num_nodes);
	assert(tal_count(node_balance) == max_num_nodes);
	assert(tal_count(capacity) == max_num_arcs);
	assert(tal_count(cost) == max_num_arcs);
	assert(tal_count(potential) == max_num_nodes);
	assert(tal_count(prev) == max_num_nodes);
	assert(tal_count(distance) == max_num_nodes);

	for (size_t i = 0; i < max_num_arcs; i++) {
		/* is this arc saturated? */
		if (capacity[i] < cap_threshold)
			continue;

		struct arc arc = {.idx = i};
		struct node tail = arc_tail(graph, arc);
		struct node head = arc_head(graph, arc);
		s64 red_cost =
		    cost[i] - potential[tail.idx] + potential[head.idx];

		/* reducted cost cannot be negative for non saturated arcs,
		 * otherwise Dijkstra does not work. */
		if (red_cost < 0)
			goto finish;
	}

	for (size_t i = 0; i < max_num_nodes; ++i)
		prev[i].idx = INVALID_INDEX;

/* Only in debug mode we keep track of visited nodes. */
#ifdef ASKRENE_UNITTEST
	bitmap *visited =
	    tal_arrz(this_ctx, bitmap, BITMAP_NWORDS(max_num_nodes));
#endif

	struct priorityqueue *q;
	q = priorityqueue_new(this_ctx, max_num_nodes);
	const s64 *const dijkstra_distance = priorityqueue_value(q);

	priorityqueue_init(q);
	priorityqueue_update(q, source.idx, 0);

	while (!priorityqueue_empty(q)) {
		const u32 idx = priorityqueue_top(q);
		const struct node cur = {.idx = idx};
		priorityqueue_pop(q);

/* Only in debug mode we keep track of visited nodes. */
#ifdef ASKRENE_UNITTEST
		assert(!bitmap_test_bit(visited, cur.idx));
		bitmap_set_bit(visited, cur.idx);
#endif

		if (node_balance[cur.idx] < 0) {
			target = cur;
			break;
		}

		for (struct arc arc = node_adjacency_begin(graph, cur);
		     !node_adjacency_end(arc);
		     arc = node_adjacency_next(graph, arc)) {
			/* check if this arc is traversable */
			if (capacity[arc.idx] < cap_threshold)
				continue;

			const struct node next = arc_head(graph, arc);

			const s64 cij = cost[arc.idx] - potential[cur.idx] +
					potential[next.idx];

			/* Dijkstra only works with non-negative weights */
			assert(cij >= 0);

			if (dijkstra_distance[next.idx] <=
			    dijkstra_distance[cur.idx] + cij)
				continue;

			priorityqueue_update(q, next.idx,
					     dijkstra_distance[cur.idx] + cij);
			prev[next.idx] = arc;
		}
	}
	for (size_t i = 0; i < max_num_nodes; i++)
		distance[i] = dijkstra_distance[i];

finish:
	tal_free(this_ctx);
	return target;
}

/* Problem: find a potential and capacity redistribution such that:
 *	excess[all nodes] = 0
 *	capacity[all arcs] >= 0
 *	cost/potential [i,j] < 0 implies capacity[i,j] = 0
 *
 *	Q. Is this a feasible solution?
 *
 *	A. If we use flow conserving function sendflow, then
 *	if for all nodes excess[i] = 0 and capacity[i,j] >= 0 for all arcs
 *	then we have reached a feasible flow.
 *
 *	Q. Is this flow optimal?
 *
 *	A. According to Theorem 9.4 (Ahuja page 309) we have reached an optimal
 *	solution if we are able to find a potential and flow that satisfy the
 *	slackness optimality conditions:
 *
 *		if cost_reduced[i,j] > 0 then x[i,j] = 0
 *		if 0 < x[i,j] < u[i,j] then cost_reduced[i,j] = 0
 *		if cost_reduced[i,j] < 0 then x[i,j] = u[i,j]
 *
 *	In our representation the slackness optimality conditions are equivalent
 *	to the following condition in the residual network:
 *
 *		cost_reduced[i,j] < 0 then capacity[i,j] = 0
 *
 *	Therefore yes, the solution is optimal.
 *
 *	Q. Why is this useful?
 *
 *	A. It can be used to compute a MCF from scratch or build an optimal
 *	solution starting from a non-optimal one, eg. if we first test the
 *	solution feasibility we already have a solution canditate, we use that
 *	flow as input to this function, in another example we might have an
 *	algorithm that changes the cost function at every iteration and we need
 *	to find the MCF every time.
 * */
bool mcf_refinement(const tal_t *ctx,
		    const struct graph *graph,
		    s64 *excess,
		    s64 *capacity,
		    const s64 *cost,
		    s64 *potential)
{
	bool solved = false;
	const tal_t *this_ctx = tal(ctx, tal_t);

	assert(graph);
	assert(excess);
	assert(capacity);
	assert(cost);
	assert(potential);

	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	assert(tal_count(excess) == max_num_nodes);
	assert(tal_count(capacity) == max_num_arcs);
	assert(tal_count(cost) == max_num_arcs);
	assert(tal_count(potential) == max_num_nodes);

	s64 total_excess = 0;
	for (u32 i = 0; i < max_num_nodes; i++)
		total_excess += excess[i];

	if (total_excess)
		/* there is no way to satisfy the constraints if supply does not
		 * match demand */
		goto finish;

	/* Enforce the complementary slackness condition, rolls back
	 * constraints.  */
	for (u32 arc_id = 0; arc_id < max_num_arcs; arc_id++) {
		struct arc arc = {.idx = arc_id};
		if(!arc_enabled(graph, arc))
			continue;
		const s64 r = capacity[arc.idx];
		if (reduced_cost(graph, arc, cost, potential) < 0 && r > 0) {
			/* This arc's reduced cost is negative and non
			 * saturated. */
			sendflow(graph, arc, r, capacity, excess);
		}
	}

	struct arc *prev = tal_arr(this_ctx, struct arc, max_num_nodes);
	s64 *distance = tal_arrz(this_ctx, s64, max_num_nodes);
	if (!prev || !distance)
		goto finish;

	/* Now build back constraints again keeping the complementary slackness
	 * condition. */
	for (u32 node_id = 0; node_id < max_num_nodes; node_id++) {
		struct node src = {.idx = node_id};

		/* is this node a source */
		while (excess[src.idx] > 0) {

			/* where is the nearest sink */
			struct node dst = dijkstra_nearest_sink(
			    this_ctx, graph, src, excess, capacity, 1, cost,
			    potential, prev, distance);

			if (dst.idx >= max_num_nodes)
				/* we failed to find a reacheable sink */
				goto finish;

			/* traverse the path and see how much flow we can send
			 */
			s64 delta = get_augmenting_flow(graph, src, dst,
							capacity, prev);

			delta = MIN(excess[src.idx], delta);
			delta = MIN(-excess[dst.idx], delta);
			assert(delta > 0);

			/* commit that flow to the path */
			augment_flow(graph, src, dst, prev, excess, capacity,
				     delta);

			/* update potentials */
			for (u32 n = 0; n < max_num_nodes; n++) {
				/* see page 323 of Ahuja-Magnanti-Orlin.
				 * Whether we prune or not the Dijkstra search,
				 * the following potentials will keep reduced
				 * costs non-negative. */
				potential[n] -=
				    MIN(distance[dst.idx], distance[n]);
			}
		}
	}

#ifdef ASKRENE_UNITTEST
	/* verify that we have satisfied all constraints */
	for (u32 i = 0; i < max_num_nodes; i++) {
		assert(excess[i] == 0);
	}
	for (u32 i = 0; i < max_num_arcs; i++) {
		struct arc arc = {.idx = i};
		if(!arc_enabled(graph, arc))
			continue;
		const s64 cap = capacity[arc.idx];
		const s64 rc = reduced_cost(graph, arc, cost, potential);

		assert(cap >= 0);
		/* asserts logic implication: (rc<0 -> cap==0)*/
		assert(!(rc < 0) || cap == 0);
	}
#endif
	solved = true;

finish:
	tal_free(this_ctx);
	return solved;
}

bool simple_mcf(const tal_t *ctx, const struct graph *graph,
		const struct node source, const struct node destination,
		s64 *capacity, s64 amount, const s64 *cost)
{
	const tal_t *this_ctx = tal(ctx, tal_t);

	assert(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	/* check preconditions */
	assert(amount > 0);
	assert(source.idx < max_num_nodes);
	assert(destination.idx < max_num_nodes);
	assert(capacity);
	assert(cost);
	assert(tal_count(capacity) == max_num_arcs);
	assert(tal_count(cost) == max_num_arcs);

	s64 *potential = tal_arrz(this_ctx, s64, max_num_nodes);
	s64 *excess = tal_arrz(this_ctx, s64, max_num_nodes);

	excess[source.idx] = amount;
	excess[destination.idx] = -amount;

	if (!mcf_refinement(this_ctx, graph, excess, capacity, cost, potential))
		goto fail;

	tal_free(this_ctx);
	return true;

fail:
	tal_free(this_ctx);
	return false;
}

s64 flow_cost(const struct graph *graph, const s64 *capacity, const s64 *cost)
{
	assert(graph);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	s64 total_cost = 0;

	/* check preconditions */
	assert(capacity);
	assert(cost);
	assert(tal_count(capacity) == max_num_arcs);
	assert(tal_count(cost) == max_num_arcs);

	for (u32 i = 0; i < max_num_arcs; i++) {
		struct arc arc = {.idx = i};
		struct arc dual = arc_dual(graph, arc);

		if (arc_is_dual(graph, arc) || !arc_enabled(graph, arc))
			continue;

		total_cost += capacity[dual.idx] * cost[arc.idx];
	}
	return total_cost;
}

/* Heuristic improvements options to Goldberg-Tarjan implementation.
 * Goldberg "An Efficient Implementation of a Scaling Minimum-Cost Flow
 * Algorithm. 1992 "*/

/* Set-relabel is applied to the set of nodes that cannot reach any sink by
 * admissible paths.
 * This heuristics alone can reduce significantly the running time by reducing
 * the number relabeling operations. */
#define GOLDBERG_PRICE_UPDATE
/* FIXME: Price refinement as proposed by Goldberg 1992 and Bunnagel-Korte-Vygen
 * seeks the minimum value of epsilon and the corresponding potential for which
 * the current state is epsilon-optimal then epsilon is reduced by a factor and
 * refine is called. Right now we simply assume the current state is
 * epsilon-optimal. */
#define GOLDBERG_PRICE_REFINEMENT 8
/* Relabel a node to its maximum extent. */
#define GOLDBERG_MAX_RELABEL
/* Relabel neighboring nodes that do not have admissible arcs before pushing
 * flow to them. GOLDBERG_LOOKAHEAD alone does not bring much performance gain.
 * But combined with GOLDBERG_MAX_RELABEL produces a substantial increase in
 * performance. */
#define GOLDBERG_LOOKAHEAD


/* FIXME: the original paper (Goldberg-Tarjan 1990) suggests using a
 * "first-active" container, but a follow up paper (Goldberg 1992) uses a queue
 * for its implementation and it should be just fine. or-tools library uses a
 * stack and still obtains very good performances. We should investigate if the
 * first-active container would improve our performance.
 * Another alternative is the use of "dynamic trees". */
QUEUE_DEFINE_TYPE(u32, queue_of_u32);
QUEUE_DEFINE_TYPE(u32, gt_active);

struct goldberg_tarjan_network {
	const struct graph *graph;
	s64 *residual_capacity;
	struct arc *current_arc;
	s64 *excess;
	s64 *potential;
	s64 *cost;
};

/* Goldberg-Tarjan's push/relabel, auxiliary routine. */
static void gt_push(struct goldberg_tarjan_network *gt, struct arc arc,
		    s64 flow)
{
	struct arc dual = arc_dual(gt->graph, arc);
	struct node from = arc_tail(gt->graph, arc);
	struct node to = arc_head(gt->graph, arc);

	gt->residual_capacity[arc.idx] -= flow;
	gt->residual_capacity[dual.idx] += flow;
	gt->excess[from.idx] -= flow;
	gt->excess[to.idx] += flow;
}

/* Goldberg-Tarjan's push/relabel, auxiliary routine.
 * note: excess is written to the same array that provides supply/demand values. */
static void gt_discharge(u32 nodeidx, struct goldberg_tarjan_network *gt,
			 struct queue_of_u32 *active, const s64 max_label)
{
	const struct node node = {.idx = nodeidx};
	struct arc arc;

	/* do push/relable while node is active */
	while (gt->potential[nodeidx] < max_label && gt->excess[nodeidx] > 0) {
		/* smallest label in the neighborhood */
		s64 min_label = INT64_MAX;

		/* try pushing out flow */
		for (arc = gt->current_arc[nodeidx];
		     !node_adjacency_end(arc) && gt->excess[nodeidx] > 0;
		     arc = node_adjacency_next(gt->graph, arc)) {
			const struct node next = arc_head(gt->graph, arc);

			/* applies only to residual arcs */
			if (gt->residual_capacity[arc.idx] <= 0)
				continue;

			if (gt->potential[nodeidx] > gt->potential[next.idx]) {
				const s64 flow =
				    MIN(gt->excess[nodeidx],
					gt->residual_capacity[arc.idx]);
				const s64 old_excess = gt->excess[next.idx];
				gt_push(gt, arc, flow);

				if (gt->excess[next.idx] > 0 &&
				    old_excess <= 0 &&
				    gt->potential[next.idx] < max_label)
					queue_of_u32_insert(active, next.idx);
			} else {
				min_label =
				    MIN(min_label, gt->potential[next.idx]);
			}

			/* we had a non-saturating push, this means the current
			 * arc is still admissible, break before we checkout the
			 * next arc. */
			if (gt->excess[nodeidx] == 0)
				break;
		}
		gt->current_arc[nodeidx] = arc;

		/* still have excess: relabel */
		if (gt->excess[nodeidx] > 0) {
			if (min_label < INT64_MAX &&
			    min_label >= gt->potential[nodeidx])
				gt->potential[nodeidx] = min_label + 1;
			else
				gt->potential[nodeidx]++;
			gt->current_arc[nodeidx] =
			    node_adjacency_begin(gt->graph, node);
		}
	}
}

/* A variation of Maximum-Flow "push/relabel" to find a feasible flow.
 *
 * See Goldberg-Tarjan "A New Approach to the Maximum-Flow Problem", JACM, Vol.
 * 35, No. 4, October 1988, pp. 921--940
 *
 * @ctx: allocator.
 * @graph: graph, assumes the existence of reverse (dual) arcs.
 * @supply: supply/demand encoding, supply[i]>0 for source nodes and supply[i]<0
 * for sinks. It is modified by the algorithm execution. When a feasible
 * solution is found supply[i] = 0 for every node.
 * @residual_capacity: residual capacity on arcs, here the final solution is
 * encoded.
 *
 * The original algorithm has an O(N^3) complexity, where N is the number of
 * nodes.
 * By limiting the highest value of the "label" to 10 we exclude all solutions
 * that require more than 10 hops from source to sink and reduce the
 * theoretical complexity to O(N^2).
 * */
static bool UNNEEDED goldberg_tarjan_feasible(const tal_t *ctx,
					      const struct graph *graph,
					      s64 *supply,
					      s64 *residual_capacity)
{
	const tal_t *this_ctx = tal(ctx, tal_t);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	/* re-use/abuse the same struct for MCF and Feasible Flow */
	struct goldberg_tarjan_network *gt =
	    tal(this_ctx, struct goldberg_tarjan_network);

	gt->graph = graph;
	/* we work with the residual_capacity in-place */
	gt->residual_capacity = residual_capacity;
	gt->current_arc = tal_arr(gt, struct arc, max_num_nodes);
	gt->excess = supply;
	gt->potential = tal_arrz(gt, s64, max_num_nodes);
	gt->cost = NULL;

	struct queue_of_u32 active;
	queue_of_u32_init(&active, this_ctx);

	/* `max_label = max_num_nodes` would exhaust every possible path from
	 * the source to the sink, this is the correct MaxFlow implementation.
	 * However we use `max_label = 10`, meaning that we discard any solution
	 * that uses more than 10 hops from source to sink. */
	const s64 max_label = MIN(10, max_num_nodes);
	for (u32 node_id = 0; node_id < max_num_nodes; node_id++) {
		if (gt->excess[node_id] > 0) {
			gt->potential[node_id] = 1;
			queue_of_u32_insert(&active, node_id);
		}
		gt->current_arc[node_id] =
		    node_adjacency_begin(gt->graph, node_obj(node_id));
	}

	while (!queue_of_u32_empty(&active)) {
		u32 node = queue_of_u32_pop(&active);
		gt_discharge(node, gt, &active, max_label);
	}

	/* did we find a feasible solution? */
	bool solved = true;
	for (u32 node_id = 0; node_id < max_num_nodes; node_id++)
		if (gt->excess[node_id] != 0) {
			solved = false;
			break;
		}
	tal_free(this_ctx);
	return solved;
}

static s64 gt_reduced_cost(const struct goldberg_tarjan_network *gt, u32 arcidx,
			   u32 from, u32 to)
{
	return gt->cost[arcidx] + gt->potential[to] - gt->potential[from];
}

#ifdef GOLDBERG_LOOKAHEAD
static bool gt_has_admissible_arcs(struct goldberg_tarjan_network *gt,
				   const u32 nodeidx)
{
	for (struct arc arc = gt->current_arc[nodeidx];
	     !node_adjacency_end(arc);
	     arc = node_adjacency_next(gt->graph, arc)) {
		struct node next = arc_head(gt->graph, arc);
		const s64 rcost =
		    gt_reduced_cost(gt, arc.idx, nodeidx, next.idx);
		if (gt->residual_capacity[arc.idx] > 0 && rcost < 0) {
			gt->current_arc[nodeidx] = arc;
			return true;
		}
	}
	return false;
}
#endif // GOLDBERG_LOOKAHEAD

static void gt_mcf_relabel(struct goldberg_tarjan_network *gt,
			   const u32 nodeidx, const s64 epsilon)
{
	/* a conservative relabel, just add epsilon */
	struct node node = {.idx = nodeidx};
	gt->potential[nodeidx] += epsilon;
	gt->current_arc[nodeidx] = node_adjacency_begin(gt->graph, node);

/* highest value relabel we can perform while keeping epsilon-optimality */
#ifdef GOLDBERG_MAX_RELABEL
	s64 smallest_cost = INT64_MAX;
	struct arc first_residual_arc;
	for (struct arc arc = node_adjacency_begin(gt->graph, node);
	     !node_adjacency_end(arc);
	     arc = node_adjacency_next(gt->graph, arc)) {

		if (gt->residual_capacity[arc.idx] <= 0)
			continue;

		struct node next = arc_head(gt->graph, arc);
		s64 rcost = gt->cost[arc.idx] + gt->potential[next.idx];

		/* remember the first residual arc to use as current_arc */
		if (smallest_cost == INT64_MAX)
			first_residual_arc = arc;

		if (rcost < gt->potential[nodeidx]) {
			// at least one arc is admissible, we exit early
			gt->current_arc[nodeidx] = arc;
			return;
		}

		smallest_cost = MIN(smallest_cost, rcost);
	}

	if (smallest_cost < INT64_MAX) {
		gt->potential[nodeidx] = smallest_cost + epsilon;
		gt->current_arc[nodeidx] = first_residual_arc;
	}
#endif // GOLDBERG_MAX_RELABEL
}

/* Goldberg-Tarjan's push/relabel, auxiliary routine */
static unsigned int gt_mcf_discharge(struct goldberg_tarjan_network *gt,
				     struct gt_active *active,
				     const s64 epsilon, const u32 nodeidx)
{
	unsigned int num_relabels = 0;

	while (gt->excess[nodeidx] > 0) {
		struct arc arc;

		/* try pushing out flow */
		for (arc = gt->current_arc[nodeidx];
		     !node_adjacency_end(arc) && gt->excess[nodeidx] > 0;
		     arc = node_adjacency_next(gt->graph, arc)) {
			const struct node next = arc_head(gt->graph, arc);

			/* applies only to residual arcs */
			if (gt->residual_capacity[arc.idx] <= 0)
				continue;

			/* applies only to admissible arcs */
			s64 rcost =
			    gt_reduced_cost(gt, arc.idx, nodeidx, next.idx);
			if (rcost >= 0)
				continue;

			const s64 flow = MIN(gt->excess[nodeidx],
					     gt->residual_capacity[arc.idx]);
			assert(flow > 0);

			const s64 old_excess = gt->excess[next.idx];

#ifdef GOLDBERG_LOOKAHEAD
			if (old_excess >= 0 &&
			    !gt_has_admissible_arcs(gt, next.idx)) {
				num_relabels++;
				gt_mcf_relabel(gt, next.idx, epsilon);

				/* the arc might not be admissible after the
				 * next node relabel, we check */
				rcost = gt_reduced_cost(gt, arc.idx, nodeidx,
							next.idx);
				if (rcost >= 0)
					continue;
			}
#endif // GOLDBERG_LOOKAHEAD

			gt_push(gt, arc, flow);
			if (gt->excess[next.idx] > 0 && old_excess <= 0)
				gt_active_insert(active, next.idx);

			/* break right away, skip moving to the next arc */
			if (gt->excess[nodeidx] == 0)
				break;
		}

		/* next time we loop over arcs starting where we ended-up now */
		gt->current_arc[nodeidx] = arc;

		/* still have excess: relabel */
		if (gt->excess[nodeidx] > 0) {
			num_relabels++;
			gt_mcf_relabel(gt, nodeidx, epsilon);
		}
	}
	return num_relabels;
}

#ifdef GOLDBERG_PRICE_UPDATE
static void gt_set_relabel(struct goldberg_tarjan_network *gt,
			   const s64 epsilon)
{
	const tal_t *this_ctx = tal(gt, tal_t);
	const size_t max_num_nodes = graph_max_num_nodes(gt->graph);

	struct priorityqueue *pending;
	pending = priorityqueue_new(this_ctx, max_num_nodes);
	priorityqueue_init(pending);
	const s64 *distance = priorityqueue_value(pending);
	s64 maximum_distance = 0;
	s64 set_excess = 0;

	/* negative excess nodes is where we start flooding */
	for (u32 nodeidx = 0; nodeidx < max_num_nodes; nodeidx++) {
		if (gt->excess[nodeidx] < 0) {
			set_excess += gt->excess[nodeidx];
			priorityqueue_update(pending, nodeidx, 0);
		}
	}

	while (!priorityqueue_empty(pending)) {
		const u32 nodeidx = priorityqueue_top(pending);

		priorityqueue_pop(pending);
		const struct node node = {.idx = nodeidx};

		if (gt->excess[nodeidx] > 0)
			set_excess += gt->excess[nodeidx];

		maximum_distance = distance[nodeidx];

		/* once we have scanned all active nodes we exit */
		if (set_excess == 0)
			break;

		for (struct arc arc = node_adjacency_begin(gt->graph, node);
		     !node_adjacency_end(arc);
		     arc = node_adjacency_next(gt->graph, arc)) {
			const struct arc dual = arc_dual(gt->graph, arc);
			const struct node next = arc_head(gt->graph, arc);

			/* traverse residual arcs only */
			if (gt->residual_capacity[dual.idx] <= 0)
				continue;

			const s64 rcost =
			    gt_reduced_cost(gt, dual.idx, next.idx, nodeidx);

			/* (node) <--- (next)
			 * distance[next] must be the least such that
			 *
			 * cost[dual] + (potential[node]+distance[node]*epsilon)
			 *      - (potential[next]+distance[next]*epsilon) < 0
			 * */
			s64 delta = 1 + rcost / epsilon;
			if (rcost < 0)
				delta = 0;

			if (distance[next.idx] <= delta + distance[nodeidx])
				continue;

			priorityqueue_update(pending, next.idx,
					     distance[nodeidx] + delta);
		}
	}

	for (u32 nodeidx = 0; nodeidx < max_num_nodes; nodeidx++) {
		s64 d = MIN(distance[nodeidx], maximum_distance);
		if (d > 0) {
			gt->potential[nodeidx] += epsilon * d;
			gt->current_arc[nodeidx] =
			    node_adjacency_begin(gt->graph, node_obj(nodeidx));
		}
	}
}
#endif // GOLDBERG_PRICE_UPDATE

/* Refine operation for Goldberg-Tarjan's push/relabel
 * min-cost-circulation. */
static void gt_refine(struct goldberg_tarjan_network *gt, s64 epsilon)
{
	const tal_t *this_ctx = tal(gt, tal_t);

	struct gt_active active;
	gt_active_init(&active, this_ctx);

	const size_t max_num_arcs = graph_max_num_arcs(gt->graph);
	const size_t max_num_nodes = graph_max_num_nodes(gt->graph);

	/* reset current act for every node */
	for (u32 nodeidx = 0; nodeidx < max_num_nodes; nodeidx++) {
		struct node node = {.idx = nodeidx};
		gt->current_arc[nodeidx] =
		    node_adjacency_begin(gt->graph, node);
	}

	/* saturate all negative cost arcs */
	for (u32 i = 0; i < max_num_arcs; i++) {
		struct arc arc = {.idx = i};
		if (arc_enabled(gt->graph, arc)) {
			struct node to = arc_head(gt->graph, arc);
			struct node from = arc_tail(gt->graph, arc);
			const s64 rcost =
			    gt_reduced_cost(gt, i, from.idx, to.idx);
			const s64 flow = gt->residual_capacity[arc.idx];
			if (rcost < 0 && flow > 0)
				gt_push(gt, arc, flow);
		}
	}

	/* enqueue all active nodes */
	for (u32 nodeidx = 0; nodeidx < max_num_nodes; nodeidx++) {
		if (gt->excess[nodeidx] > 0) {
			gt_active_insert(&active, nodeidx);
		}
	}

	unsigned int num_relabels = 0;
	/* push/relabel until there are no more active nodes */
	while (!gt_active_empty(&active)) {
#ifdef GOLDBERG_PRICE_UPDATE
		if (num_relabels >= max_num_nodes) {
			num_relabels = 0;
			gt_set_relabel(gt, epsilon);
		}
#endif // GOLDBERG_PRICE_UPDATE

		u32 nodeidx = gt_active_pop(&active);
		num_relabels += gt_mcf_discharge(gt, &active, epsilon, nodeidx);
	}
	tal_free(this_ctx);
}

/* This is the actual implementation of the Minimum-Cost Circulation algorithm.
 *
 * note: supply/demand is already satisfied in this state,
 * algorithm always succeds */
static void goldberg_tarjan_circulation(struct goldberg_tarjan_network *gt,
					s64 epsilon)
{
	while (epsilon > 1) {
#ifdef GOLDBERG_PRICE_REFINEMENT
		epsilon /= GOLDBERG_PRICE_REFINEMENT;
#else
		epsilon /= 2;
#endif // GOLDBERG_PRICE_REFINEMENT
		if (epsilon < 1)
			epsilon = 1;
		gt_refine(gt, epsilon);
	}
}

static bool check_overflow(double x, double y, double bound)
{
	return x * y <= bound;
}

/* Minimum-Cost Flow "cost scaling, push/relabel"
 *
 * see Goldberg-Tarjan "Finding Minimum-Cost Circulations by Successive
 * Approximation" Math. of Op. Research, Vol. 15, No. 3 (Aug. 1990), pp.
 * 430--466.
 *
 * @ctx: allocator.
 * @graph: graph, assumes the existence of reverse (dual) arcs.
 * @supply: supply/demand encoding, supply[i]>0 for source nodes and supply[i]<0
 * for sinks. It is modified by the algorithm execution. When a feasible
 * solution is found supply[i] = 0 for every node.
 * @residual_capacity: residual capacity on arcs, here the final solution is
 * encoded.
 * @cost: cost per unit of flow on arcs. It is assumed that dual arcs have the
 * opposite cost of its twin: cost[i] = -cost[dual(i)].
 * */
bool goldberg_tarjan_mcf(const tal_t *ctx, const struct graph *graph,
			 s64 *supply, s64 *residual_capacity, const s64 *cost)
{
	const tal_t *this_ctx = tal(ctx, tal_t);
	if (!goldberg_tarjan_feasible(this_ctx, graph, supply,
				      residual_capacity)) {
		goto fail;
	}

	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	struct goldberg_tarjan_network *gt =
	    tal(this_ctx, struct goldberg_tarjan_network);

	gt->graph = graph;
	/* we work with the residual_capacity in-place */
	gt->residual_capacity = residual_capacity;
	gt->current_arc = tal_arr(gt, struct arc, max_num_nodes);
	/* assumed to be zero at this point */
	gt->excess = supply;
	gt->potential = tal_arrz(gt, s64, max_num_nodes);
	gt->cost = tal_arrz(gt, s64, max_num_arcs);

	const s64 scale_factor = max_num_nodes;

	/* FIXME: advantage of knowing the minimum non-zero cost? */
	s64 max_epsilon = 0;
	for (u32 i = 0; i < max_num_arcs; i++)
		if (arc_enabled(gt->graph, arc_obj(i))) {
			max_epsilon = MAX(cost[i], max_epsilon);
			gt->cost[i] = cost[i] * scale_factor;
		}
	assert(check_overflow(max_epsilon, scale_factor, 9e18));
	goldberg_tarjan_circulation(gt, max_epsilon * scale_factor);

	tal_free(this_ctx);
	return true;

fail:
	tal_free(this_ctx);
	return false;
}
