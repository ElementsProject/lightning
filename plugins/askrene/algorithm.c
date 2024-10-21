#include "config.h"
#include <ccan/bitmap/bitmap.h>
#include <ccan/lqueue/lqueue.h>
#include <ccan/tal/tal.h>
#include <plugins/askrene/algorithm.h>
#include <plugins/askrene/priorityqueue.h>

static const s64 INFINITE = INT64_MAX;

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/* Simple queue to traverse the network. */
struct queue_data {
	u32 idx;
	struct lqueue_link ql;
};

bool BFS_path(const tal_t *ctx, const struct graph *graph,
	      const struct node source, const struct node destination,
	      const s64 *capacity, const s64 cap_threshold, struct arc *prev)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	bool target_found = false;
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	/* check preconditions */
	if (!graph || source.idx >= max_num_nodes || !capacity || !prev)
		goto finish;

	if (tal_count(capacity) != max_num_arcs ||
	    tal_count(prev) != max_num_nodes)
		goto finish;

	for (size_t i = 0; i < max_num_nodes; i++)
		prev[i].idx = INVALID_INDEX;

	LQUEUE(struct queue_data, ql) myqueue = LQUEUE_INIT;
	struct queue_data *qdata;

	qdata = tal(this_ctx, struct queue_data);
	qdata->idx = source.idx;
	lqueue_enqueue(&myqueue, qdata);

	while (!lqueue_empty(&myqueue)) {
		qdata = lqueue_dequeue(&myqueue);
		struct node cur = {.idx = qdata->idx};

		tal_free(qdata);

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
			if (prev[next.idx].idx != INVALID_INDEX)
				continue;

			prev[next.idx] = arc;

			qdata = tal(this_ctx, struct queue_data);
			qdata->idx = next.idx;
			lqueue_enqueue(&myqueue, qdata);
		}
	}

finish:
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
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);
	tal_t *this_ctx = tal(ctx, tal_t);

	/* check preconditions */
	if (!graph || source.idx >=max_num_nodes || !cost || !capacity ||
	    !prev || !distance)
		goto finish;

	/* if prune is true then the destination cannot be invalid */
	if (destination.idx >=max_num_nodes && prune)
		goto finish;

	if (tal_count(cost) != max_num_arcs ||
	    tal_count(capacity) != max_num_arcs ||
	    tal_count(prev) != max_num_nodes ||
	    tal_count(distance) != max_num_nodes)
		goto finish;

	/* FIXME: maybe this is unnecessary */
	bitmap *visited = tal_arrz(this_ctx, bitmap,
				   BITMAP_NWORDS(max_num_nodes));

	if (!visited)
		/* bad allocation */
		goto finish;

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

finish:
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
static inline void sendflow(const struct graph *graph, const struct arc arc,
			    const s64 flow, s64 *arc_capacity,
			    s64 *node_balance)
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
	tal_t *this_ctx = tal(ctx, tal_t);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	/* check preconditions */
	if (amount < 0)
		goto finish;

	if (!graph || source.idx >= max_num_nodes ||
	    destination.idx >= max_num_nodes || !capacity)
		goto finish;

	if (tal_count(capacity) != max_num_arcs)
		goto finish;

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
static inline s64 reduced_cost(const struct graph *graph, const struct arc arc,
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
	tal_t *this_ctx = tal(ctx, tal_t);

	if (!this_ctx)
		/* bad allocation */
		goto finish;

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
#ifndef NDEBUG
	bitmap *visited =
	    tal_arrz(this_ctx, bitmap, BITMAP_NWORDS(max_num_nodes));
	assert(visited);
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
#ifndef NDEBUG
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
	tal_t *this_ctx = tal(ctx, tal_t);

	if (!this_ctx)
		/* bad allocation */
		goto finish;

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

#ifndef NDEBUG
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
	tal_t *this_ctx = tal(ctx, tal_t);
	if (!this_ctx)
		/* bad allocation */
		goto fail;

	if (!graph)
		goto fail;

	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);

	if (amount < 0 || source.idx >= max_num_nodes ||
	    destination.idx >= max_num_nodes || !capacity || !cost)
		goto fail;

	if (tal_count(capacity) != max_num_arcs ||
	    tal_count(cost) != max_num_arcs)
		goto fail;

	s64 *potential = tal_arrz(this_ctx, s64, max_num_nodes);
	s64 *excess = tal_arrz(this_ctx, s64, max_num_nodes);

	if (!potential || !excess)
		/* bad allocation */
		goto fail;

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
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	s64 total_cost = 0;

	assert(graph && capacity && cost);
	assert(tal_count(capacity) == max_num_arcs &&
	       tal_count(cost) == max_num_arcs);

	for (u32 i = 0; i < max_num_arcs; i++) {
		struct arc arc = {.idx = i};
		struct arc dual = arc_dual(graph, arc);

		if (arc_is_dual(graph, arc))
			continue;

		total_cost += capacity[dual.idx] * cost[arc.idx];
	}
	return total_cost;
}
