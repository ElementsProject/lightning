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

/* Augment a `flow` amount along the path defined by `prev`.*/
static void augment_flow(const struct graph *graph,
			 const struct node source,
			 const struct node target,
			 const struct arc *prev,
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
		const struct arc dual = arc_dual(graph, arc);

		assert(arc.idx < max_num_arcs);
		assert(dual.idx < max_num_arcs);

		capacity[arc.idx] -= flow;
		capacity[dual.idx] += flow;

		assert(capacity[arc.idx] >= 0);

		/* we are traversing in the opposite direction to the flow,
		 * hence the next node is at the tail of the arc. */
		cur = arc_tail(graph, arc);

		/* We may never have a path exceeds the number of nodes, it this
		 * happens it means we have an infinite loop. */
		path_length++;
		if(path_length >= max_num_nodes)
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

		augment_flow(graph, source, destination, prev, capacity, delta);
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


bool simple_mcf(const tal_t *ctx, const struct graph *graph,
		const struct node source, const struct node destination,
		s64 *capacity, s64 amount, const s64 *cost)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	const size_t max_num_arcs = graph_max_num_arcs(graph);
	const size_t max_num_nodes = graph_max_num_nodes(graph);
	s64 remaining_amount = amount;

	if (amount < 0)
		goto finish;

	if (!graph || source.idx >= max_num_nodes ||
	    destination.idx >= max_num_nodes || !capacity || !cost)
		goto finish;

	if (tal_count(capacity) != max_num_arcs ||
	    tal_count(cost) != max_num_arcs)
		goto finish;

	struct arc *prev = tal_arr(this_ctx, struct arc, max_num_nodes);
	s64 *distance = tal_arrz(this_ctx, s64, max_num_nodes);
	s64 *potential = tal_arrz(this_ctx, s64, max_num_nodes);

	if (!prev || !distance || !potential)
		goto finish;

	/* FIXME: implement this algorithm as a search for matching negative and
	 * positive balance nodes, so that we can use it to adapt a flow
	 * structure for changes in the cost function. */
	while (remaining_amount > 0) {
		if (!dijkstra_path(this_ctx, graph, source, destination,
				   /* prune = */ true, capacity, 1, cost,
				   potential, prev, distance))
			goto finish;

		/* traverse the path and see how much flow we can send */
		s64 delta = get_augmenting_flow(graph, source, destination,
						capacity, prev);

		/* commit that flow to the path */
		delta = MIN(remaining_amount, delta);
		assert(delta > 0 && delta <= remaining_amount);

		augment_flow(graph, source, destination, prev, capacity, delta);
		remaining_amount -= delta;

		/* update potentials */
		for (u32 n = 0; n < max_num_nodes; n++) {
			/* see page 323 of Ahuja-Magnanti-Orlin.
			 * Whether we prune or not the Dijkstra search, the
			 * following potentials will keep reduced costs
			 * non-negative. */
			potential[n] -=
			    MIN(distance[destination.idx], distance[n]);
		}
	}
finish:
	tal_free(this_ctx);
	return remaining_amount == 0;
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
