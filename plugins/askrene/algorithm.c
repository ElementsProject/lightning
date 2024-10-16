#include "config.h"
#include <ccan/bitmap/bitmap.h>
#include <ccan/lqueue/lqueue.h>
#include <ccan/tal/tal.h>
#include <plugins/askrene/algorithm.h>
#include <plugins/askrene/priorityqueue.h>

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
