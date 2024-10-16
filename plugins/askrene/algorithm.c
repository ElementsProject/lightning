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
