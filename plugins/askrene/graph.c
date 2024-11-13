#include "config.h"
#include <plugins/askrene/graph.h>

/* in the background add the actual arc or dual arc */
static void graph_push_outbound_arc(struct graph *graph, const struct arc arc,
				    const struct node node)
{
	assert(arc.idx < graph_max_num_arcs(graph));
	assert(node.idx < graph_max_num_nodes(graph));

	/* arc is already added, skip */
	if (graph->arc_tail[arc.idx].idx != INVALID_INDEX)
		return;

	graph->arc_tail[arc.idx] = node;

	const struct arc first_arc = graph->node_adjacency_first[node.idx];
	graph->node_adjacency_next[arc.idx] = first_arc;
	graph->node_adjacency_first[node.idx] = arc;
}

bool graph_add_arc(struct graph *graph, const struct arc arc,
		   const struct node from, const struct node to)
{
	assert(from.idx < graph->max_num_nodes);
	assert(to.idx < graph->max_num_nodes);

	const struct arc dual = arc_dual(graph, arc);

	if (arc.idx >= graph->max_num_arcs || dual.idx >= graph->max_num_arcs)
		return false;

	graph_push_outbound_arc(graph, arc, from);
	graph_push_outbound_arc(graph, dual, to);

	return true;
}

struct graph *graph_new(const tal_t *ctx, const size_t max_num_nodes,
			const size_t max_num_arcs, const size_t arc_dual_bit)
{
	struct graph *graph;
	graph = tal(ctx, struct graph);

	graph->max_num_arcs = max_num_arcs;
	graph->max_num_nodes = max_num_nodes;
	graph->arc_dual_bit = arc_dual_bit;

	graph->arc_tail = tal_arr(graph, struct node, graph->max_num_arcs);
	graph->node_adjacency_first =
	    tal_arr(graph, struct arc, graph->max_num_nodes);
	graph->node_adjacency_next =
	    tal_arr(graph, struct arc, graph->max_num_arcs);

	/* initialize with invalid indexes so that we know these slots have
	 * never been used, eg. arc/node is newly created */
	for (size_t i = 0; i < graph->max_num_arcs; i++)
		graph->arc_tail[i] = node_obj(INVALID_INDEX);
	for (size_t i = 0; i < graph->max_num_nodes; i++)
		graph->node_adjacency_first[i] = arc_obj(INVALID_INDEX);
	for (size_t i = 0; i < graph->max_num_nodes; i++)
		graph->node_adjacency_next[i] = arc_obj(INVALID_INDEX);

	return graph;
}
