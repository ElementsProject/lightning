#ifndef LIGHTNING_PLUGINS_ASKRENE_GRAPH_H
#define LIGHTNING_PLUGINS_ASKRENE_GRAPH_H

/* Defines a graph data structure. */

#include "config.h"
#include <assert.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

#define INVALID_INDEX 0xffffffff

/* A directed arc in a graph.
 * It is a simple data object for typesafey. */
struct arc {
	/* arc's index */
	u32 idx;
};

/* A node in a graph.
 * It is a simple data object for typesafety. */
struct node {
	/* node's index */
	u32 idx;
};

static inline struct arc arc_obj(u32 index)
{
	struct arc arc = {.idx = index};
	return arc;
}
static inline struct node node_obj(u32 index)
{
	struct node node = {.idx = index};
	return node;
}

/* A graph's topology. */
struct graph {
	/* Every arc emanates from a node, the tail.
	 * The head of the arc is the tail of the dual. */
	struct node *arc_tail;

	/* Adjacency data for nodes. Used to move in a graph in the direction of
	 * the arcs by looping over all arcs that exit a node.
	 *
	 * For every directed arc there is a dual in the opposite direction,
	 * therefore we can use the same adjacency information to traverse in
	 * the head to tails direction as well. */
	struct arc *node_adjacency_next;
	struct arc *node_adjacency_first;

	size_t max_num_arcs, max_num_nodes;

	/* Bit that must be flipped to obtain the dual of an arc. */
	size_t arc_dual_bit;
};

//////////////////////////////////////////////////////////////////////////////

static inline size_t graph_max_num_arcs(const struct graph *graph)
{
	return graph->max_num_arcs;
}
static inline size_t graph_max_num_nodes(const struct graph *graph)
{
	return graph->max_num_nodes;
}

/* Give me the dual of an arc. */
static inline struct arc arc_dual(const struct graph *graph, struct arc arc)
{
	arc.idx ^= (1U << graph->arc_dual_bit);
	return arc;
}

/* Is this arc a dual? */
static inline bool arc_is_dual(const struct graph *graph, struct arc arc)
{
	return (arc.idx & (1U << graph->arc_dual_bit)) != 0;
}

/* Give me the node at the tail of an arc. */
static inline struct node arc_tail(const struct graph *graph,
				   const struct arc arc)
{
	assert(arc.idx < tal_count(graph->arc_tail));
	return graph->arc_tail[arc.idx];
}

/* Give me the node at the head of an arc. */
static inline struct node arc_head(const struct graph *graph,
				   const struct arc arc)
{
	const struct arc dual = arc_dual(graph, arc);
	assert(dual.idx < tal_count(graph->arc_tail));
	return graph->arc_tail[dual.idx];
}

/* Used to loop over the arcs that exit a node.
 *
 * for example:
 *
 * void show(struct graph *graph, struct node node) {
 * 	printf("Showing node %" PRIu32 "\n", node.idx);
 * 	for (struct arc arc = node_adjacency_begin(graph, node);
 * 	     !node_adjacency_end(arc);
 * 	     arc = node_adjacency_next(graph, arc)) {
 * 		printf("arc id: %" PRIu32 ", (%" PRIu32 " -> %" PRIu32 ")\n",
 * 		       arc.idx,
 * 		       arc_tail(graph, arc).idx,
 * 		       arc_head(graph, arc).idx);
 * 	}
 * }
 * */
static inline struct arc node_adjacency_begin(const struct graph *graph,
					      const struct node node)
{
	assert(node.idx < tal_count(graph->node_adjacency_first));
	return graph->node_adjacency_first[node.idx];
}
static inline bool node_adjacency_end(const struct arc arc)
{
	return arc.idx == INVALID_INDEX;
}
static inline struct arc node_adjacency_next(const struct graph *graph,
					     const struct arc arc)
{
	assert(arc.idx < tal_count(graph->node_adjacency_next));
	return graph->node_adjacency_next[arc.idx];
}

/* Used to loop over the arcs that enter a node. */
static inline struct arc node_rev_adjacency_begin(const struct graph *graph,
						  const struct node node)
{
	return arc_dual(graph, node_adjacency_begin(graph, node));
}
static inline bool node_rev_adjacency_end(const struct arc arc)
{
	return arc.idx == INVALID_INDEX;
}
static inline struct arc node_rev_adjacency_next(const struct graph *graph,
						 const struct arc arc)
{
	return arc_dual(graph,
			node_adjacency_next(graph, arc_dual(graph, arc)));
}

/* This call adds an arc to the graph, it adds also the dual automatically.
 * An arc cannot be added twice, if the caller tries to do add the same arc
 * twice the second call is ignored.
 * The call fails if the arc or its dual do not fit into max_num_arcs. */
bool graph_add_arc(struct graph *graph, const struct arc arc,
		   const struct node from, const struct node to);

/* Creates a graph object. Nodes and arcs are indexed from 0 to max_num_nodes-1
 * and max_num_arcs-1 respectively. The max_num_arcs should be big enough to
 * accomodate also the dual arcs, ie. if the maximum index for a problem arc is
 * I then Idual = I^(1<<arc_dual_bit) must be a valid arc index
 * Idual<max_num_arcs. */
struct graph *graph_new(const tal_t *ctx, const size_t max_num_nodes,
			const size_t max_num_arcs, const size_t arc_dual_bit);

#endif /* LIGHTNING_PLUGINS_ASKRENE_GRAPH_H */
