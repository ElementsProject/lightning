#ifndef LIGHTNING_PLUGINS_ASKRENE_ALGORITHM_H
#define LIGHTNING_PLUGINS_ASKRENE_ALGORITHM_H

/* Implementation of network algorithms: shortests path, minimum cost flow, etc.
 */

#include "config.h"
#include <plugins/askrene/graph.h>

/* Search any path from source to destination using Breadth First Search.
 *
 * input:
 * @ctx: tal allocator,
 * @graph: graph of the network,
 * @source: source node,
 * @destination: destination node,
 * @capacity: arcs capacity
 * @cap_threshold: an arc i is traversable if capacity[i]>=cap_threshold
 *
 * output:
 * @prev: prev[i] is the arc that leads to node i for an optimal solution, it
 * @return: true if the destination node was reached.
 *
 * precondition:
 * |capacity|=graph_max_num_arcs
 * |prev|=graph_max_num_nodes
 *
 * The destination is only used as a stopping condition, if destination is
 * passed with an invalid idx then the algorithm will produce a discovery tree
 * of all reacheable nodes from the source.
 * */
bool BFS_path(const tal_t *ctx, const struct graph *graph,
	      const struct node source, const struct node destination,
	      const s64 *capacity, const s64 cap_threshold, struct arc *prev);


/* Computes the distance from the source to every other node in the network
 * using Dijkstra's algorithm.
 *
 * input:
 * @ctx: tal context for internal allocation
 * @graph: topological information of the graph
 * @source: source node
 * @destination: destination node
 * @prune: if prune is true the algorithm stops when the optimal path is found
 * for the destination node
 * @capacity: arcs capacity
 * @cap_threshold: an arc i is traversable if capacity[i]>=cap_threshold
 * @cost: arc's cost
 * @potential: nodes' potential, ie. reduced cost for an arc
 * 	c_ij = cost_ij - potential[i] + potential[j]
 *
 * output:
 * @prev: for each node, this is the arc that was used to arrive to it, this can
 * be used to reconstruct the path from the destination to the source,
 * @distance: node's best distance
 * returns true if an optimal path is found for the destination, false otherwise
 *
 * precondition:
 * |capacity|=|cost|=graph_max_num_arcs
 * |prev|=|distance|=graph_max_num_nodes
 * cost[i]>=0
 * if prune is true the destination must be valid
 * */
bool dijkstra_path(const tal_t *ctx, const struct graph *graph,
		   const struct node source, const struct node destination,
		   bool prune, const s64 *capacity, const s64 cap_threshold,
		   const s64 *cost, const s64 *potential, struct arc *prev,
		   s64 *distance);


#endif /* LIGHTNING_PLUGINS_ASKRENE_ALGORITHM_H */
