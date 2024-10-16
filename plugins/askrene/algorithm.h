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

#endif /* LIGHTNING_PLUGINS_ASKRENE_ALGORITHM_H */
