#include "config.h"
#include <assert.h>
#include <ccan/tal/tal.h>
#include <common/setup.h>
#include <common/utils.h>
#include <inttypes.h>
#include <stdio.h>

#define ASKRENE_UNITTEST
#include "../graph.c"

#define MAX_NODES 10
#define MAX_ARCS 256
#define DUAL_BIT 7

static void show(struct graph *graph, struct node node)
{
	printf("Showing node %" PRIu32 "\n", node.idx);
	for (struct arc arc = node_adjacency_begin(graph, node);
	     !node_adjacency_end(arc); arc = node_adjacency_next(graph, arc)) {
		printf("arc id: %" PRIu32 ", (%" PRIu32 " -> %" PRIu32 ")\n",
		       arc.idx, arc_tail(graph, arc).idx,
		       arc_head(graph, arc).idx);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	printf("Allocating a memory context\n");
	tal_t *ctx = tal(NULL, tal_t);
	assert(ctx);

	printf("Allocating a graph\n");
	struct graph *graph = graph_new(ctx, MAX_NODES, MAX_ARCS, DUAL_BIT);
	assert(graph);

	bool success;

	success = graph_add_arc(graph, arc_obj(0), node_obj(0), node_obj(1));
	assert(success);

	success = graph_add_arc(graph, arc_obj(1), node_obj(0), node_obj(2));
	assert(success);

	success = graph_add_arc(graph, arc_obj(2), node_obj(0), node_obj(3));
	assert(success);

	success = graph_add_arc(graph, arc_obj(3), node_obj(3), node_obj(2));
	assert(success);

	show(graph, node_obj(0));
	show(graph, node_obj(1));
	show(graph, node_obj(2));
	show(graph, node_obj(3));

	printf("Freeing memory\n");
	ctx = tal_free(ctx);
	common_shutdown();
	return 0;
}

