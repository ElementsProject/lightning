#include "config.h"
#include <assert.h>
#include <ccan/tal/tal.h>
#include <common/setup.h>
#include <inttypes.h>
#include <plugins/askrene/graph.h>
#include <stdio.h>

#include "../algorithm.c"

#define CHECK(arg) if(!(arg)){fprintf(stderr, "failed CHECK at line %d: %s\n", __LINE__, #arg); abort();}

#define MAX_NODES 256
#define MAX_ARCS 256
#define DUAL_BIT 7

int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	printf("Allocating a memory context\n");
	tal_t *ctx = tal(NULL, tal_t);
	assert(ctx);

	printf("Allocating a graph\n");
	struct graph *graph = graph_new(ctx, MAX_NODES, MAX_ARCS, DUAL_BIT);
	assert(graph);

	s64 *capacity = tal_arrz(ctx, s64, MAX_ARCS);
	s64 *cost = tal_arrz(ctx, s64, MAX_ARCS);

	graph_add_arc(graph, arc_obj(0), node_obj(0), node_obj(1));
	capacity[0] = 2, cost[0] = 0;
	graph_add_arc(graph, arc_obj(1), node_obj(0), node_obj(2));
	capacity[1] = 2, cost[1] = 0;
	graph_add_arc(graph, arc_obj(2), node_obj(1), node_obj(3));
	capacity[2] = 1, cost[2] = 1;
	graph_add_arc(graph, arc_obj(3), node_obj(1), node_obj(4));
	capacity[3] = 1, cost[3] = 2;
	graph_add_arc(graph, arc_obj(4), node_obj(2), node_obj(3));
	capacity[4] = 2, cost[4] = 1;
	graph_add_arc(graph, arc_obj(5), node_obj(2), node_obj(4));
	capacity[5] = 1, cost[5] = 2;
	graph_add_arc(graph, arc_obj(6), node_obj(3), node_obj(5));
	capacity[6] = 3, cost[6] = 0;
	graph_add_arc(graph, arc_obj(7), node_obj(4), node_obj(5));
	capacity[7] = 3, cost[7] = 0;

	struct node src = {.idx = 0};
	struct node dst = {.idx = 5};

	bool result = simple_mcf(ctx, graph, src, dst, capacity, 4, cost);
	CHECK(result);

	CHECK(node_balance(graph, src, capacity) == -4);
	CHECK(node_balance(graph, dst, capacity) == 4);

	for (u32 i = 1; i < 4; i++)
		CHECK(node_balance(graph, node_obj(i), capacity) == 0);

	const s64 total_cost = flow_cost(graph, capacity, cost);
	printf("best flow cost: %" PRIi64 "\n", total_cost);
	CHECK(total_cost == 5);

	printf("Freeing memory\n");
	ctx = tal_free(ctx);
	common_shutdown();
	return 0;
}
