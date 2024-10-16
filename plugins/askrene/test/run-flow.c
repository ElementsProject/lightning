#include "config.h"
#include <assert.h>
#include <ccan/tal/tal.h>
#include <common/setup.h>
#include <inttypes.h>
#include <plugins/askrene/graph.h>
#include <stdio.h>

#include "../algorithm.c"

#define MAX_NODES 256
#define MAX_ARCS 256
#define DUAL_BIT 7

#define CHECK(arg) if(!(arg)){fprintf(stderr, "failed CHECK at line %d: %s\n", __LINE__, #arg); abort();}

static void problem1(void){
	printf("Allocating a memory context\n");
	tal_t *ctx = tal(NULL, tal_t);
	assert(ctx);

	printf("Allocating a graph\n");
	struct graph *graph = graph_new(ctx, MAX_NODES, MAX_ARCS, DUAL_BIT);
	assert(graph);

	s64 *capacity = tal_arrz(ctx, s64, MAX_ARCS);

	graph_add_arc(graph, arc_obj(0), node_obj(1), node_obj(2));
	capacity[0] = 1;
	graph_add_arc(graph, arc_obj(1), node_obj(1), node_obj(3));
	capacity[1] = 4;
	graph_add_arc(graph, arc_obj(2), node_obj(2), node_obj(4));
	capacity[2] = 1;
	graph_add_arc(graph, arc_obj(3), node_obj(2), node_obj(5));
	capacity[3] = 1;
	graph_add_arc(graph, arc_obj(4), node_obj(3), node_obj(5));
	capacity[4] = 4;
	graph_add_arc(graph, arc_obj(5), node_obj(4), node_obj(6));
	capacity[5] = 1;
	graph_add_arc(graph, arc_obj(6), node_obj(6), node_obj(10));
	capacity[6] = 1;
	graph_add_arc(graph, arc_obj(7), node_obj(5), node_obj(10));
	capacity[7] = 4;

	struct node src = {.idx = 1};
	struct node dst = {.idx = 10};

	bool result = simple_feasibleflow(ctx, graph, src, dst, capacity, 5);
	CHECK(result);

	CHECK(node_balance(graph, src, capacity) == -5);
	CHECK(node_balance(graph, dst, capacity) == 5);

	for (u32 i = 2; i < 10; i++)
		CHECK(node_balance(graph, node_obj(i), capacity) == 0);

	printf("Freeing memory\n");
	ctx = tal_free(ctx);
}

static void problem2(void){
	/* Stress the graph constraints by setting max_num_nodes to exactly the
	 * number of node that participate and put all nodes in line to achieve
	 * the largest path length possible. */
	printf("Allocating a memory context\n");
	tal_t *ctx = tal(NULL, tal_t);
	assert(ctx);

	printf("Allocating a graph\n");
	struct graph *graph = graph_new(ctx, 5, MAX_ARCS, DUAL_BIT);
	assert(graph);

	s64 *capacity = tal_arrz(ctx, s64, MAX_ARCS);

	graph_add_arc(graph, arc_obj(0), node_obj(0), node_obj(1));
	capacity[0] = 1;
	graph_add_arc(graph, arc_obj(1), node_obj(1), node_obj(2));
	capacity[1] = 4;
	graph_add_arc(graph, arc_obj(2), node_obj(2), node_obj(3));
	capacity[2] = 1;
	graph_add_arc(graph, arc_obj(3), node_obj(3), node_obj(4));
	capacity[3] = 1;

	struct node src = {.idx = 0};
	struct node dst = {.idx = 4};

	bool result = simple_feasibleflow(ctx, graph, src, dst, capacity, 1);
	CHECK(result);

	CHECK(node_balance(graph, src, capacity) == -1);
	CHECK(node_balance(graph, dst, capacity) == 1);

	for (u32 i = 1; i < 4; i++)
		CHECK(node_balance(graph, node_obj(i), capacity) == 0);

	printf("Freeing memory\n");
	ctx = tal_free(ctx);
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	printf("\n\nProblem 1\n\n");
	problem1();

	printf("\n\nProblem 2\n\n");
	problem2();

	common_shutdown();
	return 0;
}

