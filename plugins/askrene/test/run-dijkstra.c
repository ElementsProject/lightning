#include "config.h"
#include <assert.h>
#include <ccan/tal/tal.h>
#include <common/setup.h>
#include <inttypes.h>
#include <plugins/askrene/graph.h>
#include <stdio.h>

#define ASKRENE_UNITTEST
#include "../algorithm.c"

// 1->2 7
// 1->3 9
// 1->6 14
// 2->3 10
// 2->4 15
// 3->6 2
// 3->4 11
// 4->5 6
// 5->6 9

#define MAX_NODES 256
#define MAX_ARCS 256
#define DUAL_BIT 7

#define CHECK(arg) if(!(arg)){fprintf(stderr, "failed CHECK at line %d: %s\n", __LINE__, #arg); abort();}

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

	s64 *capacity = tal_arrz(ctx, s64, MAX_ARCS);
	s64 *cost = tal_arrz(ctx, s64, MAX_ARCS);
	s64 *potential = tal_arrz(ctx, s64, MAX_NODES);
	s64 *distance = tal_arr(ctx, s64, MAX_NODES);
	struct arc *prev = tal_arr(ctx, struct arc, MAX_NODES);

	graph_add_arc(graph, arc_obj(0), node_obj(1), node_obj(2));
	cost[0] = 7, capacity[0] = 1;
	graph_add_arc(graph, arc_obj(1), node_obj(1), node_obj(3));
	cost[1] = 9, capacity[1] = 1;
	graph_add_arc(graph, arc_obj(2), node_obj(1), node_obj(6));
	cost[2] = 14, capacity[2] = 1;
	graph_add_arc(graph, arc_obj(3), node_obj(2), node_obj(3));
	cost[3] = 10, capacity[3] = 1;
	graph_add_arc(graph, arc_obj(4), node_obj(2), node_obj(4));
	cost[4] = 15, capacity[4] = 1;
	graph_add_arc(graph, arc_obj(5), node_obj(3), node_obj(4));
	cost[5] = 11, capacity[5] = 1;
	graph_add_arc(graph, arc_obj(6), node_obj(3), node_obj(6));
	cost[6] = 2, capacity[6] = 1;
	graph_add_arc(graph, arc_obj(7), node_obj(4), node_obj(5));
	cost[7] = 6, capacity[7] = 1;
	graph_add_arc(graph, arc_obj(8), node_obj(5), node_obj(6));
	cost[8] = 9, capacity[8] = 1;

	show(graph, node_obj(1));
	show(graph, node_obj(2));
	show(graph, node_obj(3));
	show(graph, node_obj(4));
	show(graph, node_obj(5));
	show(graph, node_obj(6));

	struct node src = {.idx = 1};
	struct node dst = {.idx = 6};

	bool result = dijkstra_path(ctx, graph, src, dst, false, capacity, 1,
				    cost, potential, prev, distance);
	CHECK(result);

	int pathlen = 0;
	int arc_sequence[] = {6, 1};
	int node_sequence[] = {3, 1};

	for (struct node cur = dst; cur.idx != src.idx;) {
		struct arc arc = prev[cur.idx];
		printf("node(%" PRIu32 ") arc(%" PRIu32 ") - ", cur.idx,
		       arc.idx);
		cur = arc_tail(graph, arc);
		CHECK(pathlen < 2);
		CHECK(cur.idx == node_sequence[pathlen]);
		CHECK(arc.idx == arc_sequence[pathlen]);
		pathlen++;
	}
	CHECK(pathlen == 2);

	for (size_t i = 1; i <= 6; i++) {
		printf("node: %zu, distance: %" PRIi64 "\n", i, distance[i]);
	}

	CHECK(distance[1] == 0);
	CHECK(distance[2] == 7);
	CHECK(distance[3] == 9);
	CHECK(distance[4] == 20);
	CHECK(distance[5] == 26);
	CHECK(distance[6] == 11);

	printf("Freeing memory\n");
	ctx = tal_free(ctx);

	common_shutdown();
	return 0;
}
