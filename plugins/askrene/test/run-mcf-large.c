#include "config.h"
#include <assert.h>
#include <ccan/tal/tal.h>
#include <common/setup.h>
#include <inttypes.h>
#include <plugins/askrene/graph.h>
#include <stdio.h>

#include "../algorithm.c"

#ifdef HAVE_ZLIB
#include <zlib.h>

gzFile infile;
#define BUFFER_SIZE 10000
char buffer[BUFFER_SIZE];

static int myscanf(const char *fmt, ...)
{
	gzgets(infile, buffer, BUFFER_SIZE);
	va_list args;
	va_start(args, fmt);
	int ret = vsscanf(buffer, fmt, args);
	va_end(args);
	return ret;
}

#endif

#define CHECK(arg) if(!(arg)){fprintf(stderr, "failed CHECK at line %d: %s\n", __LINE__, #arg); abort();}

/* Read multiple testcases from a file.
 * Each test case consist of:
 * - one line with N and M, the number of nodes and arcs
 * - for each arc a line with numbers head, tail, cap and cost, defining the
 * arc's endpoints and values,
 * - one line with numbers: amount and best_cost, indicating that we wish to
 *   send amount from node 0 to node 1 with minimum cost, the correct answer
 *   should contain a flow cost equal to best_cost.
 *
 * A feasible solution is guaranteed.
 * The last test case has 0 nodes and should be ignored. */

static int next_bit(s64 x)
{
	int b;
	for (b = 0; (1LL << b) <= x; b++)
		;
	return b;
}

static bool solve_case(const tal_t *ctx)
{
	int ret;
	static int c = 0;
	c++;
	const tal_t *this_ctx = tal(ctx, tal_t);

	int N_nodes, N_arcs;
	ret = myscanf("%d %d\n", &N_nodes, &N_arcs);
	CHECK(ret == 2);
	printf("Testcase %d\n", c);
	printf("nodes %d arcs %d\n", N_nodes, N_arcs);
	if (N_nodes == 0 && N_arcs == 0)
		goto fail;

	const int MAX_NODES = N_nodes;
	const int DUAL_BIT = next_bit(N_arcs-1);
	const int MAX_ARCS = 1LL << (DUAL_BIT+1);
	printf("max nodes %d max arcs %d bit %d\n", MAX_NODES, MAX_ARCS, DUAL_BIT);

	struct graph *graph = graph_new(ctx, MAX_NODES, MAX_ARCS, DUAL_BIT);
	CHECK(graph);

	s64 *capacity = tal_arrz(ctx, s64, MAX_ARCS);
	s64 *cost = tal_arrz(ctx, s64, MAX_ARCS);

	for (u32 i = 0; i < N_arcs; i++) {
		u32 from, to;
		ret = myscanf("%" PRIu32 " %" PRIu32 " %" PRIi64 " %" PRIi64,
			      &from, &to, &capacity[i], &cost[i]);
		CHECK(ret == 4);
		struct arc arc = {.idx = i};
		graph_add_arc(graph, arc, node_obj(from), node_obj(to));

		struct arc dual = arc_dual(graph, arc);
		cost[dual.idx] = -cost[i];
	}
	printf("Reading arcs finished\n");
	struct node src = {.idx = 0};
	struct node dst = {.idx = 1};

	s64 amount, best_cost;
	ret = myscanf("%" PRIi64 " %" PRIi64, &amount, &best_cost);
	CHECK(ret == 2);

	bool result = simple_mcf(ctx, graph, src, dst, capacity, amount, cost);
	CHECK(result);

	CHECK(node_balance(graph, src, capacity) == -amount);
	CHECK(node_balance(graph, dst, capacity) == amount);

	for (u32 i = 2; i < N_nodes; i++)
		CHECK(node_balance(graph, node_obj(i), capacity) == 0);

	const s64 total_cost = flow_cost(graph, capacity, cost);
	CHECK(total_cost == best_cost);

	tal_free(this_ctx);
	return true;

fail:
	tal_free(this_ctx);
	return false;
}

int main(int argc, char *argv[])
{
#ifdef HAVE_ZLIB
	common_setup(argv[0]);
	infile = gzopen("plugins/askrene/test/data/linear_mcf.gz", "r");
	CHECK(infile);
	const tal_t *ctx = tal(NULL, tal_t);
	CHECK(ctx);

	/* One test case after another. The last test case has N number of nodes
	 * and arcs equal to 0 and must be ignored. */
	while (solve_case(ctx))
		;

	ctx = tal_free(ctx);
	gzclose(infile);
	common_shutdown();
	return 0;
#else
	return 0;
#endif
}

