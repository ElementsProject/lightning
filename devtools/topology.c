#include "config.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/time/time.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/route.h>
#include <common/type_to_string.h>
#include <devtools/clean_topo.h>
#include <inttypes.h>
#include <stdio.h>

/* We ignore capacity constraints */
static bool channel_usable(const struct gossmap *map,
			   const struct gossmap_chan *c,
			   int dir,
			   struct amount_msat amount,
			   void *unused)
{
	if (!gossmap_chan_set(c, dir))
		return false;
	if (!c->half[dir].enabled)
		return false;
	return true;
}

/* Note: dijkstra() sets dir to the neighbor side; i.e. c->half[dir].node_idx is the
 * neighbor. */
static bool channel_usable_to_excl(const struct gossmap *map,
				   const struct gossmap_chan *c,
				   int dir,
				   struct amount_msat amount,
				   struct gossmap_node *excl)
{
	if (!channel_usable(map, c, dir, amount, NULL))
		return false;

	/* Don't go via excl. */
	if (c->half[dir].nodeidx == gossmap_node_idx(map, excl))
		return false;
	return true;
}

/* What nodes can reach n without going through exclude? */
static size_t count_possible_sources(const struct gossmap *map,
				     struct gossmap_node *n,
				     struct gossmap_node *exclude,
				     bool is_last_node)
{
	const struct dijkstra *dij;
	size_t distance_budget, num;

	dij = dijkstra(tmpctx, map, n, AMOUNT_MSAT(0), 0,
		       channel_usable_to_excl, route_score_shorter, exclude);

	if (is_last_node)
		distance_budget = ROUTING_MAX_HOPS - 1;
	else
		distance_budget = ROUTING_MAX_HOPS - 2;

	assert(dijkstra_distance(dij, gossmap_node_idx(map, n)) == 0);
	assert(dijkstra_distance(dij, gossmap_node_idx(map, exclude)) == UINT_MAX);

	num = 0;
	for (n = gossmap_first_node(map); n; n = gossmap_next_node(map, n)) {
		if (dijkstra_distance(dij, gossmap_node_idx(map, n)) <= distance_budget)
			num++;
	}
	return num;
}

/* Note: dijkstra() sets dir to the neighbor side; i.e. c->half[dir].node_idx is the
 * neighbor. */
static bool channel_usable_from_excl(const struct gossmap *map,
				     const struct gossmap_chan *c,
				     int dir,
				     struct amount_msat amount,
				     struct gossmap_node *excl)
{
	if (!channel_usable(map, c, !dir, amount, NULL))
		return false;

	/* Don't go via excl. */
	if (c->half[dir].nodeidx == gossmap_node_idx(map, excl))
		return false;
	return true;
}

static size_t memcount(const void *mem, size_t len, char c)
{
	size_t count = 0;
	for (size_t i = 0; i < len; i++) {
		if (((char *)mem)[i] == c)
			count++;
	}
	return count;
}

static void visit(const struct gossmap *map,
		  struct gossmap_node *n,
		  struct gossmap_node *exclude,
		  bool *visited)
{
	if (n == exclude)
		return;
	if (visited[gossmap_node_idx(map, n)])
		return;
	visited[gossmap_node_idx(map, n)] = true;

	for (size_t i = 0; i < n->num_chans; i++) {
		int dir;
		struct gossmap_chan *c;
		c = gossmap_nth_chan(map, n, i, &dir);

		if (!channel_usable(map, c, dir, AMOUNT_MSAT(0), NULL))
			continue;
		visit(map, gossmap_nth_node(map, c, !dir), exclude, visited);
	}
}

/* What nodes can n reach without going through exclude? */
static size_t count_possible_destinations(const struct gossmap *map,
					  struct gossmap_node *start,
					  struct gossmap_node *exclude,
					  bool is_first_node)
{
	const struct dijkstra *dij;
	size_t distance_budget, num;

	dij = dijkstra(tmpctx, map, start, AMOUNT_MSAT(0), 0,
		       channel_usable_from_excl, route_score_shorter, exclude);

	if (is_first_node)
		distance_budget = ROUTING_MAX_HOPS - 1;
	else
		distance_budget = ROUTING_MAX_HOPS - 2;

	assert(dijkstra_distance(dij, gossmap_node_idx(map, start)) == 0);
	assert(dijkstra_distance(dij, gossmap_node_idx(map, exclude)) == UINT_MAX);

	num = 0;
	for (struct gossmap_node *n = gossmap_first_node(map);
	     n;
	     n = gossmap_next_node(map, n)) {
		if (dijkstra_distance(dij, gossmap_node_idx(map, n)) <= distance_budget)
			num++;
	}

	/* Now double-check with flood-fill. */
	bool *visited = tal_arrz(tmpctx, bool, gossmap_max_node_idx(map));
	visit(map, start, exclude, visited);
	assert(memcount(visited, tal_bytelen(visited), true) == num);
	return num;
}

static bool measure_least_cost(struct gossmap *map,
			       struct gossmap_node *src,
			       struct gossmap_node *dst)
{
	const struct dijkstra *dij;
	u32 srcidx = gossmap_node_idx(map, src);
	/* 10ksat, budget is 0.5% */
	const struct amount_msat sent = AMOUNT_MSAT(10000000);
	const struct amount_msat budget = amount_msat_div(sent, 200);
	const u32 riskfactor = 0;
	/* Max distance is 20 */
	const u32 distance_budget = ROUTING_MAX_HOPS;
	struct amount_msat maxcost, fee;
	struct route_hop *path;
	struct timemono tstart, tstop;
	struct node_id srcid;

	gossmap_node_get_id(map, src, &srcid);
	printf("# src %s (%u channels)\n",
	       fmt_node_id(tmpctx, &srcid),
	       src->num_chans);

	tstart = time_mono();
	dij = dijkstra(tmpctx, map, dst,
		       sent, riskfactor, channel_usable,
		       route_score_cheaper, NULL);
	tstop = time_mono();

	printf("# Time to find path: %"PRIu64" usec\n",
	       time_to_usec(timemono_between(tstop, tstart)));

	if (dijkstra_distance(dij, srcidx) > distance_budget) {
		printf("failed (%s)\n",
		       dijkstra_distance(dij, srcidx) == UINT_MAX ? "unreachable" : "too far");
		return false;
	}
	if (!amount_msat_add(&maxcost, sent, budget))
		abort();

	path = route_from_dijkstra(map, map, dij, src, sent, 0);

	if (amount_msat_greater(path[0].amount, maxcost)) {
		printf("failed (too expensive)\n");
		return false;
	}
	printf("# path length %zu\n", tal_count(path));
	if (!amount_msat_sub(&fee, path[0].amount, sent))
		abort();
	printf("# path fee %s\n",
	       fmt_amount_msat(tmpctx, fee));

	/* Count possible sources */
	for (size_t i = 0; i < tal_count(path); i++) {
		struct gossmap_node *prev, *cur;
		struct gossmap_chan *c = gossmap_find_chan(map, &path[i].scid);

		/* N+1th node is at end of Nth hop */
		prev = gossmap_nth_node(map, c, path[i].direction);
		cur = gossmap_nth_node(map, c, !path[i].direction);

		printf("source set size node %zu/%zu: %zu\n",
		       i+1, tal_count(path),
		       count_possible_sources(map, prev, cur, cur == dst));
	}

	/* Count possible destinations. */
	for (size_t i = 0; i < tal_count(path); i++) {
		struct gossmap_node *cur, *next;
		struct gossmap_chan *c = gossmap_find_chan(map, &path[i].scid);

		/* N+1th node is at end of Nth hop */
		cur = gossmap_nth_node(map, c, path[i].direction);
		next = gossmap_nth_node(map, c, !path[i].direction);

		printf("destination set size node %zu/%zu: %zu\n",
		       i, tal_count(path),
		       count_possible_destinations(map, next, cur, cur == src));
	}
	return true;
}

int main(int argc, char *argv[])
{
	struct timemono tstart, tstop;
	struct gossmap_node *n, *dst;
	struct gossmap *map;
	struct node_id dstid;
	bool no_singles = false;

	setup_locale();
	setup_tmpctx();

	opt_register_noarg("--no-single-sources", opt_set_bool, &no_singles,
			   "Eliminate single-channel nodes");
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "<gossipstore> <srcid>|all <dstid>\n"
			   "A topology test program.",
			   "Get usage information");
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 4)
		opt_usage_exit_fail("Expect 3 arguments");

	tstart = time_mono();
	map = gossmap_load(NULL, argv[1], NULL);
	if (!map)
		err(1, "Loading gossip store %s", argv[1]);
	tstop = time_mono();

	printf("# Time to load: %"PRIu64" msec\n",
	       time_to_msec(timemono_between(tstop, tstart)));

	clean_topo(map, no_singles);
	printf("# Reduced to %zu nodes and %zu channels\n",
	       gossmap_num_nodes(map), gossmap_num_chans(map));

	if (!node_id_from_hexstr(argv[3], strlen(argv[3]), &dstid))
		errx(1, "Bad dstid");
	dst = gossmap_find_node(map, &dstid);
	if (!dst)
		errx(1, "Unknown destination node '%s'", argv[3]);

	if (streq(argv[2], "all")) {
		for (n = gossmap_first_node(map);
		     n;
		     n = gossmap_next_node(map, n)) {
			measure_least_cost(map, n, dst);
			clean_tmpctx();
		}
	} else {
		struct node_id srcid;
		if (!node_id_from_hexstr(argv[2], strlen(argv[2]), &srcid))
			errx(1, "Bad srcid");
		n = gossmap_find_node(map, &srcid);
		if (!n)
			errx(1, "Unknown source node '%s'", argv[2]);
		if (!measure_least_cost(map, n, dst))
			exit(1);
	}

	tal_free(map);
}
