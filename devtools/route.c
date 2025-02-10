#include "config.h"
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/time/time.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/route.h>
#include <common/setup.h>
#include <devtools/clean_topo.h>
#include <inttypes.h>
#include <stdio.h>

static struct route_hop *least_cost(struct gossmap *map,
				    struct gossmap_node *src,
				    struct gossmap_node *dst)
{
	const struct dijkstra *dij;
	u32 srcidx = gossmap_node_idx(map, src);
	/* 10ksat, budget is 0.5% */
	const struct amount_msat sent = AMOUNT_MSAT(10000000);
	const struct amount_msat budget = amount_msat_div(sent, 200);
	struct amount_msat fee;
	const u32 riskfactor = 10;
	/* Max distance is 20 */
	const u32 distance_budget = ROUTING_MAX_HOPS;
	struct amount_msat maxcost;
	struct route_hop *path;
	struct timemono tstart, tstop;

	setup_locale();
	setup_tmpctx();

	tstart = time_mono();
	dij = dijkstra(tmpctx, map, dst,
		       sent, riskfactor, route_can_carry,
		       route_score_cheaper, NULL);
	tstop = time_mono();

	printf("# Time to find route: %"PRIu64" usec\n",
	       time_to_usec(timemono_between(tstop, tstart)));

	if (dijkstra_distance(dij, srcidx) > distance_budget) {
		printf("failed (too far)\n");
		return NULL;
	}
	if (!amount_msat_add(&maxcost, sent, budget))
		abort();
	path = route_from_dijkstra(map, map, dij, src, sent, 0);
	if (amount_msat_greater(path[0].amount, maxcost)) {
		printf("failed (too expensive)\n");
		return tal_free(path);
	}

	printf("# path length %zu\n", tal_count(path));
	/* We don't pay fee on first hop! */
	if (!amount_msat_sub(&fee, path[0].amount, sent))
		abort();
	printf("# path fee %s\n",
	       fmt_amount_msat(tmpctx, fee));
	tal_free(dij);
	return path;
}

int main(int argc, char *argv[])
{
	struct timemono tstart, tstop;
	struct gossmap_node *n, *dst;
	struct gossmap *map;
	struct node_id dstid;
	bool clean_topology = false;

	common_setup(argv[0]);

	opt_register_noarg("--clean-topology", opt_set_bool, &clean_topology,
			   "Clean up topology before run");
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "<gossipstore> <srcid>|all <dstid>\n"
			   "A routing test and benchmark program.",
			   "Get usage information");
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 4)
		opt_usage_exit_fail("Expect 3 arguments");

	tstart = time_mono();
	map = gossmap_load(NULL, argv[1], NULL, NULL);
	if (!map)
		err(1, "Loading gossip store %s", argv[1]);
	tstop = time_mono();

	printf("# Time to load: %"PRIu64" msec\n",
	       time_to_msec(timemono_between(tstop, tstart)));

	if (clean_topology)
		clean_topo(map, false);

	if (!node_id_from_hexstr(argv[3], strlen(argv[3]), &dstid))
		errx(1, "Bad dstid");
	dst = gossmap_find_node(map, &dstid);
	if (!dst)
		errx(1, "Unknown destination node '%s'", argv[3]);

	if (streq(argv[2], "all")) {
		for (n = gossmap_first_node(map);
		     n;
		     n = gossmap_next_node(map, n)) {
			struct node_id srcid;

			gossmap_node_get_id(map, n, &srcid);
			printf("# %s->%s\n",
			       fmt_node_id(tmpctx, &srcid),
			       fmt_node_id(tmpctx, &dstid));
			tal_free(least_cost(map, n, dst));
		}
	} else {
		struct route_hop *path;
		struct node_id srcid;

		if (!node_id_from_hexstr(argv[2], strlen(argv[2]), &srcid))
			errx(1, "Bad srcid");
		n = gossmap_find_node(map, &srcid);
		if (!n)
			errx(1, "Unknown source node '%s'", argv[2]);
		path = least_cost(map, n, dst);
		if (!path)
			exit(1);
		for (size_t i = 0; i < tal_count(path); i++) {
			printf("%s->%s via %s\n",
			       fmt_node_id(tmpctx, &srcid),
			       fmt_node_id(tmpctx, &path[i].node_id),
			       fmt_short_channel_id(tmpctx, path[i].scid));
			srcid = path[i].node_id;
		}
	}

	tal_free(map);
}
