/* Routing helpers for use with dijkstra */
#ifndef LIGHTNING_COMMON_ROUTE_H
#define LIGHTNING_COMMON_ROUTE_H
#include "config.h"
#include <common/amount.h>

struct dijkstra;
struct gossmap;

struct route {
	int dir;
	struct gossmap_chan *c;
};

/* Can c carry amount in dir? */
bool route_can_carry(const struct gossmap *map,
		     const struct gossmap_chan *c,
		     int dir,
		     struct amount_msat amount,
		     void *arg);

/* Same, but ignore disabled flags on channel */
bool route_can_carry_even_disabled(const struct gossmap *map,
				   const struct gossmap_chan *c,
				   int dir,
				   struct amount_msat amount,
				   void *unused);

/* Shortest path, with lower amount tiebreak */
u64 route_score_shorter(u32 distance,
			struct amount_msat cost,
			struct amount_msat risk);

/* Cheapest path, with shorter path tiebreak */
u64 route_score_cheaper(u32 distance,
			struct amount_msat cost,
			struct amount_msat risk);

/* Extract route tal_arr from completed dijkstra: NULL if none. */
struct route **route_from_dijkstra(const tal_t *ctx,
				   const struct gossmap *map,
				   const struct dijkstra *dij,
				   const struct gossmap_node *cur);
#endif /* LIGHTNING_COMMON_ROUTE_H */
