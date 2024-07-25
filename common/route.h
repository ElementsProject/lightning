/* Routing helpers for use with dijkstra */
#ifndef LIGHTNING_COMMON_ROUTE_H
#define LIGHTNING_COMMON_ROUTE_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <common/amount.h>
#include <common/node_id.h>

struct dijkstra;
struct gossmap;
struct gossmap_chan;
struct gossmap_node;

/**
 * struct route_hop: a hop in a route.
 *
 * @scid: the short_channel_id.
 * @direction: 0 (dest node_id < src node_id), 1 (dest node_id > src).
 * @node_id: the node_id of the destination of this hop.
 * @amount: amount to send through this hop.
 * @total_amount: The amount the channel was funded with.
 * @delay: total cltv delay at this hop.
 */
struct route_hop {
	struct short_channel_id scid;
	int direction;
	struct node_id node_id;
	struct amount_msat amount;
	struct amount_msat total_amount;
	u32 delay;
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
u64 route_score_shorter(struct amount_msat fee,
			struct amount_msat risk,
			struct amount_msat total,
			int dir UNUSED,
			const struct gossmap_chan *c UNUSED);

/* Cheapest path, with shorter path tiebreak */
u64 route_score_cheaper(struct amount_msat fee,
			struct amount_msat risk,
			struct amount_msat total,
			int dir UNUSED,
			const struct gossmap_chan *c UNUSED);

/* Extract route tal_arr from completed dijkstra: NULL if none. */
struct route_hop *route_from_dijkstra(const tal_t *ctx,
				      const struct gossmap *map,
				      const struct dijkstra *dij,
				      const struct gossmap_node *src,
				      struct amount_msat final_amount,
				      u32 final_cltv);

/*
 * Manually exlude nodes or channels from a route.
 * Used with `getroute` and `pay` commands
 */
enum route_exclusion_type {
	EXCLUDE_CHANNEL = 1,
	EXCLUDE_NODE = 2
};

struct route_exclusion {
	enum route_exclusion_type type;
	union {
		struct short_channel_id_dir chan_id;
		struct node_id node_id;
	} u;
};

#endif /* LIGHTNING_COMMON_ROUTE_H */
