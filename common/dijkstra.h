#ifndef LIGHTNING_COMMON_DIJKSTRA_H
#define LIGHTNING_COMMON_DIJKSTRA_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <common/amount.h>

struct gossmap;
struct gossmap_chan;
struct gossmap_node;

/* Do Dijkstra: start in this case is the dst node. */
const struct dijkstra *
dijkstra_(const tal_t *ctx,
	  const struct gossmap *gossmap,
	  const struct gossmap_node *start,
	  struct amount_msat amount,
	  double riskfactor,
	  bool (*channel_ok)(const struct gossmap *map,
			     const struct gossmap_chan *c,
			     int dir,
			     struct amount_msat amount,
			     void *arg),
	  bool (*path_better)(u32 old_distance,
			      u32 new_distance,
			      struct amount_msat old_cost,
			      struct amount_msat new_cost,
			      struct amount_msat old_risk,
			      struct amount_msat new_risk,
			      void *arg),
	  void *arg);

#define dijkstra(ctx, map, start, amount, riskfactor, channel_ok,	\
		 path_better, arg)					\
	dijkstra_((ctx), (map), (start), (amount), (riskfactor),	\
		  typesafe_cb_preargs(bool, void *, (channel_ok), (arg), \
				      const struct gossmap *,		\
				      const struct gossmap_chan *,	\
				      int, struct amount_msat),		\
		  typesafe_cb_preargs(bool, void *, (path_better), (arg), \
				      u32, u32,				\
				      struct amount_msat,		\
				      struct amount_msat,		\
				      struct amount_msat,		\
				      struct amount_msat),		\
		  (arg))

/* Returns UINT_MAX if unreachable. */
u32 dijkstra_distance(const struct dijkstra *dij, u32 node_idx);

/* Total CLTV delay (0 if unreachable) */
u32 dijkstra_delay(const struct dijkstra *dij, u32 node_idx);

/* Total cost to get here (-1ULL if unreachable) */
struct amount_msat dijkstra_amount(const struct dijkstra *dij, u32 node_idx);

/* Best path we found to here */
struct gossmap_chan *dijkstra_best_chan(const struct dijkstra *dij,
					u32 node_idx);

#endif /* LIGHTNING_COMMON_DIJKSTRA_H */
