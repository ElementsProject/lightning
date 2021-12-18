#ifndef LIGHTNING_COMMON_DIJKSTRA_H
#define LIGHTNING_COMMON_DIJKSTRA_H
#include "config.h"
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
	  u64 (*path_score)(u32 distance,
			    struct amount_msat cost,
			    struct amount_msat risk,
			    int dir,
			    const struct gossmap_chan *c),
	  void *arg);

#define dijkstra(ctx, map, start, amount, riskfactor, channel_ok,	\
		 path_score, arg)					\
	dijkstra_((ctx), (map), (start), (amount), (riskfactor),	\
		  typesafe_cb_preargs(bool, void *, (channel_ok), (arg), \
				      const struct gossmap *,		\
				      const struct gossmap_chan *,	\
				      int, struct amount_msat),		\
		  (path_score),						\
		  (arg))

/* Returns UINT_MAX if unreachable. */
u32 dijkstra_distance(const struct dijkstra *dij, u32 node_idx);

/* Best path we found to here */
struct gossmap_chan *dijkstra_best_chan(const struct dijkstra *dij,
					u32 node_idx);

#endif /* LIGHTNING_COMMON_DIJKSTRA_H */
