#ifndef LIGHTNING_GOSSIPD_PERMUTEROUTE_H
#define LIGHTNING_GOSSIPD_PERMUTEROUTE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct node_id;
struct route_hop;
struct routing_state;
struct short_channel_id_dir;

/**
 * permute_route - Modify the given route, avoiding excluded channels,
 * and return a new route to the same destination.
 * This is used to quickly modify a failing route without having to
 * use the computationally-heavy getroute.
 *
 * permute_route scans an area around one node of up to 3 hops away
 * from that node.
 * This greatly reduces the time needed to generate a new route.
 *
 * @ctx - The tal context to allocate the new route from.
 * @rstate - The routing state to scan.
 * @current_route - The route to modify, a tal_arr.
 * @permute_after - Indicates that the first permute_after hops
 * succeeded.
 * The algorithm will search the area around the last node that
 * succeeded, trying to reconnect to any node in the remaining
 * part of the route.
 * From 0 (indicating it failed at the first hop at the source)
 * to tal_count(current_route) - 1.
 * @source - The source of the route.
 * @excluded - A tal_arr of channel-directions that will not be
 * considered.
 * @max_hops - If the resulting route would exceed this, fail anyway.
 */
struct route_hop *permute_route(const tal_t *ctx,
				struct routing_state *rstate,
				const struct route_hop *current_route,
				u32 permute_after,
				const struct node_id *source,
				const struct short_channel_id_dir *excluded,
				u32 max_hops);

/* The maximum number of hops to scan to heal the route.  */
#define PERMUTE_ROUTE_DISTANCE (3)

/*~
 * The permute_route algorithm was inspired by JIT-Routing of
 * Rene Pickhardt.
 *
 * In JIT-Routing, a node that would fail to transmit over a
 * channel due to capacity issue, may instead perform a
 * rebalance of its channels.
 *
 * Unlike failing and then forcing the source to recompute a
 * new route, JIT-Routing can quickly find a route by simply
 * restricting itself to searching the nearby channels and
 * nodes to find a circular route, specifically only up to
 * the friend-of-a-friend graph.
 *
 * JIT-Routing would effectively modify the route by sending
 * money over an alternate route, then healing to continue
 * the routing.
 *
 * permute_route basically "simulates" a JIT-Routing occurring
 * at the failure point, scanning only the local area around
 * the node reporting the error until it finds an alternate
 * sub-route that attaches to the remaining part of the route.
 * This takes advantage of the speed of the local scan used
 * by the JIT-Routing, by restricting ourselves to scanning
 * only up to 3 hops away until we find a point to attach
 * to, and finishing the scan as soon as we find this point.
 *
 * Assuming the original route was optimal in terms of fees
 * and lock time, then the resulting route is only a mild
 * degradation, since we would basically replace one failing
 * channel with up to 3 channels.
 * The intent is that, *only* if the resulting route is
 * too expensive, do we bother to use the more
 * computationally-heavy getroute.
 *
 * See also: https://theory.stanford.edu/~amitp/GameProgramming/MovingObstacles.html#path-splicing
 */

#endif /* LIGHTNING_GOSSIPD_PERMUTEROUTE_H */
