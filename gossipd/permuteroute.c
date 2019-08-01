#include "permuteroute.h"
#include <common/status.h>
#include <common/type_to_string.h>
#include <gossipd/routing.h>

/*~ In theory, this could have been built as a plugin on top
 * of `getroute`.
 * However, the `max_hops` argument of `getroute` does not
 * limit the graph that the `getroute` algorithm traverses;
 * instead, it scans the entire graph, and if the resulting
 * route is longer than `max_hops` will ***re-scan*** the
 * entire graph with a tweaked cost function until it finds
 * a route that fits.
 *
 * As the speed of `permuteroute` is due solely to restricting
 * the graph we scan, we just use a depth-first iterative
 * algorithm until we reach any node after the point at which
 * the payment fails.
 *
 * Arguably a Djikstra with limited hops would be better, but
 * simplicity wins for this case as we can avoid heap
 * allocations and keep data in hot stack memory.
 */

/*~ Glossary:
 *
 * Pivot node - the node which signalled the routing failure
 * for a channel-level failure, and from which we start the
 * search to heal the route.
 *
 * Return node - the node to which we found a route from the
 * pivot.
 *
 * Prefix - the part of the path from the payer to the pivot.
 *
 * Postfix - the part of the path from the return node to the
 * payee.
 */

/*~ Possibly stores the results of a successful healing of the
 * original route.
 *
 * This is intended to be stack-allocated instead of tal-allocated.
 *
 * Our model is that the current route is broken at permute_after,
 * i.e. the channel indexed by permute_after in current_route has
 * failed, and the node indexed by permute_after was not reached
 * (but every node before permute_after was reached).
 * Our "pivot" is the node just before the failing channel.
 * Our "return" is the node at or after the failing channel where
 * we go back to the original route to the destination.
 */
struct permute_route_results {
	/* The routing state.  */
	struct routing_state *rstate;

	/* The current (failing) route.  */
	const struct route_hop *current_route;

	/* The index of current_route, whose channel is
	 * failing (the node before this index is the
	 * pivot).  */
	int permute_after;

	/* The amount we target to pass through.  */
	struct amount_msat amount;

	/* The route that heals from the pivot to the
	 * return node.  */
	int subroute_len;
	struct chan *subroute[PERMUTE_ROUTE_DISTANCE];

	/* The node after the broken channel where we
	 * return to the original route.  */
	struct node *return_node;
	/* The index of the current_route where we
	 * returned.
	 * permute_after <= return_index < tal_count(current_route)
	 */
	int return_index;
};
/* Initialize the results.  */
static inline void
permute_route_results_init(struct permute_route_results *results,
			   struct routing_state *rstate,
			   const struct route_hop *current_route,
			   int permute_after,
			   struct amount_msat amount)
{
	results->rstate = rstate;
	results->current_route = current_route;
	results->permute_after = permute_after;
	results->amount = amount;
	results->subroute_len = 0;
	results->return_node = NULL;
	results->return_index = -1;
}

/*~ Represents the currently-scanning set.
 *
 * This is a singly-linked list, allocated off the stack, with
 * recursive calls allowing multiple instances of the structure.
 *
 * This will contain enough information to recover a route
 * if we have reached a goal node.
 */
struct permute_route_scan {
	const struct permute_route_scan *prev;
	unsigned int depth;
	struct node *node;
	struct chan *next;
};
/* Determine if the given node is already in the currently-scanning
 * set.
 */
static inline bool
permute_route_scanning_duplicate(const struct permute_route_scan *scan,
				 struct node *n)
{
	for (; scan; scan = scan->prev)
		if (scan->node == n)
			return true;
	return false;
}

/* Determine if we have reached any of the goals.  */
static bool
permute_route_reached_goal(struct permute_route_results *results,
			   const struct permute_route_scan *scan,
			   struct node *n)
{
	/* No subroute yet.  */
	if (!scan)
		return false;

	for (int i = results->permute_after;
	     i < tal_count(results->current_route);
	     ++i) {
		if (node_id_eq(&results->current_route[i].nodeid, &n->id)) {
			/* Found!  */
			status_info("permute_route: Return to node %s "
				    "at %d of original path, "
				    "%u hops from pivot.",
				    type_to_string(tmpctx, struct node_id,
						   &n->id),
				    i, scan->depth);

			/* Update results.  */
			results->return_node = n;
			results->return_index = i;
			results->subroute_len = scan->depth;
			for (int i = scan->depth - 1; i >= 0; --i) {
				assert(scan);
				results->subroute[i] = scan->next;
				scan = scan->prev;
			}
			assert(!scan);

			return true;
		}
	}

	return false;
}

/* Recursive depth-first search.
 *
 * Most C ABIs indicate the first few arguments as passed
 * over registers.
 * Thus recursive functions should keep data common
 * throughout the recursion in the first few arguments.
 */
static bool
permute_route_search(struct permute_route_results *results,
		     const struct permute_route_scan *scan,
		     struct node *node)
{
	assert(results);
	assert(node);

	/* If we reached a node we already reached before, give up.  */
	if (permute_route_scanning_duplicate(scan, node))
		return false;
	/* If we reached a goal node, succeed now.  */
	if (permute_route_reached_goal(results, scan, node))
		return true;
	/* If depth is reached, give up now.  */
	if (scan && scan->depth == PERMUTE_ROUTE_DISTANCE)
		return false;

	/* Allocate our own scan structure and iterate over our
	 * channels.
	 */
	{
		struct permute_route_scan myscan;
		struct chan_map_iter it;
		struct chan *c;

		struct routing_state *rstate = results->rstate;
		struct amount_msat amount = results->amount;

		/* Make a scan node.  */
		myscan.prev = scan;
		myscan.depth = scan ? (scan->depth + 1) : 1;
		myscan.node = node;

		/* Go through our channels.  */
		for (c = first_chan(node, &it);
		     c;
		     c = next_chan(node, &it)) {
			int idx = (c->nodes[1] == node);
			struct half_chan *hc = half_chan_from(node, c);

			bool found;

			/* If not enabled, skip.  */
			if (!hc_is_routable(rstate, c, idx))
				continue;
			/* If no capacity, skip.
			 * (Excluded channels have 0 htlc_maximum).
			 */
			if (!hc_can_carry(hc, amount))
				continue;

			/* Recurse.  */
			myscan.next = c;
			found = permute_route_search(results, &myscan,
						     other_node(node, c));
			if (found)
				return true;
		}
	}

	/* Reached here?  Give up.  */
	return false;
}

static struct route_hop *
permute_and_build_route(const tal_t *ctx,
			struct routing_state *rstate,
			const struct route_hop *current_route,
			u32 permute_after,
			struct node *pivot,
			struct node *source,
			struct chan **prefix,
			u32 max_hops)
{
	struct permute_route_results results;
	bool found;

	struct chan **new_prefix;
	int prefix_len;

	struct node *n;

	int return_index;
	char *err;
	struct route_hop *new_route;

	int postfix_index;
	int prefound_len;
	int postfix_len;
	int new_route_len;

	permute_route_results_init(&results,
				   rstate,
				   current_route,
				   permute_after,
				   /* Use this as a proxy for how much
				    * to deliver across the healed
				    * route.
				    */
				   current_route[0].amount);

	found = permute_route_search(&results, NULL, pivot);
	if (!found)
		return NULL;

	assert(0 < results.subroute_len);
	assert(results.subroute_len <= PERMUTE_ROUTE_DISTANCE);

	/* Extend the prefix with the subroute found.  */
	prefix_len = tal_count(prefix);
	new_prefix = prefix;
	tal_resize(&new_prefix, prefix_len + results.subroute_len);
	/* Fill in the new extension.  */
	for (int i = 0; i < results.subroute_len; ++i)
		new_prefix[prefix_len + i] = results.subroute[i];

	/* Smoothen the prefix.  */
	smoothen_route(source, &new_prefix, &n);
	assert(n == results.return_node);

	/* Construct the prefix as route_hop structures.
	 *
	 * We deliver the same amount and delay to the
	 * return node as on the current route, letting
	 * us just copy the current route *after* the
	 * return node seamlessly.
	 *
	 * Might return an error.
	 */
	return_index = results.return_index;
	err = generate_route_hops(ctx,
				  &new_route, &n,
				  new_prefix, results.return_node,
				  current_route[return_index].amount,
				  current_route[return_index].delay);
	if (err) {
		status_unusual("permute_route: generate_route_hops: %s", err);
		return NULL;
	}
	assert(n == source);
	status_info("permute_route: Generated %d-hop route "
		    "to return node %s "
		    "giving %s (%"PRIu32" delay)",
		    (int) tal_count(new_route),
		    type_to_string(tmpctx, struct node_id,
				   &results.return_node->id),
		    type_to_string(tmpctx, struct amount_msat,
				   &current_route[return_index].amount),
		    current_route[return_index].delay);

	/* Compute final size of route.  */
	postfix_index = return_index + 1;
	prefound_len = tal_count(new_route);
	postfix_len = tal_count(current_route) - postfix_index;
	new_route_len = prefound_len + postfix_len;
	if (new_route_len > max_hops) {
		status_info("permute_route: Route length %d > max_hops %"PRIu32"",
			    new_route_len, max_hops);
		return tal_free(new_route);
	}

	/* Fill in the postfix.  */
	tal_resize(&new_route, new_route_len);
	for (int i = 0; i < postfix_len; ++i)
		new_route[prefound_len + i] = current_route[postfix_index + i];

	status_info("permute_route: Generated %d-hop route.",
		    (int)tal_count(new_route));

	return new_route;
}

struct route_hop *permute_route(const tal_t *ctx,
				struct routing_state *rstate,
				const struct route_hop *current_route,
				u32 permute_after,
				const struct node_id *source_id,
				const struct short_channel_id_dir *excluded TAKES,
				u32 max_hops)
{
	struct route_hop *new_route;

	struct node *source;
	const struct node_id *pivot_id;
	struct node *pivot;
	struct chan **prefix;

	struct exclusion_memento *exclusion_mem;

	/* No input?  No output.  */
	if (!current_route || tal_count(current_route) == 0) {
		status_unusual("permute_route: empty input route");
		return NULL;
	}

	/* Locate source.  */
	if (!source_id)
		source = get_node(rstate, &rstate->local_id);
	else
		source = get_node(rstate, source_id);
	if (!source) {
		status_info("permute_route: cannot find %s",
			    type_to_string(tmpctx, struct node_id,
					   source_id ? source_id : &rstate->local_id));
		return NULL;
	}

	/*~ The pivot is the specific node from which we start
	 * our search.
	 *
	 * permute_after indicates how many successful channel
	 * hops occurred.
	 * Thus if it is 0, we should pivot around the source,
	 * else we should pivot around permute_after - 1 in
	 * the route.
	 *
	 * We cannot permute_after at route length, as that
	 * implies that the entire route succeeded and there
	 * would be no reason to permute the route.
	 */
	if (permute_after == 0)
		pivot = source;
	else if (permute_after < tal_count(current_route)) {
		pivot_id = &current_route[permute_after - 1].nodeid;

		/* If pivot not found, fail.  */
		pivot = get_node(rstate, pivot_id);
		if (!pivot) {
			status_info("permute_route: cannot find pivot %s",
				    type_to_string(tmpctx, struct node_id,
						   pivot_id));
			return NULL;
		}
	} else {
		status_unusual("permute_route: permute_after %d >= "
			       "input route length %d?",
			       (int) permute_after,
			       (int) tal_count(current_route));
		return NULL;
	}

	/*~ The prefix is the part of the route from source to
	 * pivot node.
	 *
	 * The exact sequence of channels in the prefix will
	 * be the same as in the current route, but the amount
	 * passing through them will change, thus we only
	 * retain the channels into the prefix array.
	 *
	 * We need to re-verify the channels on the prefix
	 * are still existing in our map, as we need to
	 * recompute the fees.
	 */
	prefix = tal_arr(tmpctx, struct chan *, permute_after);
	for (int i = 0; i < permute_after; ++i) {
		const struct short_channel_id *cid;
		struct chan *c;
		int dir;

		cid = &current_route[i].channel_id;
		c = get_channel(rstate, cid);

		dir = current_route[i].direction;

		if (!c || !hc_is_routable(rstate, c, dir)) {
			status_unusual("permute_route: not routable %s/%u",
				       type_to_string(tmpctx,
						      struct short_channel_id,
						      cid),
				       dir);
			tal_free(prefix);
			return NULL;
		}

		prefix[i] = c;
	}

	/* Exclude, then actually permute route.  */
	exclusion_mem = exclude_channels(rstate, excluded);
	new_route = permute_and_build_route(ctx, rstate,
					    current_route, permute_after,
					    pivot, source, prefix,
					    max_hops);
	restore_excluded_channels(exclusion_mem);

	return new_route;
}
