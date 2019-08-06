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

/* Determine if we have reached any of the goals.  */
static bool
permute_route_reached_goal(struct permute_route_results *results,
			   struct node *n)
{
	if (n->s.permuteroute.depth == 0)
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
				    i, (int) n->s.permuteroute.depth);

			/* Update results.  */
			results->return_node = n;
			results->return_index = i;
			results->subroute_len = n->s.permuteroute.depth;
			for (int i = results->subroute_len - 1;
			     i >= 0;
			     --i) {
				struct chan *c;
				assert(n->s.permuteroute.visited);
				c = n->s.permuteroute.prev_chan;
				results->subroute[i] = c;
				n = other_node(n, c);
			}
			assert(n->s.permuteroute.depth == 0);

			return true;
		}
	}

	return false;
}

/* Clears the s.permuteroute scratch space. */
static void
permute_clear_scratch(struct routing_state *rstate)
{
	struct node *n;
	struct node_map_iter it;
	for (n = node_map_first(rstate->nodes, &it);
	     n;
	     n = node_map_next(rstate->nodes, &it))
		n->s.permuteroute.visited = false;
}

#define PERMUTEROUTE_QUEUE_SIZE 128
struct permuteroute_queue {
	struct node *queue[PERMUTEROUTE_QUEUE_SIZE];
	int head;
	int tail;
};
static inline void
permuteroute_queue_init(struct permuteroute_queue *queue)
{
	queue->head = 0;
	queue->tail = 0;
}
static inline bool
permuteroute_queue_is_empty(const struct permuteroute_queue *queue)
{
	return queue->head == queue->tail;
}
static inline bool
permuteroute_queue_is_full(const struct permuteroute_queue *queue)
{
	return queue->head == ((queue->tail + PERMUTEROUTE_QUEUE_SIZE) % (2 * PERMUTEROUTE_QUEUE_SIZE));
}
static inline void
permuteroute_queue_push(struct permuteroute_queue *queue,
			struct node *node)
{
	assert(!permuteroute_queue_is_full(queue));
	queue->queue[queue->head % PERMUTEROUTE_QUEUE_SIZE] = node;
	queue->head = (queue->head + 1) % (2 * PERMUTEROUTE_QUEUE_SIZE);
}
static inline struct node *
permuteroute_queue_pop(struct permuteroute_queue *queue)
{
	struct node *node;
	assert(!permuteroute_queue_is_empty(queue));
	node = queue->queue[queue->tail % PERMUTEROUTE_QUEUE_SIZE];
	queue->tail = (queue->tail + 1) % (2 * PERMUTEROUTE_QUEUE_SIZE);
	return node;
}

/* Breadth-first search.  */
static bool
permute_route_search(struct permute_route_results *results,
		     struct node *pivot)
{
	struct permuteroute_queue queue;
	struct amount_msat amount = results->amount;
	struct routing_state *rstate = results->rstate;

	assert(results);
	assert(pivot);

	permute_clear_scratch(results->rstate);
	permuteroute_queue_init(&queue);

	/* Prime the queue.  */
	pivot->s.permuteroute.visited = true;
	pivot->s.permuteroute.depth = 0;
	pivot->s.permuteroute.prev_chan = NULL;
	permuteroute_queue_push(&queue, pivot);

	while (!permuteroute_queue_is_empty(&queue)) {
		struct node *node;
		struct chan_map_iter it;
		struct chan *c;
		u8 currdepth;

		node = permuteroute_queue_pop(&queue);
		assert(node);
		assert(node->s.permuteroute.visited);

		/* If already at max depth, do not scan further links.  */
		currdepth = node->s.permuteroute.depth;
		if (currdepth == PERMUTE_ROUTE_DISTANCE)
			continue;

		for (c = first_chan(node, &it);
		     c;
		     c = next_chan(node, &it)) {
			int idx = (c->nodes[1] == node);
			struct half_chan *hc = half_chan_from(node, c);
			struct node *other;

			/* If not enabled, skip.  */
			if (!hc_is_routable(rstate, c, idx))
				continue;
			/* If no capacity, skip.
			 * (Excluded channels have 0 htlc_maximum).
			 */
			if (!hc_can_carry(hc, amount))
				continue;

			/* If node is already visited, skip.  */
			other = other_node(node, c);
			if (other->s.permuteroute.visited)
				continue;

			/* Mark as visited.  */
			other->s.permuteroute.visited = true;
			other->s.permuteroute.depth = currdepth + 1;
			other->s.permuteroute.prev_chan = c;

			/* If goal node, finished!
			 * Need to do this after we have marked this
			 * other node as visited so that if we *are*
			 * at a goal node, we can build the path
			 * now.
			 */
			if (permute_route_reached_goal(results, other))
				return true;

			/* Push to queue.  */
			permuteroute_queue_push(&queue, other);

			/* If queue full, stop adding.  */
			if (permuteroute_queue_is_full(&queue))
				break;
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

	found = permute_route_search(&results, pivot);
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
