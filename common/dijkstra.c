/* Without this, gheap is *really* slow!  Comment out for debugging. */
#define NDEBUG
#include "config.h"
#include <ccan/cast/cast.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/overflows.h>
#include <gheap.h>

/* Each node has this side-info. */
struct dijkstra {
	/* Number of hops: destination == 0, unreachable == UINTMAX */
	u32 distance;
	/* Total amount from here to destination */
	struct amount_msat amount;
	/* I want to use an index here, except that gheap moves things onto
	 * a temporary on the stack and that makes things complex. */
	/* NULL means it's been visited already. */
	const struct gossmap_node **heapptr;

	/* How we decide "best", lower is better (this is the cost function output) */
	u64 score;

	/* We could re-evaluate to determine this, but keeps it simple */
	struct gossmap_chan *best_chan;
};

/* Because item_mover doesn't provide a ctx ptr, we need a global anyway. */
static struct dijkstra *global_dijkstra;
static const struct gossmap *global_map;

/* Returns UINT_MAX if unreachable. */
u32 dijkstra_distance(const struct dijkstra *dij, u32 node_idx)
{
	return dij[node_idx].distance;
}

struct gossmap_chan *dijkstra_best_chan(const struct dijkstra *dij,
					u32 node_idx)
{
	return dij[node_idx].best_chan;
}

static struct dijkstra *get_dijkstra(const struct dijkstra *dij,
				     const struct gossmap *map,
				     const struct gossmap_node *n)
{
	return cast_const(struct dijkstra *, dij) + gossmap_node_idx(map, n);
}

/* We want a minheap, not a maxheap, so this is backwards! */
static int less_comparer(const void *const ctx,
			 const void *const a,
			 const void *const b)
{
	return get_dijkstra(global_dijkstra, global_map,
			    *(struct gossmap_node **)a)->score
		> get_dijkstra(global_dijkstra, global_map,
			       *(struct gossmap_node **)b)->score;
}

static void item_mover(void *const dst, const void *const src)
{
	struct gossmap_node *n = *((struct gossmap_node **)src);
	get_dijkstra(global_dijkstra, global_map, n)->heapptr = dst;
	*((struct gossmap_node **)dst) = n;
}

static const struct gossmap_node **mkheap(const tal_t *ctx,
					  struct dijkstra *dij,
					  const struct gossmap *map,
					  const struct gossmap_node *start,
					  struct amount_msat sent)
{
	const struct gossmap_node *n, **heap;
	size_t i;

	heap = tal_arr(tmpctx, const struct gossmap_node *,
		       gossmap_num_nodes(map));
	for (i = 1, n = gossmap_first_node(map);
	     n;
	     n = gossmap_next_node(map, n), i++) {
		struct dijkstra *d = get_dijkstra(dij, map, n);
		if (n == start) {
			/* First entry in heap is start, distance 0 */
			heap[0] = start;
			d->heapptr = &heap[0];
			d->distance = 0;
			d->amount = sent;
			d->score = 0;
			i--;
		} else {
			heap[i] = n;
			d->heapptr = &heap[i];
			d->distance = UINT_MAX;
			d->amount = AMOUNT_MSAT(-1ULL);
			d->score = -1ULL;
		}
	}
	assert(i == tal_count(heap));
	return heap;
}

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

/* We price in risk as riskfactor percent per year. */
static struct amount_msat risk_price(struct amount_msat amount,
				     u32 riskfactor, u32 cltv_delay)
{
	struct amount_msat riskfee;

	if (!amount_msat_scale(&riskfee, amount,
			       riskfactor / 100.0 / BLOCKS_PER_YEAR
			       * cltv_delay))
		return AMOUNT_MSAT(-1ULL);
	return riskfee;
}

/* Do Dijkstra: start in this case is the dst node. */
const struct dijkstra *
dijkstra_(const tal_t *ctx,
	  const struct gossmap *map,
	  const struct gossmap_node *start,
	  struct amount_msat amount,
	  double riskfactor,
	  bool (*channel_ok)(const struct gossmap *map,
			     const struct gossmap_chan *c,
			     int dir,
			     struct amount_msat amount,
			     void *arg),
	  u64 (*channel_score)(struct amount_msat fee,
			       struct amount_msat risk,
			       struct amount_msat total,
			       int dir,
			       const struct gossmap_chan *c),
	  void *arg)
{
	struct dijkstra *dij;
	const struct gossmap_node **heap;
	size_t heapsize;
	struct gheap_ctx gheap_ctx;

	/* There doesn't seem to be much difference with fanout 2-4. */
	gheap_ctx.fanout = 2;
	/* There seems to be a slight decrease if we alter this value. */
	gheap_ctx.page_chunks = 1;
	gheap_ctx.item_size = sizeof(*heap);
	gheap_ctx.less_comparer = less_comparer;
	gheap_ctx.less_comparer_ctx = NULL;
	gheap_ctx.item_mover = item_mover;

	dij = tal_arr(ctx, struct dijkstra, gossmap_max_node_idx(map));

	/* Pay no attention to the man behind the curtain! */
	global_map = map;
	global_dijkstra = dij;

	/* Wikipedia's article on Dijkstra is excellent:
	 *    https://en.wikipedia.org/wiki/Dijkstra's_algorithm
	 * (License https://creativecommons.org/licenses/by-sa/3.0/)
	 *
	 * So I quote here:
	 *
	 * 1. Mark all nodes unvisited. Create a set of all the unvisited
	 * nodes called the unvisited set.
	 *
	 * 2. Assign to every node a tentative distance value: set it to zero
	 * for our initial node and to infinity for all other nodes. Set the
	 * initial node as current.[14]
	 */
	heap = mkheap(NULL, dij, map, start, amount);
	heapsize = tal_count(heap);

	/*
	 * 3. For the current node, consider all of its unvisited neighbouds
	 * and calculate their tentative distances through the current
	 * node. Compare the newly calculated tentative distance to the
	 * current assigned value and assign the smaller one. For example, if
	 * the current node A is marked with a distance of 6, and the edge
	 * connecting it with a neighbour B has length 2, then the distance to
	 * B through A will be 6 + 2 = 8. If B was previously marked with a
	 * distance greater than 8 then change it to 8. Otherwise, the current
	 * value will be kept.
	 *
	 * 4. When we are done considering all of the unvisited neighbouds of
	 * the current node, mark the current node as visited and remove it
	 * from the unvisited set. A visited node will never be checked again.
	 *
	 * 5. If the destination node has been marked visited (when planning a
	 * route between two specific nodes) or if the smallest tentative
	 * distance among the nodes in the unvisited set is infinity (when
	 * planning a complete travedsal; occuds when there is no connection
	 * between the initial node and remaining unvisited nodes), then
	 * stop. The algorithm has finished.
	 *
	 * 6.  Otherwise, select the unvisited node that is marked with the
	 * smallest tentative distance, set it as the new "current node", and
	 * go back to step 3.
	 */
	while (heapsize != 0) {
		struct dijkstra *cur_d;
		const struct gossmap_node *cur = heap[0];

		cur_d = get_dijkstra(dij, map, cur);
		assert(cur_d->heapptr == heap);

		/* Finished all reachable nodes */
		if (cur_d->distance == UINT_MAX)
			break;

		for (size_t i = 0; i < cur->num_chans; i++) {
			struct gossmap_node *neighbor;
			int which_half;
			struct gossmap_chan *c;
			struct dijkstra *d;
			struct amount_msat fee, risk;
			u64 score;

			c = gossmap_nth_chan(map, cur, i, &which_half);
			neighbor = gossmap_nth_node(map, c, !which_half);

			d = get_dijkstra(dij, map, neighbor);
			/* Ignore if already visited. */
			if (!d->heapptr)
				continue;

			/* We're going from neighbor to c, hence !which_half */
			if (!channel_ok(map, c, !which_half, cur_d->amount, arg))
				continue;

			if (!amount_msat_fee(&fee, cur_d->amount,
					     c->half[!which_half].base_fee,
					     c->half[!which_half].proportional_fee)) {
				/* Shouldn't happen! */
				continue;
			}

			/* cltv_delay can't overflow: only 20 bits per hop. */
			risk = risk_price(cur_d->amount, riskfactor, c->half[!which_half].delay);
			score = channel_score(fee, risk, cur_d->amount, !which_half, c);

			/* That score is on top of current score */
			if (add_overflows_u64(score, cur_d->score))
				continue;
			score += cur_d->score;

			if (score >= d->score)
				continue;

			/* Shouldn't happen! */
			if (!amount_msat_add(&d->amount, cur_d->amount, fee))
				continue;

			d->distance = cur_d->distance + 1;
			d->best_chan = c;
			d->score = score;
			gheap_restore_heap_after_item_increase(&gheap_ctx,
							       heap, heapsize,
							       d->heapptr - heap);
		}
		gheap_pop_heap(&gheap_ctx, heap, heapsize--);
		cur_d->heapptr = NULL;
	}
	tal_free(heap);
	return dij;
}
