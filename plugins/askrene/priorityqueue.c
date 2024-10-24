#define NDEBUG 1
#include "config.h"
#include <plugins/askrene/priorityqueue.h>

/* priorityqueue: a data structure for pairs (key, value) with
 * 0<=key<max_num_elements, with easy access to elements by key and the pair
 * with the smallest value. */
struct priorityqueue {
	s64 *value;
	u32 *base;
	u32 **heapptr;
	size_t heapsize;
	struct gheap_ctx gheap_ctx;
};

static const s64 INFINITE = INT64_MAX;

/* Required a global priorityqueue for gheap. */
static struct priorityqueue *global_priorityqueue;

/* The heap comparer for priorityqueue search. Since the top element must be the
 * one with the smallest value, we use the operator >, rather than <. */
static int priorityqueue_less_comparer(const void *const ctx UNUSED,
				       const void *const a,
				       const void *const b) {
	return global_priorityqueue->value[*(u32 *)a] >
	       global_priorityqueue->value[*(u32 *)b];
}

/* The heap move operator for priorityqueue search. */
static void priorityqueue_item_mover(void *const dst, const void *const src) {
	u32 src_idx = *(u32 *)src;
	*(u32 *)dst = src_idx;

	/* we keep track of the pointer position of each element in the heap,
	 * for easy update. */
	global_priorityqueue->heapptr[src_idx] = dst;
}

/* Allocation of resources for the heap. */
struct priorityqueue *priorityqueue_new(const tal_t *ctx,
					size_t max_num_nodes) {
	struct priorityqueue *q = tal(ctx, struct priorityqueue);
	/* check allocation */
	if (!q) return NULL;

	q->value = tal_arr(q, s64, max_num_nodes);
	q->base = tal_arr(q, u32, max_num_nodes);
	q->heapptr = tal_arrz(q, u32 *, max_num_nodes);

	/* check allocation */
	if (!q->value || !q->base || !q->heapptr) return tal_free(q);

	q->heapsize = 0;
	q->gheap_ctx.fanout = 2;
	q->gheap_ctx.page_chunks = 1024;
	q->gheap_ctx.item_size = sizeof(q->base[0]);
	q->gheap_ctx.less_comparer = priorityqueue_less_comparer;
	q->gheap_ctx.less_comparer_ctx = NULL;
	q->gheap_ctx.item_mover = priorityqueue_item_mover;
	return q;
}

void priorityqueue_init(struct priorityqueue *q) {
	const size_t max_num_nodes = tal_count(q->value);
	q->heapsize = 0;
	for (size_t i = 0; i < max_num_nodes; ++i) {
		q->value[i] = INFINITE;
		q->heapptr[i] = NULL;
	}
}
size_t priorityqueue_size(const struct priorityqueue *q) { return q->heapsize; }

size_t priorityqueue_maxsize(const struct priorityqueue *q) {
	return tal_count(q->value);
}

static void priorityqueue_append(struct priorityqueue *q, u32 key, s64 value) {
	assert(priorityqueue_size(q) < priorityqueue_maxsize(q));
	assert(key < priorityqueue_maxsize(q));

	const size_t pos = q->heapsize;

	q->base[pos] = key;
	q->value[key] = value;
	q->heapptr[key] = &(q->base[pos]);
	q->heapsize++;
}

void priorityqueue_update(struct priorityqueue *q, u32 key, s64 value) {
	assert(key < priorityqueue_maxsize(q));

	if (!q->heapptr[key]) {
		/* not in the heap */
		priorityqueue_append(q, key, value);
		global_priorityqueue = q;
		gheap_restore_heap_after_item_increase(
		    &q->gheap_ctx, q->base, q->heapsize,
		    q->heapptr[key] - q->base);
		global_priorityqueue = NULL;
		return;
	}

	if (q->value[key] > value) {
		/* value decrease */
		q->value[key] = value;

		global_priorityqueue = q;
		gheap_restore_heap_after_item_increase(
		    &q->gheap_ctx, q->base, q->heapsize,
		    q->heapptr[key] - q->base);
		global_priorityqueue = NULL;
	} else {
		/* value increase */
		q->value[key] = value;

		global_priorityqueue = q;
		gheap_restore_heap_after_item_decrease(
		    &q->gheap_ctx, q->base, q->heapsize,
		    q->heapptr[key] - q->base);
		global_priorityqueue = NULL;
	}
	/* assert(gheap_is_heap(&q->gheap_ctx,
	 *                      q->base,
	 * 		        priorityqueue_size())); */
}

u32 priorityqueue_top(const struct priorityqueue *q) {
	assert(!priorityqueue_empty(q));
	return q->base[0];
}

bool priorityqueue_empty(const struct priorityqueue *q) {
	return q->heapsize == 0;
}

void priorityqueue_pop(struct priorityqueue *q) {
	if (q->heapsize == 0) return;

	const u32 top = priorityqueue_top(q);
	assert(q->heapptr[top] == q->base);

	global_priorityqueue = q;
	gheap_pop_heap(&q->gheap_ctx, q->base, q->heapsize--);
	global_priorityqueue = NULL;
	q->heapptr[top] = NULL;
}

const s64 *priorityqueue_value(const struct priorityqueue *q) {
	return q->value;
}
