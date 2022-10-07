/* Priority queue on top of gheap. */

/******************************************************************************
 * Interface.
 *****************************************************************************/

#include "gheap.h"

#include <stddef.h>    /* for size_t */


/*
 * Deletes the given item.
 */
typedef void (*gpriority_queue_item_deleter_t)(void *);

/*
 * Opaque type for priority queue.
 */
struct gpriority_queue;

/*
 * Creates an empty priority queue.
 *
 * The gheap context pointed by ctx must remain valid until
 * gpriority_queue_delete() call.
 */
static inline struct gpriority_queue *gpriority_queue_create(
    const struct gheap_ctx *ctx, gpriority_queue_item_deleter_t item_deleter);

/*
 * Creates a pirority queue and copies items from the given array into
 * the priority queue.
 */
static inline struct gpriority_queue *gpriority_queue_create_from_array(
    const struct gheap_ctx *ctx, gpriority_queue_item_deleter_t item_deleter,
    const void *a, size_t n);

/*
 * Deletes the given priority queue.
 */
static inline void gpriority_queue_delete(struct gpriority_queue *q);

/*
 * Returns non-zero if the given priority queue is empty.
 * Otherwise returns zero.
 */
static inline int gpriority_queue_empty(struct gpriority_queue *q);

/*
 * Returns the size of the given priority queue.
 */
static inline size_t gpriority_queue_size(struct gpriority_queue *q);

/*
 * Returns a pointer to the top element in the priority queue.
 */
static inline const void *gpriority_queue_top(struct gpriority_queue *q);

/*
 * Pushes a copy of the given item into priority queue.
 */
static inline void gpriority_queue_push(struct gpriority_queue *q,
    const void *item);

/*
 * Pops the top element from the priority queue.
 */
static inline void gpriority_queue_pop(struct gpriority_queue *q);


/******************************************************************************
 * Implementation.
 *****************************************************************************/

#include <stdint.h>   /* for SIZE_MAX */
#include <stdio.h>    /* for fprintf() */
#include <stdlib.h>   /* for malloc(), free() */

struct gpriority_queue
{
  const struct gheap_ctx *ctx;
  gpriority_queue_item_deleter_t item_deleter;

  void *base;
  size_t size;
  size_t capacity;
};

static inline struct gpriority_queue *gpriority_queue_create(
    const struct gheap_ctx *const ctx,
    const gpriority_queue_item_deleter_t item_deleter)
{
  struct gpriority_queue *q = malloc(sizeof(*q));

  q->ctx = ctx;
  q->item_deleter = item_deleter;

  q->base = malloc(ctx->item_size);
  q->size = 0;
  q->capacity = 1;

  return q;
}

static inline struct gpriority_queue *gpriority_queue_create_from_array(
    const struct gheap_ctx *const ctx,
    const gpriority_queue_item_deleter_t item_deleter,
    const void *const a, size_t n)
{
  struct gpriority_queue *q = malloc(sizeof(*q));

  q->ctx = ctx;
  q->item_deleter = item_deleter;

  assert(n <= SIZE_MAX / ctx->item_size);
  q->base = malloc(n * ctx->item_size);
  q->size = n;
  q->capacity = n;

  for (size_t i = 0; i < n; ++i) {
    const void *const src = ((char *)a) + i * ctx->item_size;
    void *const dst = ((char *)q->base) + i * ctx->item_size;
    ctx->item_mover(dst, src);
  }
  gheap_make_heap(ctx, q->base, q->size);

  return q;
}

static inline void gpriority_queue_delete(struct gpriority_queue *const q)
{
  for (size_t i = 0; i < q->size; ++i) {
    void *const item = ((char *)q->base) + i * q->ctx->item_size;
    q->item_deleter(item);
  }
  free(q->base);
  free(q);
}

static inline int gpriority_queue_empty(struct gpriority_queue *const q)
{
  return (q->size == 0);
}

static inline size_t gpriority_queue_size(struct gpriority_queue *const q)
{
  return q->size;
}

static inline const void *gpriority_queue_top(struct gpriority_queue *const q)
{
  assert(q->size > 0);

  return q->base;
}

static inline void gpriority_queue_push(struct gpriority_queue *const q,
    const void *item)
{
  if (q->size == q->capacity) {
    if (q->capacity > SIZE_MAX / 2 / q->ctx->item_size) {
      fprintf(stderr, "priority queue size overflow");
      exit(EXIT_FAILURE);
    }
    q->capacity *= 2;
    char *const new_base = malloc(q->capacity * q->ctx->item_size);
    for (size_t i = 0; i < q->size; ++i) {
      void *const dst = new_base + i * q->ctx->item_size;
      const void *const src = ((char *)q->base) + i * q->ctx->item_size;
      q->ctx->item_mover(dst, src);
    }
    free(q->base);
    q->base = new_base;
  }

  assert(q->size < q->capacity);
  void *const dst = ((char *)q->base) + q->size * q->ctx->item_size;
  q->ctx->item_mover(dst, item);
  ++(q->size);
  gheap_push_heap(q->ctx, q->base, q->size);
}

static inline void gpriority_queue_pop(struct gpriority_queue *const q)
{
  assert(q->size > 0);

  gheap_pop_heap(q->ctx, q->base, q->size);
  --(q->size);
  void *const item = ((char *)q->base) + q->size * q->ctx->item_size;
  q->item_deleter(item);
}
