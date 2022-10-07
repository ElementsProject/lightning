#ifndef GHEAP_H
#define GHEAP_H

/*
 * Generalized heap implementation for C99.
 *
 * Don't forget passing -DNDEBUG option to the compiler when creating optimized
 * builds. This significantly speeds up gheap code by removing debug assertions.
 *
 * Author: Aliaksandr Valialkin <valyala@gmail.com>.
 */


/*******************************************************************************
 * Interface.
 ******************************************************************************/

#include <stddef.h>     /* for size_t */
#include <stdint.h>     /* for SIZE_MAX */

/*
 * Less comparer must return non-zero value if a < b.
 * ctx is the gheap_ctx->less_comparer_ctx.
 * Otherwise it must return 0.
 */
typedef int (*gheap_less_comparer_t)(const void *ctx, const void *a,
    const void *b);

/*
 * Moves the item from src to dst.
 */
typedef void (*gheap_item_mover_t)(void *dst, const void *src);

/*
 * Gheap context.
 * This context must be passed to every gheap function.
 */
struct gheap_ctx
{
  /*
   * How much children each heap item can have.
   */
  size_t fanout;

  /*
   * A chunk is a tuple containing fanout items arranged sequentially in memory.
   * A page is a subheap containing page_chunks chunks arranged sequentially
   * in memory.
   * The number of chunks in a page is an arbitrary integer greater than 0.
   */
  size_t page_chunks;

  /*
   * The size of each item in bytes.
   */
  size_t item_size;

  gheap_less_comparer_t less_comparer;
  const void *less_comparer_ctx;

  gheap_item_mover_t item_mover;
};

/*
 * Returns parent index for the given child index.
 * Child index must be greater than 0.
 * Returns 0 if the parent is root.
 */
static inline size_t gheap_get_parent_index(const struct gheap_ctx *ctx,
    size_t u);

/*
 * Returns the index of the first child for the given parent index.
 * Parent index must be less than SIZE_MAX.
 * Returns SIZE_MAX if the index of the first child for the given parent
 * cannot fit size_t.
 */
static inline size_t gheap_get_child_index(const struct gheap_ctx *ctx,
    size_t u);

/*
 * Returns a pointer to the first non-heap item using less_comparer
 * for items' comparison.
 * Returns the index of the first non-heap item.
 * Returns heap_size if base points to valid max heap with the given size.
 */
static inline size_t gheap_is_heap_until(const struct gheap_ctx *ctx,
    const void *base, size_t heap_size);

/*
 * Returns non-zero if base points to valid max heap. Returns zero otherwise.
 * Uses less_comparer for items' comparison.
 */
static inline int gheap_is_heap(const struct gheap_ctx *ctx,
    const void *base, size_t heap_size);

/*
 * Makes max heap from items base[0] ... base[heap_size-1].
 * Uses less_comparer for items' comparison.
 */
static inline void gheap_make_heap(const struct gheap_ctx *ctx,
    void *base, size_t heap_size);

/*
 * Pushes the item base[heap_size-1] into max heap base[0] ... base[heap_size-2]
 * Uses less_comparer for items' comparison.
 */
static inline void gheap_push_heap(const struct gheap_ctx *ctx,
    void *base, size_t heap_size);

/*
 * Pops the maximum item from max heap base[0] ... base[heap_size-1] into
 * base[heap_size-1].
 * Uses less_comparer for items' comparison.
 */
static inline void gheap_pop_heap(const struct gheap_ctx *ctx,
    void *base, size_t heap_size);

/*
 * Sorts items in place of max heap in ascending order.
 * Uses less_comparer for items' comparison.
 */
static inline void gheap_sort_heap(const struct gheap_ctx *ctx,
    void *base, size_t heap_size);

/*
 * Swaps the item outside the heap with the maximum item inside
 * the heap and restores heap invariant.
 */
static inline void gheap_swap_max_item(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size, void *item);

/*
 * Restores max heap invariant after item's value has been increased,
 * i.e. less_comparer(old_item, new_item) != 0.
 */
static inline void gheap_restore_heap_after_item_increase(
    const struct gheap_ctx *ctx,
    void *base, size_t heap_size, size_t modified_item_index);

/*
 * Restores max heap invariant after item's value has been decreased,
 * i.e. less_comparer(new_item, old_item) != 0.
 */
static inline void gheap_restore_heap_after_item_decrease(
    const struct gheap_ctx *ctx,
    void *base, size_t heap_size, size_t modified_item_index);

/*
 * Removes the given item from the heap and puts it into base[heap_size-1].
 * Uses less_comparer for items' comparison.
 */
static inline void gheap_remove_from_heap(const struct gheap_ctx *ctx,
    void *base, size_t heap_size, size_t item_index);

/*******************************************************************************
 * Implementation.
 *
 * Define all functions inline, so compiler will be able optimizing out common
 * args (fanout, page_chunks, item_size, less_comparer and item_mover),
 * which are usually constants, using contant folding optimization
 * ( http://en.wikipedia.org/wiki/Constant_folding ).
 *****************************************************************************/

#include <assert.h>     /* for assert */
#include <stddef.h>     /* for size_t */
#include <stdint.h>     /* for uintptr_t, SIZE_MAX and UINTPTR_MAX */

static inline size_t gheap_get_parent_index(const struct gheap_ctx *const ctx,
    size_t u)
{
  assert(u > 0);

  const size_t fanout = ctx->fanout;
  const size_t page_chunks = ctx->page_chunks;

  --u;
  if (page_chunks == 1) {
    return u / fanout;
  }

  if (u < fanout) {
    /* Parent is root. */
    return 0;
  }

  assert(page_chunks <= SIZE_MAX / fanout);
  const size_t page_size = fanout * page_chunks;
  size_t v = u % page_size;
  if (v >= fanout) {
    /* Fast path. Parent is on the same page as the child. */
    return u - v + v / fanout;
  }

  /* Slow path. Parent is on another page. */
  v = u / page_size - 1;
  const size_t page_leaves = (fanout - 1) * page_chunks + 1;
  u = v / page_leaves + 1;
  return u * page_size + v % page_leaves - page_leaves + 1;
}

static inline size_t gheap_get_child_index(const struct gheap_ctx *const ctx,
    size_t u)
{
  assert(u < SIZE_MAX);

  const size_t fanout = ctx->fanout;
  const size_t page_chunks = ctx->page_chunks;

  if (page_chunks == 1) {
    if (u > (SIZE_MAX - 1) / fanout) {
      /* Child overflow. */
      return SIZE_MAX;
    }
    return u * fanout + 1;
  }

  if (u == 0) {
    /* Root's child is always 1. */
    return 1;
  }

  assert(page_chunks <= SIZE_MAX / fanout);
  const size_t page_size = fanout * page_chunks;
  --u;
  size_t v = u % page_size + 1;
  if (v < page_size / fanout) {
    /* Fast path. Child is on the same page as the parent. */
    v *= fanout - 1;
    if (u > SIZE_MAX - 2 - v) {
      /* Child overflow. */
      return SIZE_MAX;
    }
    return u + v + 2;
  }

  /* Slow path. Child is on another page. */
  const size_t page_leaves = (fanout - 1) * page_chunks + 1;
  v += (u / page_size + 1) * page_leaves - page_size;
  if (v > (SIZE_MAX - 1) / page_size) {
    /* Child overflow. */
    return SIZE_MAX;
  }
  return v * page_size + 1;
}

/* Returns a pointer to base[index]. */
static inline void *_gheap_get_item_ptr(const struct gheap_ctx *const ctx,
    const void *const base, const size_t index)
{
  const size_t item_size = ctx->item_size;

  assert(index <= SIZE_MAX / item_size);

  const size_t offset = item_size * index;
  assert((uintptr_t)base <= UINTPTR_MAX - offset);

  return ((char *)base) + offset;
}

/*
 * Sifts the item up in the given sub-heap with the given root_index
 * starting from the hole_index.
 */
static inline void _gheap_sift_up(const struct gheap_ctx *const ctx,
    void *const base, const size_t root_index, size_t hole_index,
    const void *const item)
{
  assert(hole_index >= root_index);

  const gheap_less_comparer_t less_comparer = ctx->less_comparer;
  const void *const less_comparer_ctx = ctx->less_comparer_ctx;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  while (hole_index > root_index) {
    const size_t parent_index = gheap_get_parent_index(ctx, hole_index);
    assert(parent_index >= root_index);
    const void *const parent = _gheap_get_item_ptr(ctx, base, parent_index);
    if (!less_comparer(less_comparer_ctx, parent, item)) {
      break;
    }
    item_mover(_gheap_get_item_ptr(ctx, base, hole_index),
        parent);
    hole_index = parent_index;
  }

  item_mover(_gheap_get_item_ptr(ctx, base, hole_index), item);
}

/*
 * Moves the max child into the given hole and returns index
 * of the new hole.
 */
static inline size_t _gheap_move_up_max_child(const struct gheap_ctx *const ctx,
    void *const base, const size_t children_count,
    const size_t hole_index, const size_t child_index)
{
  assert(children_count > 0);
  assert(children_count <= ctx->fanout);
  assert(child_index == gheap_get_child_index(ctx, hole_index));

  const gheap_less_comparer_t less_comparer = ctx->less_comparer;
  const void *const less_comparer_ctx = ctx->less_comparer_ctx;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  size_t max_child_index = child_index;
  for (size_t i = 1; i < children_count; ++i) {
    if (!less_comparer(less_comparer_ctx,
        _gheap_get_item_ptr(ctx, base, child_index + i),
        _gheap_get_item_ptr(ctx, base, max_child_index))) {
      max_child_index = child_index + i;
    }
  }
  item_mover(_gheap_get_item_ptr(ctx, base, hole_index),
      _gheap_get_item_ptr(ctx, base, max_child_index));
  return max_child_index;
}

/*
 * Sifts the given item down in the heap of the given size starting
 * from the hole_index.
 */
static inline void _gheap_sift_down(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size, size_t hole_index,
    const void *const item)
{
  assert(heap_size > 0);
  assert(hole_index < heap_size);

  const size_t fanout = ctx->fanout;

  const size_t root_index = hole_index;
  const size_t last_full_index = heap_size - (heap_size - 1) % fanout;
  while (1) {
    const size_t child_index = gheap_get_child_index(ctx, hole_index);
    if (child_index >= last_full_index) {
      if (child_index < heap_size) {
        assert(child_index == last_full_index);
        hole_index = _gheap_move_up_max_child(ctx, base,
            heap_size - child_index, hole_index, child_index);
      }
      break;
    }
    assert(heap_size - child_index >= fanout);
    hole_index = _gheap_move_up_max_child(ctx, base, fanout, hole_index,
        child_index);
  }
  _gheap_sift_up(ctx, base, root_index, hole_index, item);
}

/*
 * Pops the maximum item from the heap [base[0] ... base[heap_size-1]]
 * into base[heap_size].
 */
static inline void _gheap_pop_max_item(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size)
{
  void *const hole = _gheap_get_item_ptr(ctx, base, heap_size);
  gheap_swap_max_item(ctx, base, heap_size, hole);
}

static inline size_t gheap_is_heap_until(const struct gheap_ctx *const ctx,
    const void *const base, const size_t heap_size)
{
  const gheap_less_comparer_t less_comparer = ctx->less_comparer;
  const void *const less_comparer_ctx = ctx->less_comparer_ctx;

  for (size_t u = 1; u < heap_size; ++u) {
    const size_t v = gheap_get_parent_index(ctx, u);
    const void *const a = _gheap_get_item_ptr(ctx, base, v);
    const void *const b = _gheap_get_item_ptr(ctx, base, u);
    if (less_comparer(less_comparer_ctx, a, b)) {
      return u;
    }
  }
  return heap_size;
}

static inline int gheap_is_heap(const struct gheap_ctx *const ctx,
    const void *const base, const size_t heap_size)
{
  return (gheap_is_heap_until(ctx, base, heap_size) == heap_size);
}

static inline void gheap_make_heap(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size)
{
  const size_t fanout = ctx->fanout;
  const size_t page_chunks = ctx->page_chunks;
  const size_t item_size = ctx->item_size;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  if (heap_size > 1) {
    /* Skip leaf nodes without children. This is easy to do for non-paged heap,
     * i.e. when page_chunks = 1, but it is difficult for paged heaps.
     * So leaf nodes in paged heaps are visited anyway.
     */
    size_t i = (page_chunks == 1) ? ((heap_size - 2) / fanout) :
        (heap_size - 2);
    do {
      char tmp[item_size];
      item_mover(tmp, _gheap_get_item_ptr(ctx, base, i));
      _gheap_sift_down(ctx, base, heap_size, i, tmp);
    } while (i-- > 0);
  }

  assert(gheap_is_heap(ctx, base, heap_size));
}

static inline void gheap_push_heap(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size)
{
  assert(heap_size > 0);
  assert(gheap_is_heap(ctx, base, heap_size - 1));

  const size_t item_size = ctx->item_size;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  if (heap_size > 1) {
    const size_t u = heap_size - 1;
    char tmp[item_size];
    item_mover(tmp, _gheap_get_item_ptr(ctx, base, u));
    _gheap_sift_up(ctx, base, 0, u, tmp);
  }

  assert(gheap_is_heap(ctx, base, heap_size));
}

static inline void gheap_pop_heap(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size)
{
  assert(heap_size > 0);
  assert(gheap_is_heap(ctx, base, heap_size));

  if (heap_size > 1) {
    _gheap_pop_max_item(ctx, base, heap_size - 1);
  }

  assert(gheap_is_heap(ctx, base, heap_size - 1));
}

static inline void gheap_sort_heap(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size)
{
  for (size_t i = heap_size; i > 1; --i) {
    _gheap_pop_max_item(ctx, base, i - 1);
  }
}

static inline void gheap_swap_max_item(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size, void *item)
{
  assert(heap_size > 0);
  assert(gheap_is_heap(ctx, base, heap_size));

  const size_t item_size = ctx->item_size;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  char tmp[item_size];
  item_mover(tmp, item);
  item_mover(item, base);
  _gheap_sift_down(ctx, base, heap_size, 0, tmp);

  assert(gheap_is_heap(ctx, base, heap_size));
}

static inline void gheap_restore_heap_after_item_increase(
    const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size, size_t modified_item_index)
{
  assert(heap_size > 0);
  assert(modified_item_index < heap_size);
  assert(gheap_is_heap(ctx, base, modified_item_index));

  const size_t item_size = ctx->item_size;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  if (modified_item_index > 0) {
    char tmp[item_size];
    item_mover(tmp, _gheap_get_item_ptr(ctx, base, modified_item_index));
    _gheap_sift_up(ctx, base, 0, modified_item_index, tmp);
  }

  assert(gheap_is_heap(ctx, base, heap_size));
  (void)heap_size;
}

static inline void gheap_restore_heap_after_item_decrease(
    const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size, size_t modified_item_index)
{
  assert(heap_size > 0);
  assert(modified_item_index < heap_size);
  assert(gheap_is_heap(ctx, base, modified_item_index));

  const size_t item_size = ctx->item_size;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  char tmp[item_size];
  item_mover(tmp, _gheap_get_item_ptr(ctx, base, modified_item_index));
  _gheap_sift_down(ctx, base, heap_size, modified_item_index, tmp);

  assert(gheap_is_heap(ctx, base, heap_size));
}

static inline void gheap_remove_from_heap(const struct gheap_ctx *const ctx,
    void *const base, const size_t heap_size, size_t item_index)
{
  assert(heap_size > 0);
  assert(item_index < heap_size);
  assert(gheap_is_heap(ctx, base, heap_size));

  const size_t item_size = ctx->item_size;
  const gheap_less_comparer_t less_comparer = ctx->less_comparer;
  const void *const less_comparer_ctx = ctx->less_comparer_ctx;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  const size_t new_heap_size = heap_size - 1;
  if (item_index < new_heap_size) {
    char tmp[item_size];
    void *const hole = _gheap_get_item_ptr(ctx, base, new_heap_size);
    item_mover(tmp, hole);
    item_mover(hole, _gheap_get_item_ptr(ctx, base, item_index));
    if (less_comparer(less_comparer_ctx, tmp, hole)) {
      _gheap_sift_down(ctx, base, new_heap_size, item_index, tmp);
    }
    else {
      _gheap_sift_up(ctx, base, 0, item_index, tmp);
    }
  }

  assert(gheap_is_heap(ctx, base, new_heap_size));
}

#endif
