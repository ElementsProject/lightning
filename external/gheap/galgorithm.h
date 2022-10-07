#ifndef GALGORITHM_H
#define GALGORITHM_H

/*
 * Generalized aglogithms based on gheap for C99.
 *
 * Don't forget passing -DNDEBUG option to the compiler when creating optimized
 * builds. This significantly speeds up gheap code by removing debug assertions.
 *
 * Author: Aliaksandr Valialkin <valyala@gmail.com>.
 */


/*******************************************************************************
 * Interface.
 ******************************************************************************/

#include "gheap.h"      /* for gheap_ctx */

#include <stddef.h>     /* for size_t */

/*
 * Sorts [base[0] ... base[n-1]] in ascending order via heapsort.
 */
static inline void galgorithm_heapsort(const struct gheap_ctx *const ctx,
    void *const base, const size_t n);

/*
 * Performs partial sort, so [base[0] ... base[middle_index-1]) will contain
 * items sorted in ascending order, which are smaller than the rest of items
 * in the [base[middle_index] ... base[n-1]).
 */
static inline void galgorithm_partial_sort(const struct gheap_ctx *ctx,
    void *base, size_t n, size_t middle_index);

/*
 * Vtable for input iterators, which is passed to galgorithm_nway_merge().
 */
struct galgorithm_nway_merge_input_vtable
{
  /*
   * Must advance the iterator to the next item.
   * Must return non-zero on success or 0 on the end of input.
   *
   * Galgorithm won't call this function after it returns 0.
   */
  int (*next)(void *ctx);

  /*
   * Must return a pointer to the current item.
   *
   * Galgorithm won't call this function after the next() returns 0.
   */
  const void *(*get)(const void *ctx);
};

/*
 * A collection of input iterators, which is passed to galgorithm_nway_merge().
 */
struct galgorithm_nway_merge_input
{
  const struct galgorithm_nway_merge_input_vtable *vtable;

  /*
   * An array of opaque contexts, which are passed to vtable functions.
   * Each context represents a single input iterator.
   * Contextes must contain data reqired for fetching items from distinct
   * input iterators.
   *
   * Contextes in this array can be shuffled using ctx_mover.
   */
  void *ctxs;

  /* The number of contextes. */
  size_t ctxs_count;

  /* The size of each context object. */
  size_t ctx_size;

  /* Is used for shuffling context objects. */
  gheap_item_mover_t ctx_mover;
};

/*
 * Vtable for output iterator, which is passed to galgorithm_nway_merge().
 */
struct galgorithm_nway_merge_output_vtable
{
  /*
   * Must put data into the output and advance the iterator
   * to the next position.
   */
  void (*put)(void *ctx, const void *data);
};

/*
 * Output iterator, which is passed to galgorithm_nway_merge().
 */
struct galgorithm_nway_merge_output
{
  const struct galgorithm_nway_merge_output_vtable *vtable;

  /*
   * An opaque context, which is passed to vtable functions.
   * The context must contain data essential for the output iterator.
   */
  void *ctx;
};

/*
 * Performs N-way merging of the given inputs into the output sorted
 * in ascending order, using ctx->less_comparer for items' comparison.
 *
 * Each input must hold non-zero number of items sorted in ascending order.
 *
 * As a side effect the function shuffles input contextes.
 */
static inline void galgorithm_nway_merge(const struct gheap_ctx *ctx,
    const struct galgorithm_nway_merge_input *input,
    const struct galgorithm_nway_merge_output *output);

/*
 * Must sort the range [base[0] ... base[n-1]].
 * ctx is small_range_sorter_ctx passed to galgorithm_nway_mergesort.
 */
typedef void (*galgorithm_nway_mergesort_small_range_sorter_t)(
    const void *ctx, void *base, size_t n);

/*
 * Performs n-way mergesort for [base[0] ... base[range_size-1]] items.
 *
 * Uses small_range_sorter for sorting ranges containing no more
 * than small_range_size items.
 *
 * Splits the input range into subranges with small_range_size size,
 * sorts them using small_range_sorter and then merges them back
 * using n-way merge with n = subranges_count.
 *
 * items_tmp_buf must point to an uninitialized memory, which can hold
 * up to range_size items.
 */
static inline void galgorithm_nway_mergesort(const struct gheap_ctx *ctx,
    void *base, size_t range_size,
    galgorithm_nway_mergesort_small_range_sorter_t small_range_sorter,
    const void *small_range_sorter_ctx,
    size_t small_range_size, size_t subranges_count, void *items_tmp_buf);


/*******************************************************************************
 * Implementation.
 *
 * Define all functions inline, so compiler will be able optimizing out common
 * args (fanout, page_chunks, item_size, less_comparer and item_mover),
 * which are usually constants, using constant folding optimization
 * ( http://en.wikipedia.org/wiki/Constant_folding ).
 *****************************************************************************/

#include "gheap.h"      /* for gheap_* stuff */

#include <assert.h>     /* for assert */
#include <stddef.h>     /* for size_t */
#include <stdint.h>     /* for uintptr_t, SIZE_MAX and UINTPTR_MAX */
#include <stdlib.h>     /* for malloc(), free() */

/* Returns a pointer to base[index]. */
static inline void *_galgorithm_get_item_ptr(
    const struct gheap_ctx *const ctx,
    const void *const base, const size_t index)
{
  const size_t item_size = ctx->item_size;

  assert(index <= SIZE_MAX / item_size);

  const size_t offset = item_size * index;
  assert((uintptr_t)base <= UINTPTR_MAX - offset);

  return ((char *)base) + offset;
}

/* Swaps items with given indexes */
static inline void _galgorithm_swap_items(const struct gheap_ctx *const ctx,
    const void *const base, const size_t a_index, const size_t b_index)
{
  const size_t item_size = ctx->item_size;
  const gheap_item_mover_t item_mover = ctx->item_mover;

  char tmp[item_size];
  void *const a = _galgorithm_get_item_ptr(ctx, base, a_index);
  void *const b = _galgorithm_get_item_ptr(ctx, base, b_index);
  item_mover(tmp, a);
  item_mover(a, b);
  item_mover(b, tmp);
}

static inline void galgorithm_heapsort(const struct gheap_ctx *const ctx,
    void *const base, const size_t n)
{
  gheap_make_heap(ctx, base, n);
  gheap_sort_heap(ctx, base, n);
}

static inline void galgorithm_partial_sort(const struct gheap_ctx *const ctx,
    void *const base, const size_t n, const size_t middle_index)
{
  assert(middle_index <= n);

  if (middle_index > 0) {
    gheap_make_heap(ctx, base, middle_index);

    const gheap_less_comparer_t less_comparer = ctx->less_comparer;
    const void *const less_comparer_ctx = ctx->less_comparer_ctx;

    for (size_t i = middle_index; i < n; ++i) {
      void *const tmp = _galgorithm_get_item_ptr(ctx, base, i);
      if (less_comparer(less_comparer_ctx, tmp, base)) {
        gheap_swap_max_item(ctx, base, middle_index, tmp);
      }
    }

    gheap_sort_heap(ctx, base, middle_index);
  }
}

struct _galgorithm_nway_merge_less_comparer_ctx
{
  gheap_less_comparer_t less_comparer;
  const void *less_comparer_ctx;
  const struct galgorithm_nway_merge_input_vtable *vtable;
};

static inline int _galgorithm_nway_merge_less_comparer(const void *const ctx,
    const void *const a, const void *const b)
{
  const struct _galgorithm_nway_merge_less_comparer_ctx *const c = ctx;
  const gheap_less_comparer_t less_comparer = c->less_comparer;
  const void *const less_comparer_ctx = c->less_comparer_ctx;
  const struct galgorithm_nway_merge_input_vtable *const vtable = c->vtable;

  return less_comparer(less_comparer_ctx, vtable->get(b), vtable->get(a));
}

static inline void galgorithm_nway_merge(const struct gheap_ctx *const ctx,
    const struct galgorithm_nway_merge_input *const input,
    const struct galgorithm_nway_merge_output *const output)
{
  void *const top_input = input->ctxs;
  size_t inputs_count = input->ctxs_count;

  assert(inputs_count > 0);

  const struct _galgorithm_nway_merge_less_comparer_ctx less_comparer_ctx = {
    .less_comparer = ctx->less_comparer,
    .less_comparer_ctx = ctx->less_comparer_ctx,
    .vtable = input->vtable,
  };
  const struct gheap_ctx nway_ctx = {
    .fanout = ctx->fanout,
    .page_chunks = ctx->page_chunks,
    .item_size = input->ctx_size,
    .less_comparer = &_galgorithm_nway_merge_less_comparer,
    .less_comparer_ctx = &less_comparer_ctx,
    .item_mover = input->ctx_mover,
  };

  gheap_make_heap(&nway_ctx, top_input, inputs_count);
  while (1) {
    const void *const data = input->vtable->get(top_input);
    output->vtable->put(output->ctx, data);
    if (!input->vtable->next(top_input)) {
      --inputs_count;
      if (inputs_count == 0) {
        break;
      }
      _galgorithm_swap_items(&nway_ctx, top_input, 0, inputs_count);
    }
    gheap_restore_heap_after_item_decrease(&nway_ctx, top_input,
        inputs_count, 0);
  }
}

static inline void _galgorithm_move_items(const struct gheap_ctx *const ctx,
    void *const src, const size_t n, void *const dst)
{
  const gheap_item_mover_t item_mover = ctx->item_mover;

  for (size_t i = 0; i < n; ++i) {
    item_mover(
        _galgorithm_get_item_ptr(ctx, dst, i),
        _galgorithm_get_item_ptr(ctx, src, i));
  }
}

static inline void _galgorithm_sort_subranges(const struct gheap_ctx *const ctx,
    void *const base, const size_t range_size,
    const galgorithm_nway_mergesort_small_range_sorter_t small_range_sorter,
    const void *const small_range_sorter_ctx,
    const size_t small_range_size)
{
  assert(small_range_size > 0);

  const size_t last_full_range = range_size - range_size % small_range_size;
  for (size_t i = 0; i != last_full_range; i += small_range_size) {
    small_range_sorter(small_range_sorter_ctx,
        _galgorithm_get_item_ptr(ctx, base, i), small_range_size);
  }

  /* Sort the last subrange, which contains less than small_range_size items. */
  if (last_full_range < range_size) {
    small_range_sorter(small_range_sorter_ctx,
        _galgorithm_get_item_ptr(ctx, base, last_full_range),
        range_size - last_full_range);
  }
}

struct _galgorithm_nway_mergesort_input_ctx
{
  const struct gheap_ctx *ctx;
  const void *next;
  const void *last;
};

static inline int _galgorithm_nway_mergesort_input_next(void *ctx)
{
  struct _galgorithm_nway_mergesort_input_ctx *const c = ctx;

  assert(c->next < c->last);
  c->next = _galgorithm_get_item_ptr(c->ctx, c->next, 1);
  assert(c->next <= c->last);
  return (c->next < c->last);
}

static inline const void *_galgorithm_nway_mergesort_input_get(const void *ctx)
{
  const struct _galgorithm_nway_mergesort_input_ctx *const c = ctx;

  assert(c->next < c->last);
  return c->next;
}

static const struct galgorithm_nway_merge_input_vtable
    _galgorithm_nway_mergesort_input_vtable = {
  .next = &_galgorithm_nway_mergesort_input_next,
  .get = &_galgorithm_nway_mergesort_input_get,
};

struct _galgorithm_nway_mergesort_output_ctx
{
  const struct gheap_ctx *ctx;
  void *next;
};

static inline void _galgorithm_nway_mergesort_output_put(void *ctx,
    const void *data)
{
  struct _galgorithm_nway_mergesort_output_ctx *const c = ctx;
  const gheap_item_mover_t item_mover = c->ctx->item_mover;

  item_mover(c->next, data);
  c->next = _galgorithm_get_item_ptr(c->ctx, c->next, 1);
}

static const struct galgorithm_nway_merge_output_vtable
    _galgorithm_nway_mergesort_output_vtable = {
  .put = &_galgorithm_nway_mergesort_output_put,
};

static inline void _galgorithm_merge_subrange_tuples(
    const struct gheap_ctx *const ctx, void *const base, const size_t range_size,
    struct galgorithm_nway_merge_input *const input,
    const struct galgorithm_nway_merge_output *const output,
    const size_t subranges_count, const size_t subrange_size)
{
  assert(subranges_count > 1);
  assert(subrange_size > 0);

  struct _galgorithm_nway_mergesort_input_ctx *const input_ctxs = input->ctxs;
  input->ctxs_count = subranges_count;

  size_t i = 0;

  /*
   * Merge full subrange tuples. Each full subrange tuple contains
   * subranges_count full subranges. Each full subrange contains
   * subrange_size items.
   */
  if (subrange_size <= range_size / subranges_count) {
    const size_t tuple_size = subrange_size * subranges_count;
    const size_t last_full_tuple = range_size - range_size % tuple_size;

    while (i != last_full_tuple) {
      for (size_t j = 0; j < subranges_count; ++j) {
        input_ctxs[j].next = _galgorithm_get_item_ptr(ctx, base, i);
        i += subrange_size;
        input_ctxs[j].last = _galgorithm_get_item_ptr(ctx, base, i);
      }

      galgorithm_nway_merge(ctx, input, output);
    }
  }

  /*
   * Merge tail subrange tuple. Tail subrange tuple contains less than
   * subranges_count full subranges. It also may contain tail subrange
   * with less than subrange_size items.
   */
  const size_t tail_tuple_size = range_size - i;
  if (tail_tuple_size > 0) {
    const size_t full_subranges_count = tail_tuple_size / subrange_size;
    assert(full_subranges_count < subranges_count);
    size_t tail_subranges_count = full_subranges_count;

    for (size_t j = 0; j < full_subranges_count; ++j) {
      input_ctxs[j].next = _galgorithm_get_item_ptr(ctx, base, i);
      i += subrange_size;
      input_ctxs[j].last = _galgorithm_get_item_ptr(ctx, base, i);
    }

    if (i < range_size) {
      input_ctxs[full_subranges_count].next =
          _galgorithm_get_item_ptr(ctx, base, i);
      input_ctxs[full_subranges_count].last =
          _galgorithm_get_item_ptr(ctx, base, range_size);
      ++tail_subranges_count;
    }

    input->ctxs_count = tail_subranges_count;
    galgorithm_nway_merge(ctx, input, output);
  }
}

static inline void _galgorithm_nway_mergesort_input_ctx_mover(void *dst,
    const void *src)
{
  *(struct _galgorithm_nway_mergesort_input_ctx *)dst =
      *(struct _galgorithm_nway_mergesort_input_ctx *)src;
}

static inline void galgorithm_nway_mergesort(const struct gheap_ctx *const ctx,
    void *const base, const size_t range_size,
    const galgorithm_nway_mergesort_small_range_sorter_t small_range_sorter,
    const void *const small_range_sorter_ctx,
    const size_t small_range_size, const size_t subranges_count,
    void *const items_tmp_buf)
{
  assert(small_range_size > 0);
  assert(subranges_count > 1);

  /* Preparation: Move items to a temporary buffer. */
  _galgorithm_move_items(ctx, base, range_size, items_tmp_buf);

  /*
   * Step 1: split the range into subranges with small_range_size size each
   * (except the last subrange, which may contain less than small_range_size
   * items) and sort each of these subranges using small_range_sorter.
   */
  _galgorithm_sort_subranges(ctx, items_tmp_buf, range_size,
      small_range_sorter, small_range_sorter_ctx, small_range_size);

  /* Step 2: Merge subranges sorted at the previous step using n-way merge. */
  struct _galgorithm_nway_mergesort_input_ctx *const input_ctxs =
      malloc(sizeof(input_ctxs[0]) * subranges_count);
  for (size_t i = 0; i < subranges_count; ++i) {
    input_ctxs[i].ctx = ctx;
  }

  struct galgorithm_nway_merge_input input = {
      .vtable = &_galgorithm_nway_mergesort_input_vtable,
      .ctxs = input_ctxs,
      .ctxs_count = subranges_count,
      .ctx_size = sizeof(input_ctxs[0]),
      .ctx_mover = &_galgorithm_nway_mergesort_input_ctx_mover,
  };

  struct _galgorithm_nway_mergesort_output_ctx output_ctx;
  output_ctx.ctx = ctx;

  const struct galgorithm_nway_merge_output output = {
    .vtable = &_galgorithm_nway_mergesort_output_vtable,
    .ctx = &output_ctx,
  };

  size_t subrange_size = small_range_size;
  for (;;) {
    /*
     * First pass: merge items from the temporary buffer
     * to the original location.
     */
    output_ctx.next = base;
    _galgorithm_merge_subrange_tuples(ctx, items_tmp_buf, range_size,
        &input, &output, subranges_count, subrange_size);

    if (subrange_size > range_size / subranges_count) {
      break;
    }
    subrange_size *= subranges_count;

    /*
     * Second pass: merge items from the original location
     * to the temporary buffer.
     */
    output_ctx.next = items_tmp_buf;
    _galgorithm_merge_subrange_tuples(ctx, base, range_size,
        &input, &output, subranges_count, subrange_size);

    if (subrange_size > range_size / subranges_count) {
      /* Move items from the temporary buffer to the original location. */
      _galgorithm_move_items(ctx, items_tmp_buf, range_size, base);
      break;
    }
    subrange_size *= subranges_count;
  }

  free(input_ctxs);
}



#endif
