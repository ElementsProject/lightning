#include "galgorithm.h"
#include "gheap.h"
#include "gpriority_queue.h"

#include <assert.h>
#include <stdio.h>     // for printf()
#include <stdlib.h>    // for rand(), srand()
#include <time.h>      // for clock()

typedef size_t T;

static int less(const void *const ctx, const void *const a, const void *const b)
{
  (void)ctx;
  return *((T *)a) < *((T *)b);
}

static void move(void *const dst, const void *const src)
{
  *((T *)dst) = *((T *)src);
}

static double get_time(void)
{
  return (double)clock() / CLOCKS_PER_SEC;
}

static void print_performance(const double t, const size_t m)
{
  printf(": %.0lf Kops/s\n", m / t / 1000);
}

static void init_array(T *const a, const size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    a[i] = rand();
  }
}

static void perftest_heapsort(const struct gheap_ctx *const ctx,
    T *const a, const size_t n, const size_t m)
{
  printf("perftest_heapsort(n=%zu, m=%zu)", n, m);

  double total_time = 0;

  for (size_t i = 0; i < m / n; ++i) {
    init_array(a, n);

    const double start = get_time();
    galgorithm_heapsort(ctx, a, n);
    const double end = get_time();

    total_time += end - start;
  }

  print_performance(total_time, m);
}

static void perftest_partial_sort(const struct gheap_ctx *const ctx,
    T *const a, const size_t n, const size_t m)
{
  const size_t k = n / 4;

  printf("perftest_partial_sort(n=%zu, m=%zu, k=%zu)", n, m, k);

  double total_time = 0;

  for (size_t i = 0; i < m / n; ++i) {
    init_array(a, n);

    const double start = get_time();
    galgorithm_partial_sort(ctx, a, n, k);
    const double end = get_time();

    total_time += end - start;
  }

  print_performance(total_time, m);
}

static void small_range_sorter(const void *const ctx, void *const a,
    const size_t n)
{
  galgorithm_heapsort(ctx, a, n);
}

static void perftest_nway_mergesort(const struct gheap_ctx *const ctx,
    T *const a, const size_t n, const size_t m)
{
  const size_t small_range_size = ((1 << 20) - 1) / 3;
  const size_t subranges_count = 15;

  printf("perftest_nway_mergesort(n=%zu, m=%zu, small_range_size=%zu, "
      "subranges_count=%zu)", n, m, small_range_size, subranges_count);

  double total_time = 0;

  struct gheap_ctx small_range_sorter_ctx = *ctx;
  small_range_sorter_ctx.fanout = 4;

  for (size_t i = 0; i < m / n; ++i) {
    init_array(a, n);

    const double start = get_time();
    T *const items_tmp_buf = malloc(sizeof(items_tmp_buf[0]) * n);
    galgorithm_nway_mergesort(ctx, a, n,
        &small_range_sorter, &small_range_sorter_ctx,
        small_range_size, subranges_count, items_tmp_buf);
    free(items_tmp_buf);
    const double end = get_time();

    total_time += end - start;
  }

  print_performance(total_time, m);
}

static void delete_item(void *item)
{
  /* do nothing */
  (void)item;
}

static void perftest_priority_queue(const struct gheap_ctx *const ctx,
    T *const a, const size_t n, const size_t m)
{
  printf("perftest_priority_queue(n=%zu, m=%zu)", n, m);

  init_array(a, n);
  struct gpriority_queue *const q = gpriority_queue_create_from_array(
      ctx, &delete_item, a, n);

  double start = get_time();
  for (size_t i = 0; i < m; ++i) {
    gpriority_queue_pop(q);
    const T tmp = rand();
    gpriority_queue_push(q, &tmp);
  }
  double end = get_time();

  gpriority_queue_delete(q);

  print_performance(end - start, m);
}

static void perftest(const struct gheap_ctx *const ctx, T *const a,
    const size_t max_n)
{
  size_t n = max_n;
  while (n > 0) {
    perftest_heapsort(ctx, a, n, max_n);
    perftest_partial_sort(ctx, a, n, max_n);
    perftest_nway_mergesort(ctx, a, n, max_n);
    perftest_priority_queue(ctx, a, n, max_n);

    n >>= 1;
  }
}

static const struct gheap_ctx ctx_v = {
  .fanout = 2,
  .page_chunks = 1,
  .item_size = sizeof(T),
  .less_comparer = &less,
  .less_comparer_ctx = NULL,
  .item_mover = &move,
};

int main(void)
{
  static const size_t MAX_N = 32 * 1024 * 1024;

  printf("fanout=%zu, page_chunks=%zu, max_n=%zu\n",
      ctx_v.fanout, ctx_v.page_chunks, MAX_N);

  srand(0);
  T *const a = malloc(sizeof(a[0]) * MAX_N);

  perftest(&ctx_v, a, MAX_N);

  free(a);

  return 0;
}
