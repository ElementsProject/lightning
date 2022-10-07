Generalized heap implementation

Generalized heap is based on usual heap data structure -
http://en.wikipedia.org/wiki/Heap_%28data_structure%29 .

It provides two additional paremeters, which allow optimizing heap
for particular cases:

* Fanout. The number of children per each heap node.
  * Fanout=1 corresponds to sorted List data structure.
    See http://en.wikipedia.org/wiki/List_%28computing%29 .
  * Fanout=2 corresponds to Binary heap.
    See http://en.wikipedia.org/wiki/Binary_heap .
  * Fanout>2 corresponds to D-heap. See http://en.wikipedia.org/wiki/D-heap .
    D-heap can be faster than Binary heap in the following cases:
    * If item comparison is faster than item assignment.
    * If sequential access to items is faster than non-sequential access
      to items.
    * If the number of 'decrease key' operations is larger than the number
      of 'pop heap' operations for min-heap. This is usually the case
      for Dijkstra algorithm
      ( http://en.wikipedia.org/wiki/Dijkstra%27s_algorithm ).

* PageChunks. The number of chunks per each heap page. Each chunk contains
  Fanout items, so each heap page contains (PageChunks * Fanout) items.
  Items inside heap page are organized into a sub-heap with a root item outside
  the page. Leaf items in the page can be roots pointing to another pages.
  * PageChunks=1 corresponds to standard heap.
  * PageChunks>1 corresponds to B-heap. See http://en.wikipedia.org/wiki/B-heap.
    Heap pages containing more than one page chunk can be useful if multiple
    item accesses inside heap page is faster than multiple accesses to items
    across distinct heap pages. This can be the case for systems with virtual
    memory, where VM pages can be swapped out to slow media.
    Heap pages can be mapped to VM pages if PageChunks is calculated using
    the following formula:
    * PageChunks = sizeof(VM_page) / (sizeof(item) * Fanout)
    Perfrect alginment between VM pages and heap pages can be achieved if
    heap's root item is placed at the end of VM page. In this case the first
    child of the heap's root (i.e. the item with index 1) sits at the beginning
    of the next VM page.

See also https://github.com/valyala/gheap/tree/sophisticated-gheap branch,
which contains sophisticated gheap implementation with more complex heap layout
and low-level optimizations.


===============================================================================
The implementation provides the following functions:
* Auxiliary functions:
  * get_parent_index() - returns parent index for the given child.
  * get_child_index() - returns the first child index for the given parent.
  * swap_max_item() - swaps heap's maximum item with the item outside heap
    and restores max heap invariant.
  * restore_heap_after_item_increase() - restores max heap invariant after
    the item's value increase.
  * restore_heap_after_item_decrease() - restores max heap invariant after
    the item's value decrease.
  * remove_from_heap() - removes the given item from the heap.

* STL-like functions:
  * is_heap_until() - returns an iterator to the first non-heap item
    in the given range.
  * is_heap() - checks whether the given range contains valid heap.
  * make_heap() - creates a heap.
  * push_heap() - pushes the last element in the range to the heap.
  * pop_heap() - pops up the maximum element from the heap.
  * sort_heap() - sorts heap items in ascending order.

* Heap-based algorithms:
  * heapsort() - performs heapsort.
  * partial_sort() - performs partial sort.
  * nway_merge() - performs N-way merge on top of the heap.
  * nway_mergesort() - performs N-way mergesort on top of the heap.

The implementation is inspired by http://queue.acm.org/detail.cfm?id=1814327 ,
but it is more generalized. The implementation is optimized for speed.
There are the following files:
* gheap_cpp03.hpp - gheap optimized for C++03.
* gheap_cpp11.hpp - gheap optimized for C++11.
* gheap.hpp - switch file, which includes either gheap_cpp03.hpp
  or gheap_cpp11.hpp depending on whether GHEAP_CPP11 macro is defined.
* gheap.h - gheap optimized for C99.
* galgorithm.hpp - various algorithms on top of gheap for C++.
* galgorithm.h - various algorithms on top of gheap for C99.
* gpriority_queue.hpp - priority queue on top of gheap for C++.
* gpriority_queue.h - priority queue on top of gheap for C99.

Don't forget passing -DNDEBUG option to the compiler when creating optimized
builds. This significantly speeds up gheap code by removing debug assertions.

There are the following tests:
* tests.cpp and tests.c - tests for gheap algorithms' correctness.
* perftests.cpp and perftests.c - performance tests.
* ops_count_test.cpp - the test, which counts the number of varius operations
  performed by gheap algorithms.

===============================================================================
gheap for C++ usage

#include "gheap.hpp"

...

template <class Heap>
void heapsort(vector<int> &a)
{
  Heap::make_heap(a.begin(), a.end());
  Heap::sort_heap(a.begin(), a.end());
}

typedef gheap<2, 1> binary_heap;
heapsort<binary_heap>(a);

typedef gheap<4, 1> d4_heap;
heapsort<d4_heap>(a);

typedef gheap<2, 512> paged_binary_heap;
heapsort<paged_binary_heap>(a);


===============================================================================
gheap for C usage

#include "gheap.h"

static void less(const void *const ctx, const void *const a,
    const void *const b)
{
  (void)ctx;
  return *(int *)a < *(int *)b;
}

static void move(void *const dst, const void *const src)
{
  *(int *)dst = *(int *)src;
}

static void heapsort(const struct gheap_ctx *const ctx,
    int *const a, const size_t n)
{
  gheap_make_heap(ctx, a, n);
  gheap_sort_heap(ctx, a, n);
}

/* heapsort using binary heap */
static const struct gheap_ctx binary_heap_ctx = {
  .fanout = 2,
  .page_chunks = 1,
  .item_size = sizeof(int),
  .less_comparer = &less,
  .less_comparer_ctx = NULL,
  .item_mover = &move,
};
heapsort(&binary_heap_ctx, a, n);

/* heapsort using D-4 heap */
static const struct gheap_ctx d4_heap_ctx = {
  .fanout = 4,
  .page_chunks = 1,
  .item_size = sizeof(int),
  .less_comparer = &less,
  .less_comparer_ctx = NULL,
  .item_mover = &move,
};
heapsort(&d4_heap_ctx, a, n);

/* heapsort using paged binary heap */
static const struct gheap_ctx paged_binary_heap_ctx = {
  .fanout = 2,
  .page_chunks = 512,
  .item_size = sizeof(int),
  .less_comparer = &less,
  .less_comparer_ctx = NULL,
  .item_mover = &move,
};
heapsort(&paged_binary_heap_ctx, a, n);
