// Pass -DGHEAP_CPP11 to compiler for gheap_cpp11.hpp tests,
// otherwise gheap_cpp03.hpp will be tested.

#include "galgorithm.hpp"
#include "gheap.hpp"
#include "gpriority_queue.hpp"

#include <algorithm>  // for *_heap(), copy()
#include <cstdlib>    // for rand(), srand()
#include <ctime>      // for clock()
#include <iostream>
#include <queue>      // for priority_queue
#include <utility>    // for pair
#include <vector>     // for vector

using namespace std;

namespace {

double get_time()
{
  return (double)clock() / CLOCKS_PER_SEC;
}

void print_performance(const double t, const size_t m)
{
  cout << ": " << (m / t / 1000) << " Kops/s" << endl;
}

template <class T>
void init_array(T *const a, const size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    a[i] = rand();
  }
}

// Dummy wrapper for STL heap.
struct stl_heap
{
  template <class RandomAccessIterator, class LessComparer>
  static void make_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    std::make_heap(first, last, less_comparer);
  }

  template <class RandomAccessIterator, class LessComparer>
  static void sort_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    std::sort_heap(first, last, less_comparer);
  }
};

// Dummy wrapper for STL algorithms.
struct stl_algorithm
{
  template <class RandomAccessIterator>
  static void partial_sort(const RandomAccessIterator &first,
      const RandomAccessIterator &middle, const RandomAccessIterator &last)
  {
    std::partial_sort(first, middle, last);
  }
};

template <class T, class Heap>
void perftest_heapsort(T *const a, const size_t n, const size_t m)
{
  cout << "perftest_heapsort(n=" << n << ", m=" << m << ")";

  typedef galgorithm<Heap> algorithm;

  double total_time = 0;

  for (size_t i = 0; i < m / n; ++i) {
    init_array(a, n);

    const double start = get_time();
    algorithm::heapsort(a, a + n);
    const double end = get_time();

    total_time += end - start;
  }

  print_performance(total_time, m);
}

template <class T, class Algorithm>
void perftest_partial_sort(T *const a, const size_t n, const size_t m)
{
  const size_t k = n / 4;

  cout << "perftest_partial_sort(n=" << n << ", m=" << m << ", k=" << k << ")";

  double total_time = 0;

  for (size_t i = 0; i < m / n; ++i) {
    init_array(a, n);

    const double start = get_time();
    Algorithm::partial_sort(a, a + k, a + n);
    const double end = get_time();

    total_time += end - start;
  }

  print_performance(total_time, m);
}

template <class T>
bool less_comparer(const T &a, const T &b)
{
  return (a < b);
}

template <class T>
void small_range_sorter(T *const first, T *const last,
      bool (&less_comparer)(const T &, const T &))
{
  galgorithm<gheap<2, 1> >::heapsort(first, last, less_comparer);
}

template <class T, class Heap>
void perftest_nway_mergesort(T *const a, const size_t n, const size_t m)
{
  const size_t small_range_size = (1 << 15) - 1;
  const size_t subranges_count = 7;

  cout << "perftest_nway_mergesort(n=" << n << ", m=" << m <<
      ", small_range_size=" << small_range_size << ", subranges_count=" <<
      subranges_count << ")";

  typedef galgorithm<Heap> algorithm;

  double total_time = 0;

  for (size_t i = 0; i < m / n; ++i) {
    init_array(a, n);

    const double start = get_time();
    algorithm::nway_mergesort(a, a + n,
        less_comparer<T>, small_range_sorter<T>,
        small_range_size, subranges_count);
    const double end = get_time();

    total_time += end - start;
  }

  print_performance(total_time, m);
}

template <class T, class PriorityQueue>
void perftest_priority_queue(T *const a, const size_t n, const size_t m)
{
  cout << "perftest_priority_queue(n=" << n << ", m=" << m << ")";

  init_array(a, n);
  PriorityQueue q(a, a + n);

  const double start = get_time();
  for (size_t i = 0; i < m; ++i) {
    q.pop();
    q.push(rand());
  }
  const double end = get_time();

  print_performance(end - start, m);
}

template <class T, class Heap>
void perftest_gheap(T *const a, const size_t max_n)
{
  size_t n = max_n;
  while (n > 0) {
    perftest_heapsort<T, Heap>(a, n, max_n);
    perftest_partial_sort<T, galgorithm<Heap> >(a, n, max_n);
    perftest_nway_mergesort<T, Heap>(a, n, max_n);
    perftest_priority_queue<T, gpriority_queue<Heap, T> >(a, n, max_n);

    n >>= 1;
  }
}

template <class T>
void perftest_stl_heap(T *const a, const size_t max_n)
{
  size_t n = max_n;
  while (n > 0) {
    perftest_heapsort<T, stl_heap>(a, n, max_n);
    perftest_partial_sort<T, stl_algorithm>(a, n, max_n);

    // stl heap doesn't provide nway_merge(),
    // so skip perftest_nway_mergesort().

    perftest_priority_queue<T, priority_queue<T> >(a, n, max_n);

    n >>= 1;
  }
}

}  // end of anonymous namespace.


int main(void)
{
  static const size_t MAX_N = 32 * 1024 * 1024;
  static const size_t FANOUT = 2;
  static const size_t PAGE_CHUNKS = 1;
  typedef size_t T;

  cout << "fanout=" << FANOUT << ", page_chunks=" << PAGE_CHUNKS <<
      ", max_n=" << MAX_N << endl;

  srand(0);
  T *const a = new T[MAX_N];

  cout << "* STL heap" << endl;
  perftest_stl_heap(a, MAX_N);

  cout << "* gheap" << endl;
  typedef gheap<FANOUT, PAGE_CHUNKS> heap;
  perftest_gheap<T, heap>(a, MAX_N);

  delete[] a;
}
