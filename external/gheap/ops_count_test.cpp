// Compares the number of operations with items in gheap-based algorithms
// to the number of operations with items in the corresponding STL algorithms.
//
// Pass -DNDEBUG for eliminating operations related to debugging checks.

#include "galgorithm.hpp"
#include "gheap.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <list>
#include <stdint.h>  // for uintptr_t (<cstdint> is missing in C++03).
#include <vector>

using namespace std;

// Simulates a LRU list of pages, which can contain up to _max_lru_size entries.
// Each page's size is PAGE_MASK + 1 bytes.
struct lru
{
  typedef list<uintptr_t> lru_t;

  static const uintptr_t PAGE_MASK = (((uintptr_t)1) << 12) - 1;

  // Maximum number of pages in LRU list.
  static const size_t MAX_LRU_SIZE = 20;

  // LRU list of pages. Front of the list contains least recently used pages.
  static lru_t lru_pages;

  // The number of simulated pagefaults since the last lru::init() call.
  static int pagefaults;

  // Resets the model to initial state.
  static void reset()
  {
    lru_pages.clear();
    pagefaults = 0;
  }

  // Simulates access to a memory pointed by ptr.
  // Brings the accessed page to the back of LRU list.
  // If the page is absent in LRU list, then increments pagefaults counter.
  static void access_ptr(const void *const ptr)
  {
    assert(lru_pages.size() <= MAX_LRU_SIZE);

    const uintptr_t page_num = ((uintptr_t)ptr) & ~PAGE_MASK;
    lru_t::iterator it = find(lru_pages.begin(), lru_pages.end(),
        page_num);
    if (it == lru_pages.end()) {
      const uintptr_t prev_page_num = page_num - PAGE_MASK - 1;
      if (count(lru_pages.begin(), lru_pages.end(), prev_page_num) == 0) {
        // Count pagefault only if the previous page is not in the LRU list.
        // If the previous page is in the LRU list, then assume that the current
        // page is already pre-fetched, so no hard pagefault.
        ++pagefaults;
      }

      lru_pages.push_front(page_num);
      if (lru_pages.size() > MAX_LRU_SIZE) {
        lru_pages.pop_back();
      }
      assert(lru_pages.size() <= MAX_LRU_SIZE);
    }
    else {
      lru_pages.splice(lru_pages.begin(), lru_pages, it);
    }
  }
};

lru::lru_t lru::lru_pages;
int lru::pagefaults = 0;


struct A
{
  static int default_ctors;
  static int copy_ctors;
  static int copy_assignments;
  static int swaps;
  static int cheap_dtors;
  static int expensive_dtors;
  static int move_ctors;
  static int cheap_move_assignments;
  static int expensive_move_assignments;
  static int comparisons;

  static void reset()
  {
    default_ctors = 0;
    copy_ctors = 0;
    copy_assignments = 0;
    swaps = 0;
    cheap_dtors = 0;
    expensive_dtors = 0;
    move_ctors = 0;
    cheap_move_assignments = 0;
    expensive_move_assignments = 0;
    comparisons = 0;
    lru::reset();
  }

  static void print()
  {
    cout << "default_ctors=" << default_ctors << ", copy_ctors=" <<
        copy_ctors << ", copy_assignments=" << copy_assignments <<
        ", swaps=" << swaps << ", cheap_dtors=" << cheap_dtors <<
        ", expensive_dtors=" << expensive_dtors << ", move_ctors=" <<
        move_ctors << ", cheap_move_assignments=" << cheap_move_assignments <<
        ", expensive_move_assignments=" << expensive_move_assignments <<
        ", comparisons=" << comparisons << ", pagefaults=" << lru::pagefaults <<
            endl;
  }

  int value;

  bool has_value() const
  {
    return (value >= 0);
  }

  int get_value() const
  {
    assert(has_value());
    lru::access_ptr(this);
    return value;
  }

  void set_value(const int v)
  {
    assert(v >= 0);
    value = v;
    lru::access_ptr(this);
  }

  void set_value(const A &a)
  {
    int v = a.get_value();
    set_value(v);
  }

  void clear_value()
  {
    value = -1;
    lru::access_ptr(this);
  }

  A()
  {
    ++default_ctors;
    clear_value();
  }

  A(const int v)
  {
    set_value(v);
  }

  A(const A &a)
  {
    ++copy_ctors;
    set_value(a);
  }

  void operator = (const A &a)
  {
    if (this == &a) {
      return;
    }

    assert(has_value());
    ++copy_assignments;
    set_value(a);
  }

  ~A()
  {
    if (has_value()) {
      ++expensive_dtors;
    }
    else {
      ++cheap_dtors;
    }
    clear_value();
  }

#ifdef GHEAP_CPP11

  A(A &&a)
  {
    ++move_ctors;
    set_value(a);
    a.clear_value();
  }

  void operator = (A &&a)
  {
    if (this == &a) {
      return;
    }

    if (has_value()) {
      ++expensive_move_assignments;
    }
    else {
      ++cheap_move_assignments;
    }

    set_value(a);
    a.clear_value();
  }

#endif
};

int A::default_ctors;
int A::copy_ctors;
int A::copy_assignments;
int A::swaps;
int A::cheap_dtors;
int A::expensive_dtors;
int A::move_ctors;
int A::cheap_move_assignments;
int A::expensive_move_assignments;
int A::comparisons;

namespace std
{
  template <>
  void swap(A &a, A &b)
  {
    ++A::swaps;

    int tmp = a.get_value();
    a.set_value(b);
    b.set_value(tmp);
  }
}

bool operator < (const A &a, const A &b)
{
  ++A::comparisons;
  return (a.get_value() < b.get_value());
}

struct stl
{
  static const char *name()
  {
    return "stl";
  }

  template <class RandomAccessIterator>
  static void push_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    ::std::push_heap(first, last);
  }

  template <class RandomAccessIterator>
  static void pop_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    ::std::pop_heap(first, last);
  }

  template <class RandomAccessIterator>
  static void make_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    ::std::make_heap(first, last);
  }

  template <class RandomAccessIterator>
  static void sort_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    ::std::sort_heap(first, last);
  }
};

struct gtl
{
  typedef gheap<> heap;

  static const char *name()
  {
    return "gheap<>";
  }

  template <class RandomAccessIterator>
  static void push_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    heap::push_heap(first, last);
  }

  template <class RandomAccessIterator>
  static void pop_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    heap::pop_heap(first, last);
  }

  template <class RandomAccessIterator>
  static void make_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    heap::make_heap(first, last);
  }

  template <class RandomAccessIterator>
  static void sort_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    heap::sort_heap(first, last);
  }
};

namespace {

void init_array(vector<A> &a, const size_t n)
{
  a.clear();
  srand(0);
  generate_n(back_inserter(a), n, rand);
}

template <class Heap>
void test_push_heap(vector<A> &a, const size_t n)
{
  cout << "  test_push_heap(" << Heap::name() << "): ";

  init_array(a, n);
  A::reset();
  for (size_t i = 2; i <= n; ++i) {
    Heap::push_heap(a.begin(), a.begin() + i);
  }
  A::print();
}

template <class Heap>
void test_pop_heap(vector<A> &a, const size_t n)
{
  cout << "  test_pop_heap(" << Heap::name() << "): ";

  init_array(a, n);
  Heap::make_heap(a.begin(), a.end());

  A::reset();
  for (size_t i = 0; i < n - 1; ++i) {
    Heap::pop_heap(a.begin(), a.end() - i);
  }
  A::print();
}

template <class Heap>
void test_make_heap(vector<A> &a, const size_t n)
{
  cout << "  test_make_heap(" << Heap::name() << "): ";

  init_array(a, n);
  A::reset();
  Heap::make_heap(a.begin(), a.end());
  A::print();
}

template <class Heap>
void test_sort_heap(vector<A> &a, const size_t n)
{
  cout << "  test_sort_heap(" << Heap::name() << "): ";

  init_array(a, n);
  Heap::make_heap(a.begin(), a.end());

  A::reset();
  Heap::sort_heap(a.begin(), a.end());
  A::print();
}

void test_nway_mergesort_avg(vector<A> &a, const size_t n)
{
  cout << "  test_nway_mergesort_avg(" << gtl::name() << "): ";

  typedef galgorithm<gtl::heap> algorithm;

  init_array(a, n);
  A::reset();
  algorithm::nway_mergesort(a.begin(), a.end());
  A::print();
}

void test_nway_mergesort_worst(vector<A> &a, const size_t n)
{
  cout << "  test_nway_mergesort_worst(" << gtl::name() << "): ";

  typedef galgorithm<gtl::heap> algorithm;

  // Simulate worst case for SGI STL sort implementation (aka introsort) -
  // see http://en.wikipedia.org/wiki/Introsort .
  // Actually n-way mergesort must be free of bad cases.
  for (size_t i = 0; i < n; ++i) {
    a[i] = n - i;
  }

  init_array(a, n);
  A::reset();
  algorithm::nway_mergesort(a.begin(), a.end());
  A::print();
}

void test_sort_avg(vector<A> &a, const size_t n)
{
  cout << "  test_sort_avg(" << stl::name() << "): ";

  init_array(a, n);
  A::reset();
  sort(a.begin(), a.end());
  A::print();
}

void test_sort_worst(vector<A> &a, const size_t n)
{
  cout << "  test_sort_worst(" << stl::name() << "): ";

  // Simulate worst case for SGI STL sort implementation (aka introsort) -
  // see http://en.wikipedia.org/wiki/Introsort .
  for (size_t i = 0; i < n; ++i) {
    a[i] = n - i;
  }

  A::reset();
  sort(a.begin(), a.end());
  A::print();
}

}  // end of anonymous namespace

int main()
{
  const size_t N = 1000000;

  cout << "N=" << N << endl;

  vector<A> a;
  a.reserve(N);

  test_push_heap<stl>(a, N);
  test_push_heap<gtl>(a, N);

  test_pop_heap<stl>(a, N);
  test_pop_heap<gtl>(a, N);

  test_make_heap<stl>(a, N);
  test_make_heap<gtl>(a, N);

  test_sort_heap<stl>(a, N);
  test_sort_heap<gtl>(a, N);

  test_nway_mergesort_avg(a, N);
  test_nway_mergesort_worst(a, N);
  test_sort_avg(a, N);
  test_sort_worst(a, N);
}
