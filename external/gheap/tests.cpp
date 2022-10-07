// Tests for C++03 and C++11 gheap, galgorithm and gpriority_queue.
//
// Pass -DGHEAP_CPP11 to compiler for gheap_cpp11.hpp tests,
// otherwise gheap_cpp03.hpp will be tested.

#include "galgorithm.hpp"
#include "gheap.hpp"
#include "gpriority_queue.hpp"

#include <algorithm>  // for min_element()
#include <cassert>
#include <cstdlib>    // for srand(), rand()
#include <deque>
#include <iostream>   // for cout
#include <iterator>   // for back_inserter
#include <vector>
#include <utility>    // for pair

#ifndef GHEAP_CPP11
#  include <algorithm>  // for swap()
#endif

using namespace std;

namespace {

template <class Heap>
void test_parent_child(const size_t start_index, const size_t n)
{
  assert(start_index > 0);
  assert(start_index <= SIZE_MAX - n);

  cout << "    test_parent_child(start_index=" << start_index << ", n=" << n <<
      ") ";

  for (size_t i = 0; i < n; ++i) {
    const size_t u = start_index + i;
    size_t v = Heap::get_child_index(u);
    if (v < SIZE_MAX) {
      assert(v > u);
      v = Heap::get_parent_index(v);
      assert(v == u);
    }

    v = Heap::get_parent_index(u);
    assert(v < u);
    v = Heap::get_child_index(v);
    assert(v <= u && u - v < Heap::FANOUT);
  }

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_is_heap(const size_t n)
{
  assert(n > 0);

  cout << "    test_is_heap(n=" << n << ") ";

  IntContainer a;

  // Verify that ascending sorted array creates one-item heap.
  a.clear();
  for (size_t i = 0; i < n; ++i) {
    a.push_back(i);
  }
  assert(Heap::is_heap_until(a.begin(), a.end()) == a.begin() + 1);
  assert(Heap::is_heap(a.begin(), a.begin() + 1));
  if (n > 1) {
    assert(!Heap::is_heap(a.begin(), a.end()));
  }

  // Verify that descending sorted array creates valid heap.
  a.clear();
  for (size_t i = 0; i < n; ++i) {
    a.push_back(n - i);
  }
  assert(Heap::is_heap_until(a.begin(), a.end()) == a.end());
  assert(Heap::is_heap(a.begin(), a.end()));

  // Verify that array containing identical items creates valid heap.
  a.clear();
  for (size_t i = 0; i < n; ++i) {
    a.push_back(n);
  }
  assert(Heap::is_heap_until(a.begin(), a.end()) == a.end());
  assert(Heap::is_heap(a.begin(), a.end()));

  cout << "OK" << endl;
}

template <class IntContainer>
void init_array(IntContainer &a, const size_t n)
{
  a.clear();

  for (size_t i = 0; i < n; ++i) {
    a.push_back(rand());
  }
}

template <class RandomAccessIterator>
void assert_sorted_asc(const RandomAccessIterator &first,
    const RandomAccessIterator &last)
{
  assert(last > first);

  const size_t size = last - first;
  for (size_t i = 1; i < size; ++i) {
    assert(first[i] >= first[i - 1]);
  }
}

template <class RandomAccessIterator>
void assert_sorted_desc(const RandomAccessIterator &first,
    const RandomAccessIterator &last)
{
  assert(last > first);

  const size_t size = last - first;
  for (size_t i = 1; i < size; ++i) {
    assert(first[i] <= first[i - 1]);
  }
}

bool less_comparer_desc(const int &a, const int &b)
{
  return (b < a);
}

template <class Heap, class IntContainer>
void test_make_heap(const size_t n)
{
  cout << "    test_make_heap(n=" << n << ") ";

  IntContainer a;
  init_array(a, n);
  Heap::make_heap(a.begin(), a.end());
  assert(Heap::is_heap(a.begin(), a.end()));

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_sort_heap(const size_t n)
{
  cout << "    test_sort_heap(n=" << n << ") ";

  IntContainer a;

  // Test ascending sorting
  init_array(a, n);
  Heap::make_heap(a.begin(), a.end());
  Heap::sort_heap(a.begin(), a.end());
  assert_sorted_asc(a.begin(), a.end());

  // Test descending sorting
  init_array(a, n);
  Heap::make_heap(a.begin(), a.end(), less_comparer_desc);
  Heap::sort_heap(a.begin(), a.end(), less_comparer_desc);
  assert_sorted_desc(a.begin(), a.end());

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_push_heap(const size_t n)
{
  cout << "    test_push_heap(n=" << n << ") ";

  IntContainer a;
  init_array(a, n);

  for (size_t i = 0; i < n; ++i) {
    Heap::push_heap(a.begin(), a.begin() + i + 1);
  }
  assert(Heap::is_heap(a.begin(), a.end()));

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_pop_heap(const size_t n)
{
  cout << "    test_pop_heap(n=" << n << ") ";

  IntContainer a;
  init_array(a, n);

  Heap::make_heap(a.begin(), a.end());
  for (size_t i = 0; i < n; ++i) {
    const int item = a[0];
    Heap::pop_heap(a.begin(), a.end() - i);
    assert(item == *(a.end() - i - 1));
  }
  assert_sorted_asc(a.begin(), a.end());

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_swap_max_item(const size_t n)
{
  typedef typename IntContainer::iterator iterator;

  cout << "    test_swap_max_item(n=" << n << ") ";

  IntContainer a;
  init_array(a, n);

  const size_t m = n / 2;

  if (m > 0) {
    Heap::make_heap(a.begin(), a.begin() + m);
    for (size_t i = m; i < n; ++i) {
      const int max_item = a[0];
      Heap::swap_max_item(a.begin(), a.begin() + m, a[i]);
      assert(max_item == a[i]);
      assert(Heap::is_heap(a.begin(), a.begin() + m));
    }
  }

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_restore_heap_after_item_increase(const size_t n)
{
  cout << "    test_restore_heap_after_item_increase(n=" << n << ") ";

  IntContainer a;
  init_array(a, n);

  Heap::make_heap(a.begin(), a.end());
  for (size_t i = 0; i < n; ++i) {
    const size_t item_index = rand() % n;
    const int old_item = a[item_index];

    // Don't allow integer overflow.
    size_t fade = SIZE_MAX;
    do {
      // Division by zero is impossible here.
      a[item_index] = old_item + rand() % fade;
      fade /= 2;
    } while (a[item_index] < old_item);
    Heap::restore_heap_after_item_increase(a.begin(), a.begin() + item_index);
    assert(Heap::is_heap(a.begin(), a.end()));
  }

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_restore_heap_after_item_decrease(const size_t n)
{
  cout << "    test_restore_heap_after_item_decrease(n=" << n << ") ";

  IntContainer a;
  init_array(a, n);

  Heap::make_heap(a.begin(), a.end());
  for (size_t i = 0; i < n; ++i) {
    const size_t item_index = rand() % n;
    const int old_item = a[item_index];

    // Don't allow integer underflow.
    size_t fade = SIZE_MAX;
    do {
      // Division by zero is impossible here.
      a[item_index] = old_item - rand() % fade;
      fade /= 2;
    } while (a[item_index] > old_item);
    Heap::restore_heap_after_item_decrease(a.begin(), a.begin() + item_index,
        a.end());
    assert(Heap::is_heap(a.begin(), a.end()));
  }

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_remove_from_heap(const size_t n)
{
  cout << "    test_remove_from_heap(n=" << n << ") ";

  IntContainer a;
  init_array(a, n);

  Heap::make_heap(a.begin(), a.end());
  for (size_t i = 0; i < n; ++i) {
    const size_t item_index = rand() % (n - i);
    const int item = a[item_index];
    Heap::remove_from_heap(a.begin(), a.begin() + item_index, a.end() - i);
    assert(Heap::is_heap(a.begin(), a.end() - i - 1));
    assert(item == *(a.end() - i - 1));
  }

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_heapsort(const size_t n)
{
  typedef galgorithm<Heap> algorithm;

  cout << "    test_heapsort(n=" << n << ") ";

  IntContainer a;

  // Verify ascending sorting with default less_comparer.
  init_array(a, n);
  algorithm::heapsort(a.begin(), a.end());
  assert_sorted_asc(a.begin(), a.end());

  // Verify descending sorting with custom less_comparer.
  init_array(a, n);
  algorithm::heapsort(a.begin(), a.end(), less_comparer_desc);
  assert_sorted_desc(a.begin(), a.end());

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_partial_sort(const size_t n)
{
  typedef galgorithm<Heap> algorithm;
  typedef typename IntContainer::iterator iterator;

  cout << "    test_partial_sort(n=" << n << ") ";

  IntContainer a;

  // Check 0-items partial sort.
  init_array(a, n);
  algorithm::partial_sort(a.begin(), a.begin(), a.end());

  // Check 1-item partial sort.
  if (n > 0) {
    init_array(a, n);
    algorithm::partial_sort(a.begin(), a.begin() + 1, a.end());
    assert(min_element(a.begin(), a.end()) == a.begin());
  }

  // Check 2-items partial sort.
  if (n > 1) {
    init_array(a, n);
    algorithm::partial_sort(a.begin(), a.begin() + 2, a.end());
    assert_sorted_asc(a.begin(), a.begin() + 2);
    assert(min_element(a.begin() + 1, a.end()) == a.begin() + 1);
  }

  // Check n-items partial sort.
  init_array(a, n);
  algorithm::partial_sort(a.begin(), a.end(), a.end());
  assert_sorted_asc(a.begin(), a.end());

  // Check (n-1)-items partial sort.
  if (n > 0) {
    init_array(a, n);
    algorithm::partial_sort(a.begin(), a.end() - 1, a.end());
    assert_sorted_asc(a.begin(), a.end());
  }

  // Check (n-2)-items partial sort.
  if (n > 2) {
    init_array(a, n);
    algorithm::partial_sort(a.begin(), a.end() - 2, a.end());
    assert_sorted_asc(a.begin(), a.end() - 2);
    assert(min_element(a.end() - 3, a.end()) == a.end() - 3);
  }

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_nway_merge(const size_t n)
{
  typedef galgorithm<Heap> algorithm;
  typedef typename IntContainer::iterator iterator;

  cout << "    test_nway_merge(n=" << n << ") ";

  IntContainer a, b;
  vector<pair<iterator, iterator> > input_ranges;

  // Check 1-way merge.
  init_array(a, n);
  b.clear();
  input_ranges.clear();
  algorithm::heapsort(a.begin(), a.end());
  input_ranges.push_back(pair<iterator, iterator>(a.begin(), a.end()));
  algorithm::nway_merge(input_ranges.begin(), input_ranges.end(),
      back_inserter(b));
  assert_sorted_asc(b.begin(), b.end());

  // Check 2-way merge.
  if (n > 1) {
    init_array(a, n);
    b.clear();
    input_ranges.clear();
    const iterator middle = a.begin() + n / 2;
    algorithm::heapsort(a.begin(), middle);
    algorithm::heapsort(middle, a.end());
    input_ranges.push_back(pair<iterator, iterator>(a.begin(), middle));
    input_ranges.push_back(pair<iterator, iterator>(middle, a.end()));
    algorithm::nway_merge(input_ranges.begin(), input_ranges.end(),
        back_inserter(b));
    assert_sorted_asc(b.begin(), b.end());
  }

  // Check n-way merge with n sorted lists each containing exactly one item.
  init_array(a, n);
  b.clear();
  input_ranges.clear();
  for (size_t i = 0; i < n; ++i) {
    input_ranges.push_back(pair<iterator, iterator>(a.begin() + i,
        a.begin() + (i + 1)));
  }
  algorithm::nway_merge(input_ranges.begin(), input_ranges.end(),
      back_inserter(b));
  assert_sorted_asc(b.begin(), b.end());


  cout << "OK" << endl;
}

template <class T>
void small_range_sorter(T *const first, T *const last,
    bool (&less_comparer)(const T &, const T &))
{
  galgorithm<gheap<2, 1> >::heapsort(first, last, less_comparer);
}

template <class Heap, class IntContainer>
void test_nway_mergesort(const size_t n)
{
  typedef galgorithm<Heap> algorithm;
  typedef typename IntContainer::value_type value_type;

  cout << "    test_nway_mergesort(n=" << n << ") ";

  IntContainer a;

  // Verify n-way mergesort with default settings.
  init_array(a, n);
  algorithm::nway_mergesort(a.begin(), a.end());
  assert_sorted_asc(a.begin(), a.end());

  // Verify n-way mergesort with custom less_comparer.
  init_array(a, n);
  algorithm::nway_mergesort(a.begin(), a.end(), less_comparer_desc);
  assert_sorted_desc(a.begin(), a.end());

  // Verify n-way mergesort with custom small_range_sorter.
  init_array(a, n);
  algorithm::nway_mergesort(a.begin(), a.end(), less_comparer_desc,
      small_range_sorter<value_type>);
  assert_sorted_desc(a.begin(), a.end());

  // Verify n-way mergesort with custom small_range_size.
  init_array(a, n);
  algorithm::nway_mergesort(a.begin(), a.end(), less_comparer_desc,
      small_range_sorter<value_type>, 1);
  assert_sorted_desc(a.begin(), a.end());

  // Verify n-way mergesort with custom subranges_count.
  init_array(a, n);
  algorithm::nway_mergesort(a.begin(), a.end(), less_comparer_desc,
      small_range_sorter<value_type>, 2, 3);
  assert_sorted_desc(a.begin(), a.end());

  cout << "OK" << endl;
}

template <class Heap, class IntContainer>
void test_priority_queue(const size_t n)
{
  typedef typename IntContainer::value_type value_type;
  typedef gpriority_queue<Heap, value_type, IntContainer> priority_queue;

  cout << "    test_priority_queue(n=" << n << ") ";

  // Verify default constructor.
  priority_queue q_empty;
  assert(q_empty.empty());
  assert(q_empty.size() == 0);

  // Verify non-empty priority queue.
  IntContainer a;
  init_array(a, n);
  priority_queue q(a.begin(), a.end());
  assert(!q.empty());
  assert(q.size() == n);

  // Verify swap().
  q.swap(q_empty);
  assert(q.empty());
  assert(!q_empty.empty());
  assert(q_empty.size() == n);
  swap(q, q_empty);
  assert(!q.empty());
  assert(q.size() == n);
  assert(q_empty.empty());

  // Pop all items from the priority queue.
  int max_item = q.top();
  for (size_t i = 1; i < n; ++i) {
    q.pop();
    assert(q.size() == n - i);
    assert(q.top() <= max_item);
    max_item = q.top();
  }
  assert(q.top() <= max_item);
  q.pop();
  assert(q.empty());

  // Push items to priority queue.
  for (size_t i = 0; i < n; ++i) {
    q.push(rand());
    assert(q.size() == i + 1);
  }

  // Interleave pushing and popping items in priority queue.
  max_item = q.top();
  for (size_t i = 1; i < n; ++i) {
    q.pop();
    assert(q.top() <= max_item);
    const int tmp = rand();
    if (tmp > max_item) {
      max_item = tmp;
    }
    q.push(tmp);
  }
  assert(q.size() == n);

  cout << "OK" << endl;
}

template <class Func>
void test_func(const Func &func)
{
  for (size_t i = 1; i < 12; ++i) {
    func(i);
  }
  func(1001);
}

template <size_t Fanout, size_t PageChunks, class IntContainer>
void test_all()
{
  cout << "  test_all(Fanout=" << Fanout << ", PageChunks=" << PageChunks <<
      ") start" << endl;

  typedef gheap<Fanout, PageChunks> heap;

  // Verify parent-child calculations for indexes close to zero and
  // indexes close to SIZE_MAX.
  static const size_t n = 1000000;
  test_parent_child<heap>(1, n);
  test_parent_child<heap>(SIZE_MAX - n, n);

  test_func(test_is_heap<heap, IntContainer>);
  test_func(test_make_heap<heap, IntContainer>);
  test_func(test_sort_heap<heap, IntContainer>);
  test_func(test_push_heap<heap, IntContainer>);
  test_func(test_pop_heap<heap, IntContainer>);
  test_func(test_swap_max_item<heap, IntContainer>);
  test_func(test_restore_heap_after_item_increase<heap, IntContainer>);
  test_func(test_restore_heap_after_item_decrease<heap, IntContainer>);
  test_func(test_remove_from_heap<heap, IntContainer>);
  test_func(test_heapsort<heap, IntContainer>);
  test_func(test_partial_sort<heap, IntContainer>);
  test_func(test_nway_merge<heap, IntContainer>);
  test_func(test_nway_mergesort<heap, IntContainer>);
  test_func(test_priority_queue<heap, IntContainer>);

  cout << "  test_all(Fanout=" << Fanout << ", PageChunks=" << PageChunks <<
      ") OK" << endl;
}

template <class IntContainer>
void main_test(const char *const container_name)
{
  cout << "main_test(" << container_name << ") start" << endl;

  test_all<1, 1, IntContainer>();
  test_all<2, 1, IntContainer>();
  test_all<3, 1, IntContainer>();
  test_all<4, 1, IntContainer>();
  test_all<101, 1, IntContainer>();

  test_all<1, 2, IntContainer>();
  test_all<2, 2, IntContainer>();
  test_all<3, 2, IntContainer>();
  test_all<4, 2, IntContainer>();
  test_all<101, 2, IntContainer>();

  test_all<1, 3, IntContainer>();
  test_all<2, 3, IntContainer>();
  test_all<3, 3, IntContainer>();
  test_all<4, 3, IntContainer>();
  test_all<101, 3, IntContainer>();

  test_all<1, 4, IntContainer>();
  test_all<2, 4, IntContainer>();
  test_all<3, 4, IntContainer>();
  test_all<4, 4, IntContainer>();
  test_all<101, 4, IntContainer>();

  test_all<1, 101, IntContainer>();
  test_all<2, 101, IntContainer>();
  test_all<3, 101, IntContainer>();
  test_all<4, 101, IntContainer>();
  test_all<101, 101, IntContainer>();

  cout << "main_test(" << container_name << ") OK" << endl;
}

}  // End of anonymous namespace.

int main()
{
  srand(0);
  main_test<vector<int> >("vector");
  main_test<deque<int> >("deque");
}
