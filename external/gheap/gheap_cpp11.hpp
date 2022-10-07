#ifndef GHEAP_H
#define GHEAP_H

// Generalized heap implementation for C++11.
// The implementation requires the following C++11 features:
// - <cstdint> must contain SIZE_MAX definition.
// - std::move() support. The implementation relies on move constructors
//   and move assignment operators, so define them for classes with expensive
//   copy constructors and copy assignment operators.
// See http://en.wikipedia.org/wiki/C%2B%2B11 for details.
//
// Use gheap_cpp03.hpp instead if your compiler doesn't support these features.
// The implementation for C++11 is usually faster than the implementation
// for C++03.
//
// Don't forget passing -DNDEBUG option to the compiler when creating optimized
// builds. This significantly speeds up gheap code by removing debug assertions.
//
// Author: Aliaksandr Valialkin <valyala@gmail.com>.

#include <cassert>     // for assert
#include <cstddef>     // for size_t
#include <cstdint>     // for SIZE_MAX
#include <iterator>    // for std::iterator_traits
#include <utility>     // for std::move()

template <size_t Fanout = 2, size_t PageChunks = 1>
class gheap
{
public:

  static const size_t FANOUT = Fanout;
  static const size_t PAGE_CHUNKS = PageChunks;
  static const size_t PAGE_SIZE = Fanout * PageChunks;

  // Returns parent index for the given child index.
  // Child index must be greater than 0.
  // Returns 0 if the parent is root.
  static size_t get_parent_index(size_t u)
  {
    assert(u > 0);

    --u;
    if (PageChunks == 1) {
      return u / Fanout;
    }

    if (u < Fanout) {
      // Parent is root.
      return 0;
    }

    assert(PageChunks <= SIZE_MAX / Fanout);
    const size_t page_size = Fanout * PageChunks;
    size_t v = u % page_size;
    if (v >= Fanout) {
      // Fast path. Parent is on the same page as the child.
      return u - v + v / Fanout;
    }

    // Slow path. Parent is on another page.
    v = u / page_size - 1;
    const size_t page_leaves = (Fanout - 1) * PageChunks + 1;
    u = v / page_leaves + 1;
    return u * page_size + v % page_leaves - page_leaves + 1;
  }

  // Returns the index of the first child for the given parent index.
  // Parent index must be less than SIZE_MAX.
  // Returns SIZE_MAX if the index of the first child for the given parent
  // cannot fit size_t.
  static size_t get_child_index(size_t u)
  {
    assert(u < SIZE_MAX);

    if (PageChunks == 1) {
      if (u > (SIZE_MAX - 1) / Fanout) {
        // Child overflow.
        return SIZE_MAX;
      }
      return u * Fanout + 1;
    }

    if (u == 0) {
      // Root's child is always 1.
      return 1;
    }

    assert(PageChunks <= SIZE_MAX / Fanout);
    const size_t page_size = Fanout * PageChunks;
    --u;
    size_t v = u % page_size + 1;
    if (v < page_size / Fanout) {
      // Fast path. Child is on the same page as the parent.
      v *= Fanout - 1;
      if (u > SIZE_MAX - 2 - v) {
        // Child overflow.
        return SIZE_MAX;
      }
      return u + v + 2;
    }

    // Slow path. Child is on another page.
    const size_t page_leaves = (Fanout - 1) * PageChunks + 1;
    v += (u / page_size + 1) * page_leaves - page_size;
    if (v > (SIZE_MAX - 1) / page_size) {
      // Child overflow.
      return SIZE_MAX;
    }
    return v * page_size + 1;
  }

private:

  // moves the value from src to dst.
  template <class T>
  static void _move(T &dst, const T &src)
  {
    // src is const for optimization purposes only. This hints compiler
    // that the value referenced by src cannot be modified by somebody else,
    // so it is safe reading the value from a register instead of reading it
    // from slow memory on each read access.
    //
    // Of course, this optimization works only for values small enough to fit
    // CPU registers.
    dst = std::move(const_cast<T &>(src));
  }

  // Sifts the item up in the given sub-heap with the given root_index
  // starting from the hole_index.
  template <class RandomAccessIterator, class LessComparer>
  static void _sift_up(const RandomAccessIterator &first,
      const LessComparer &less_comparer,
      const size_t root_index, size_t hole_index,
      const typename std::iterator_traits<RandomAccessIterator>::value_type
          &item)
  {
    assert(hole_index >= root_index);

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    while (hole_index > root_index) {
      const size_t parent_index = get_parent_index(hole_index);
      assert(parent_index >= root_index);
      const value_type &parent = first[parent_index];
      if (!less_comparer(parent, item)) {
        break;
      }
      _move(first[hole_index], parent);
      hole_index = parent_index;
    }
    _move(first[hole_index], item);
  }

  // Moves the max child into the given hole and returns index
  // of the new hole.
  template <class RandomAccessIterator, class LessComparer>
  static size_t _move_up_max_child(const RandomAccessIterator &first,
      const LessComparer &less_comparer, const size_t children_count,
      const size_t hole_index, const size_t child_index)
  {
    assert(children_count > 0);
    assert(children_count <= Fanout);
    assert(child_index == get_child_index(hole_index));

    size_t max_child_index = child_index;
    for (size_t i = 1; i < children_count; ++i) {
      if (!less_comparer(first[child_index + i], first[max_child_index])) {
        max_child_index = child_index + i;
      }
    }
    _move(first[hole_index], first[max_child_index]);
    return max_child_index;
  }

  // Sifts the given item down in the heap of the given size starting
  // from the hole_index.
  template <class RandomAccessIterator, class LessComparer>
  static void _sift_down(const RandomAccessIterator &first,
      const LessComparer &less_comparer,
      const size_t heap_size, size_t hole_index,
      const typename std::iterator_traits<RandomAccessIterator>::value_type
          &item)
  {
    assert(heap_size > 0);
    assert(hole_index < heap_size);

    const size_t root_index = hole_index;
    const size_t last_full_index = heap_size - (heap_size - 1) % Fanout;
    while (true) {
      const size_t child_index = get_child_index(hole_index);
      if (child_index >= last_full_index) {
        if (child_index < heap_size) {
          assert(child_index == last_full_index);
          hole_index = _move_up_max_child(first, less_comparer,
              heap_size - child_index, hole_index, child_index);
        }
        break;
      }
      assert(heap_size - child_index >= Fanout);
      hole_index = _move_up_max_child(first, less_comparer, Fanout,
          hole_index, child_index);
    }
    _sift_up(first, less_comparer, root_index, hole_index, item);
  }

  // Standard less comparer.
  template <class InputIterator>
  static bool _std_less_comparer(
      const typename std::iterator_traits<InputIterator>::value_type &a,
      const typename std::iterator_traits<InputIterator>::value_type &b)
  {
    return (a < b);
  }

  // Pops max item from the heap [first[0] ... first[heap_size-1]]
  // into first[heap_size].
  template <class RandomAccessIterator, class LessComparer>
  static void _pop_max_item(const RandomAccessIterator &first,
      const LessComparer &less_comparer, const size_t heap_size)
  {
    assert(heap_size > 0);

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    value_type tmp = std::move(first[heap_size]);
    _move(first[heap_size], first[0]);
    _sift_down(first, less_comparer, heap_size, 0, tmp);
  }

public:

  // Returns an iterator for the first non-heap item in the range
  // [first ... last) using less_comparer for items' comparison.
  // Returns last if the range contains valid max heap.
  template <class RandomAccessIterator, class LessComparer>
  static RandomAccessIterator is_heap_until(
      const RandomAccessIterator &first, const RandomAccessIterator &last,
      const LessComparer &less_comparer)
  {
    assert(last >= first);

    const size_t heap_size = last - first;
    for (size_t u = 1; u < heap_size; ++u) {
      const size_t v = get_parent_index(u);
      if (less_comparer(first[v], first[u])) {
        return first + u;
      }
    }
    return last;
  }

  // Returns an iterator for the first non-heap item in the range
  // [first ... last) using operator< for items' comparison.
  // Returns last if the range contains valid max heap.
  template <class RandomAccessIterator>
  static RandomAccessIterator is_heap_until(
    const RandomAccessIterator &first, const RandomAccessIterator &last)
  {
    return is_heap_until(first, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Returns true if the range [first ... last) contains valid max heap.
  // Returns false otherwise.
  // Uses less_comparer for items' comparison.
  template <class RandomAccessIterator, class LessComparer>
  static bool is_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    return (is_heap_until(first, last, less_comparer) == last);
  }

  // Returns true if the range [first ... last) contains valid max heap.
  // Returns false otherwise.
  // Uses operator< for items' comparison.
  template <class RandomAccessIterator>
  static bool is_heap(const RandomAccessIterator &first,
    const RandomAccessIterator &last)
  {
    return is_heap(first, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Makes max heap from items [first ... last) using the given less_comparer
  // for items' comparison.
  template <class RandomAccessIterator, class LessComparer>
  static void make_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    assert(last >= first);

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    const size_t heap_size = last - first;
    if (heap_size > 1) {
      // Skip leaf nodes without children. This is easy to do for non-paged
      // heap, i.e. when page_chunks = 1, but it is difficult for paged heaps.
      // So leaf nodes in paged heaps are visited anyway.
      size_t i = (PageChunks == 1) ? ((heap_size - 2) / Fanout) :
          (heap_size - 2);
      do {
        value_type item = std::move(first[i]);
        _sift_down(first, less_comparer, heap_size, i, item);
      } while (i-- > 0);
    }

    assert(is_heap(first, last, less_comparer));
  }

  // Makes max heap from items [first ... last) using operator< for items'
  // comparison.
  template <class RandomAccessIterator>
  static void make_heap(const RandomAccessIterator &first,
    const RandomAccessIterator &last)
  {
    make_heap(first, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Pushes the item *(last - 1) into max heap [first ... last - 1)
  // using the given less_comparer for items' comparison.
  template <class RandomAccessIterator, class LessComparer>
  static void push_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    assert(last > first);
    assert(is_heap(first, last - 1, less_comparer));

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    const size_t heap_size = last - first;
    if (heap_size > 1) {
      const size_t u = heap_size - 1;
      value_type item = std::move(first[u]);
      _sift_up(first, less_comparer, 0, u, item);
    }

    assert(is_heap(first, last, less_comparer));
  }

  // Pushes the item *(last - 1) into max heap [first ... last - 1)
  // using operator< for items' comparison.
  template <class RandomAccessIterator>
  static void push_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    push_heap(first, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Pops the maximum item from max heap [first ... last) into
  // *(last - 1) using the given less_comparer for items' comparison.
  template <class RandomAccessIterator, class LessComparer>
  static void pop_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    assert(last > first);
    assert(is_heap(first, last, less_comparer));

    const size_t heap_size = last - first;
    if (heap_size > 1) {
      _pop_max_item(first, less_comparer, heap_size - 1);
    }

    assert(is_heap(first, last - 1, less_comparer));
  }

  // Pops the maximum item from max heap [first ... last) into
  // *(last - 1) using operator< for items' comparison.
  template <class RandomAccessIterator>
  static void pop_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    pop_heap(first, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Sorts max heap [first ... last) using the given less_comparer
  // for items' comparison.
  // Items are sorted in ascending order.
  template <class RandomAccessIterator, class LessComparer>
  static void sort_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    assert(last >= first);

    const size_t heap_size = last - first;
    for (size_t i = heap_size; i > 1; --i) {
      _pop_max_item(first, less_comparer, i - 1);
    }
  }

  // Sorts max heap [first ... last) using operator< for items' comparison.
  // Items are sorted in ascending order.
  template <class RandomAccessIterator>
  static void sort_heap(const RandomAccessIterator &first,
    const RandomAccessIterator &last)
  {
    sort_heap(first, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Swaps the item outside the heap with the maximum item inside
  // the heap [first ... last) and restores the heap invariant.
  // Uses less_comparer for items' comparisons.
  template <class RandomAccessIterator, class LessComparer>
  static void swap_max_item(const RandomAccessIterator &first,
      const RandomAccessIterator &last,
      typename std::iterator_traits<RandomAccessIterator>::value_type &item,
      const LessComparer &less_comparer)
  {
    assert(first < last);
    assert(is_heap(first, last, less_comparer));

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    const size_t heap_size = last - first;

    value_type tmp = std::move(item);
    _move(item, first[0]);
    _sift_down(first, less_comparer, heap_size, 0, tmp);

    assert(is_heap(first, last, less_comparer));
  }

  // Swaps the item outside the heap with the maximum item inside
  // the heap [first ... last) and restores the heap invariant.
  // Uses operator< for items' comparisons.
  template <class RandomAccessIterator>
  static void swap_max_item(const RandomAccessIterator &first,
      const RandomAccessIterator &last,
      typename std::iterator_traits<RandomAccessIterator>::value_type &item)
  {
    swap_max_item(first, last, item, _std_less_comparer<RandomAccessIterator>);
  }

  // Restores max heap invariant after item's value has been increased,
  // i.e. less_comparer(old_item, new_item) == true.
  template <class RandomAccessIterator, class LessComparer>
  static void restore_heap_after_item_increase(
      const RandomAccessIterator &first, const RandomAccessIterator &item,
      const LessComparer &less_comparer)
  {
    assert(item >= first);
    assert(is_heap(first, item, less_comparer));

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    const size_t hole_index = item - first;
    if (hole_index > 0) {
      value_type tmp = std::move(*item);
      _sift_up(first, less_comparer, 0, hole_index, tmp);
    }

    assert(is_heap(first, item + 1, less_comparer));
  }

  // Restores max heap invariant after item's value has been increased,
  // i.e. old_item < new_item.
  template <class RandomAccessIterator>
  static void restore_heap_after_item_increase(
      const RandomAccessIterator &first, const RandomAccessIterator &item)
  {
    restore_heap_after_item_increase(first, item,
        _std_less_comparer<RandomAccessIterator>);
  }

  // Restores max heap invariant after item's value has been decreased,
  // i.e. less_comparer(new_item, old_item) == true.
  template <class RandomAccessIterator, class LessComparer>
  static void restore_heap_after_item_decrease(
      const RandomAccessIterator &first, const RandomAccessIterator &item,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    assert(last > first);
    assert(item >= first);
    assert(item < last);
    assert(is_heap(first, item, less_comparer));

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    const size_t heap_size = last - first;
    const size_t hole_index = item - first;
    value_type tmp = std::move(*item);
    _sift_down(first, less_comparer, heap_size, hole_index, tmp);

    assert(is_heap(first, last, less_comparer));
  }

  // Restores max heap invariant after item's value has been decreased,
  // i.e. new_item < old_item.
  template <class RandomAccessIterator>
  static void restore_heap_after_item_decrease(
      const RandomAccessIterator &first, const RandomAccessIterator &item,
      const RandomAccessIterator &last)
  {
    restore_heap_after_item_decrease(first, item, last,
        _std_less_comparer<RandomAccessIterator>);
  }

  // Removes the given item from the heap and puts it into *(last - 1).
  // less_comparer is used for items' comparison.
  template <class RandomAccessIterator, class LessComparer>
  static void remove_from_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &item, const RandomAccessIterator &last,
      const LessComparer &less_comparer)
  {
    assert(last > first);
    assert(item >= first);
    assert(item < last);
    assert(is_heap(first, last, less_comparer));

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    const size_t new_heap_size = last - first - 1;
    const size_t hole_index = item - first;
    if (hole_index < new_heap_size) {
      value_type tmp = std::move(first[new_heap_size]);
      _move(first[new_heap_size], *item);
      if (less_comparer(tmp, first[new_heap_size])) {
        _sift_down(first, less_comparer, new_heap_size, hole_index, tmp);
      }
      else {
        _sift_up(first, less_comparer, 0, hole_index, tmp);
      }
    }

    assert(is_heap(first, last - 1, less_comparer));
  }

  // Removes the given item from the heap and puts it into *(last - 1).
  // operator< is used for items' comparison.
  template <class RandomAccessIterator>
  static void remove_from_heap(const RandomAccessIterator &first,
      const RandomAccessIterator &item, const RandomAccessIterator &last)
  {
    remove_from_heap(first, item, last,
        _std_less_comparer<RandomAccessIterator>);
  }
};
#endif
