#ifndef GALGORITHM_H
#define GALGORITHM_H

// Generalized algorithms based on Heap.
//
// Pass -DGHEAP_CPP11 to compiler for enabling C++11 optimization,
// otherwise C++03 optimization will be enabled.
//
// Don't forget passing -DNDEBUG option to the compiler when creating optimized
// builds. This significantly speeds up the code by removing debug assertions.
//
// Author: Aliaksandr Valialkin <valyala@gmail.com>.

#include "gheap.hpp"

#include <cassert>     // for assert
#include <cstddef>     // for size_t, ptrdiff_t
#include <iterator>    // for std::iterator_traits, std::advance()
#include <memory>      // for std::*_temporary_buffer()
#include <new>         // for std::bad_alloc
#include <utility>     // for std::move(), std::swap(), std::*pair

template <class Heap = gheap<> >
class galgorithm
{
private:

  // Standard less comparer.
  template <class InputIterator>
  static bool _std_less_comparer(
      const typename std::iterator_traits<InputIterator>::value_type &a,
      const typename std::iterator_traits<InputIterator>::value_type &b)
  {
    return (a < b);
  }

  // Less comparer for nway_merge().
  template <class LessComparer>
  class _nway_merge_less_comparer
  {
  private:
    const LessComparer &_less_comparer;

  public:
    _nway_merge_less_comparer(const LessComparer &less_comparer) :
        _less_comparer(less_comparer) {}

    template <class InputIterator>
    bool operator() (
      const std::pair<InputIterator, InputIterator> &input_range_a,
      const std::pair<InputIterator, InputIterator> &input_range_b) const
    {
      assert(input_range_a.first != input_range_a.second);
      assert(input_range_b.first != input_range_b.second);

      return _less_comparer(*(input_range_b.first), *(input_range_a.first));
    }
  };

  // RAII wrapper around temporary buffer.
  // It is used by nway_mergesort() for allocation of temporary memory.
  template <class T>
  class _temporary_buffer
  {
  private:
    T *_ptr;

  public:
    _temporary_buffer(const size_t size)
    {
      const std::pair<T *, ptrdiff_t> tmp_buf =
          std::get_temporary_buffer<T>(size);
      _ptr = tmp_buf.first;
      assert(tmp_buf.second >= 0);
      if (_ptr == 0 || (size_t)tmp_buf.second < size) {
        // It is OK passing (_ptr == 0) to std::return_temporary_buffer().
        std::return_temporary_buffer(_ptr);
        throw std::bad_alloc();
      }
    }

    ~_temporary_buffer()
    {
      std::return_temporary_buffer(_ptr);
      _ptr = 0;
    }

    T *get_ptr() const
    {
      return _ptr;
    }
  };

  // Standard sorter for small ranges.
  template <class T, class LessComparer>
  static void _std_small_range_sorter(T *const first, T *const last,
      const LessComparer &less_comparer)
  {
    assert(first <= last);

    // Insertion sort implementation.
    // See http://en.wikipedia.org/wiki/Insertion_sort .

    for (T *it = first + 1; it != last; ++it) {
#ifdef GHEAP_CPP11
      T tmp = std::move(*it);
      T *hole = it;
      while (hole != first && less_comparer(tmp, *(hole - 1))) {
        *hole = std::move(*(hole - 1));
        --hole;
      }
      *hole = std::move(tmp);
#else
      T *hole = it;
      while (hole != first && less_comparer(*hole, *(hole - 1))) {
        std::swap(*hole, *(hole - 1));
        --hole;
      }
#endif
    }
  }

  // Moves items from [first ... last) to uninitialized memory pointed
  // by result.
  template <class InputIterator, class ForwardIterator>
  static ForwardIterator _uninitialized_move_items(const InputIterator &first,
      const InputIterator &last, const ForwardIterator &result)
  {
#ifdef GHEAP_CPP11
    // libstdc++ is missing std::uninitialized_move(), so wrap
    // the input iterator into std::make_move_iterator().
    // See http://gcc.gnu.org/bugzilla/show_bug.cgi?id=51981 .
    return std::uninitialized_copy(std::make_move_iterator(first),
        std::make_move_iterator(last), result);
#else
    return std::uninitialized_copy(first, last, result);
#endif
  }

  // Moves items from [first ... last) to result.
  template <class InputIterator, class OutputIterator>
  static OutputIterator _move_items(const InputIterator &first,
      const InputIterator &last, const OutputIterator &result)
  {
#ifdef GHEAP_CPP11
    return std::move(first, last, result);
#else
    return std::copy(first, last, result);
#endif
  }

  // Auxiliary function for nway_mergesort().
  // Splits the range [first ... last) into subranges with small_range_size size
  // each (except the last subrange, which may contain less
  // than small_range_size items) and sort each of these subranges using
  // small_range_sorter.
  template <class RandomAccessIterator, class LessComparer,
      class SmallRangeSorter>
  static void _sort_subranges(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer,
      const SmallRangeSorter &small_range_sorter,
      const size_t small_range_size)
  {
    assert(first <= last);
    assert(small_range_size > 0);

    const size_t range_size = last - first;

    const RandomAccessIterator it_last = last - range_size % small_range_size;
    RandomAccessIterator it = first;
    while (it != it_last) {
      const RandomAccessIterator it_first = it;
      it += small_range_size;
      small_range_sorter(it_first, it, less_comparer);
    }

    // Sort the last subrange, which contains less than small_range_size items.
    if (it < last) {
      small_range_sorter(it, last, less_comparer);
    }
  }

  // Auxiliary function for nway_mergesort().
  // Merges subranges inside each subrange tuple.
  // Each subrange tuple contains subranges_count subranges, except the last
  // tuple, which may contain less than subranges_count subranges.
  // Each subrange contains subrange_size items, except the last subrange,
  // which may contain less than subrange_size items.
  template <class InputIterator, class OutputIterator, class LessComparer>
  static void _merge_subrange_tuples(const InputIterator &first,
      const InputIterator &last, const OutputIterator &result,
      const LessComparer &less_comparer,
      std::pair<InputIterator, InputIterator> *const subranges,
      const size_t subranges_count, const size_t subrange_size)
  {
    assert(first <= last);
    assert(subranges_count > 1);
    assert(subrange_size > 0);

    typedef std::pair<InputIterator, InputIterator> subrange_t;

    const size_t range_size = last - first;
    InputIterator it = first;
    OutputIterator output = result;

    // Merge full subrange tuples. Each full subrange tuple contains
    // subranges_count full subranges. Each full subrange contains
    // subrange_size items.
    if (subrange_size <= range_size / subranges_count) {
      const size_t tuple_size = subrange_size * subranges_count;
      const InputIterator it_last = last - range_size % tuple_size;

      while (it != it_last) {
        for (size_t i = 0; i < subranges_count; ++i) {
          const InputIterator it_first = it;
          std::advance(it, subrange_size);
          new (subranges + i) subrange_t(it_first, it);
        }

        output = nway_merge(subranges, subranges + subranges_count, output,
            less_comparer);

        for (size_t i = 0; i < subranges_count; ++i) {
          subranges[i].~subrange_t();
        }
      }
    }

    // Merge tail subrange tuple. Tail subrange tuple contains less than
    // subranges_count full subranges. It also may contain tail subrange
    // with less than subrange_size items.
    const size_t tail_tuple_size = last - it;
    if (tail_tuple_size > 0) {
      const size_t full_subranges_count = tail_tuple_size / subrange_size;
      assert(full_subranges_count < subranges_count);
      size_t tail_subranges_count = full_subranges_count;

      for (size_t i = 0; i < full_subranges_count; ++i) {
        const InputIterator it_first = it;
        std::advance(it, subrange_size);
        new (subranges + i) subrange_t(it_first, it);
      }

      if (it < last) {
        new (subranges + full_subranges_count) subrange_t(it, last);
        ++tail_subranges_count;
      }

      nway_merge(subranges, subranges + tail_subranges_count, output,
          less_comparer);

      for (size_t i = 0; i < tail_subranges_count; ++i) {
        subranges[i].~subrange_t();
      }
    }
  }

public:

  // Sorts items [first ... middle) in ascending order.
  // Uses less_comparer for items' comparison.
  //
  // std::swap() specialization and/or move constructor/assignment
  // may be provided for non-trivial items as a speed optimization.
  template <class RandomAccessIterator, class LessComparer>
  static void heapsort(const RandomAccessIterator &first,
      const RandomAccessIterator &last, const LessComparer &less_comparer)
  {
    Heap::make_heap(first, last, less_comparer);
    Heap::sort_heap(first, last, less_comparer);
  }

  // Sorts items [first ... middle) in ascending order.
  // Uses operator< for items' comparison.
  //
  // std::swap() specialization and/or move constructor/assignment
  // may be provided for non-trivial items as a speed optimization.
  template <class RandomAccessIterator>
  static void heapsort(const RandomAccessIterator &first,
      const RandomAccessIterator &last)
  {
    heapsort(first, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Performs partial sort, so [first ... middle) will contain items sorted
  // in ascending order, which are smaller than the rest of items
  // in the [middle ... last).
  // Uses less_comparer for items' comparison.
  //
  // std::swap() specialization and/or move constructor/assignment
  // may be provided for non-trivial items as a speed optimization.
  template <class RandomAccessIterator, class LessComparer>
  static void partial_sort(const RandomAccessIterator &first,
      const RandomAccessIterator &middle, const RandomAccessIterator &last,
      const LessComparer &less_comparer)
  {
    assert(first <= middle);
    assert(middle <= last);

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        value_type;

    const size_t sorted_range_size = middle - first;
    if (sorted_range_size > 0) {
      Heap::make_heap(first, middle, less_comparer);

      const size_t heap_size = last - first;
      for (size_t i = sorted_range_size; i < heap_size; ++i) {
        if (less_comparer(first[i], first[0])) {
          Heap::swap_max_item(first, middle, first[i], less_comparer);
        }
      }

      Heap::sort_heap(first, middle, less_comparer);
    }
  }

  // Performs partial sort, so [first ... middle) will contain items sorted
  // in ascending order, which are smaller than the rest of items
  // in the [middle ... last).
  // Uses operator< for items' comparison.
  //
  // std::swap() specialization and/or move constructor/assignment
  // may be provided for non-trivial items as a speed optimization.
  template <class RandomAccessIterator>
  static void partial_sort(const RandomAccessIterator &first,
      const RandomAccessIterator &middle, const RandomAccessIterator &last)
  {
    partial_sort(first, middle, last, _std_less_comparer<RandomAccessIterator>);
  }

  // Performs N-way merging of the given input ranges into the result sorted
  // in ascending order, using less_comparer for items' comparison.
  //
  // Each input range must hold non-zero number of items sorted
  // in ascending order. Each range is defined as a std::pair containing
  // input iterators, where the first iterator points to the beginning
  // of the range, while the second iterator points to the end of the range.
  //
  // Returns an iterator pointing to the next element in the result after
  // the merge.
  //
  // std::swap() specialization and/or move constructor/assignment
  // may be provided for non-trivial input ranges as a speed optimization.
  //
  // As a side effect the function shuffles input ranges between
  // [input_ranges_first ... input_ranges_last) and sets the first iterator
  // for each input range to the end of the corresponding range.
  //
  // Also values from input ranges may become obsolete after
  // the funtion return, because they can be moved to the result via
  // move construction or move assignment in C++11.
  template <class RandomAccessIterator, class OutputIterator,
      class LessComparer>
  static OutputIterator nway_merge(
      const RandomAccessIterator &input_ranges_first,
      const RandomAccessIterator &input_ranges_last,
      const OutputIterator &result, const LessComparer &less_comparer)
  {
    assert(input_ranges_first < input_ranges_last);

    typedef typename std::iterator_traits<RandomAccessIterator>::value_type
        input_range_iterator;

    const RandomAccessIterator &first = input_ranges_first;
    RandomAccessIterator last = input_ranges_last;
    OutputIterator output = result;

    const _nway_merge_less_comparer<LessComparer> less(less_comparer);

    Heap::make_heap(first, last, less);
    while (true) {
      input_range_iterator &input_range = first[0];
      assert(input_range.first != input_range.second);
#ifdef GHEAP_CPP11
      *output = std::move(*(input_range.first));
#else
      *output = *(input_range.first);
#endif
      ++output;
      ++(input_range.first);
      if (input_range.first == input_range.second) {
        --last;
        if (first == last) {
          break;
        }
        std::swap(input_range, *last);
      }
      Heap::restore_heap_after_item_decrease(first, first, last, less);
    }

    return output;
  }

  // Performs N-way merging of the given input ranges into the result sorted
  // in ascending order, using operator< for items' comparison.
  //
  // Each input range must hold non-zero number of items sorted
  // in ascending order. Each range is defined as a std::pair containing
  // input iterators, where the first iterator points to the beginning
  // of the range, while the second iterator points to the end of the range.
  //
  // Returns an iterator pointing to the next element in the result after
  // the merge.
  //
  // std::swap() specialization and/or move constructor/assignment
  // may be provided for non-trivial input ranges as a speed optimization.
  //
  // As a side effect the function shuffles input ranges between
  // [input_ranges_first ... input_ranges_last) and sets the first iterator
  // for each input range to the end of the corresponding range.
  //
  // Also values from input ranges may become obsolete after
  // the function return, because they can be moved to the result via
  // move construction or move assignment in C++11.
  template <class RandomAccessIterator, class OutputIterator>
  static OutputIterator nway_merge(
      const RandomAccessIterator &input_ranges_first,
      const RandomAccessIterator &input_ranges_last,
      const OutputIterator &result)
  {
    typedef typename std::iterator_traits<RandomAccessIterator
        >::value_type::first_type input_iterator;

    return nway_merge(input_ranges_first, input_ranges_last, result,
        _std_less_comparer<input_iterator>);
  }

  // Performs n-way mergesort.
  //
  // Uses:
  // - less_comparer for items' comparison.
  // - small_range_sorter for sorting ranges containing no more
  //   than small_range_size items.
  //
  // Splits the input range into subranges with small_range_size size,
  // sorts them using small_range_sorter and then merges them back
  // using n-way merge with n = subranges_count.
  //
  // items_tmp_buf must point to an uninitialized memory, which can hold
  // up to (last - first) items.
  //
  // May raise std::bad_alloc on unsuccessful attempt to allocate temporary
  // space for auxiliary structures required for n-way merging.
  template <class ForwardIterator, class LessComparer, class SmallRangeSorter>
  static void nway_mergesort(const ForwardIterator &first,
      const ForwardIterator &last, const LessComparer &less_comparer,
      const SmallRangeSorter &small_range_sorter,
      const size_t small_range_size, const size_t subranges_count,
      typename std::iterator_traits<ForwardIterator>::value_type
          *const items_tmp_buf)
  {
    assert(first <= last);
    assert(small_range_size > 0);
    assert(subranges_count > 1);

    typedef typename std::iterator_traits<ForwardIterator>::value_type
        value_type;
    typedef std::pair<ForwardIterator, ForwardIterator> subrange1_t;
    typedef std::pair<value_type *, value_type *> subrange2_t;

    const size_t range_size = last - first;

    // Preparation: Move items to a temporary buffer.
    _uninitialized_move_items(first, last, items_tmp_buf);

    // Step 1: split the range into subranges with small_range_size size each
    // (except the last subrange, which may contain less than small_range_size
    // items) and sort each of these subranges using small_range_sorter.
    _sort_subranges(items_tmp_buf, items_tmp_buf + range_size,
        less_comparer, small_range_sorter, small_range_size);

    // Step 2: Merge subranges sorted at the previous step using n-way merge.
    const _temporary_buffer<subrange1_t> subranges_tmp_buf1(subranges_count);
    const _temporary_buffer<subrange2_t> subranges_tmp_buf2(subranges_count);

    size_t subrange_size = small_range_size;
    for (;;) {
      // First pass: merge items from the temporary buffer
      // to the original location.
      _merge_subrange_tuples(
          items_tmp_buf, items_tmp_buf + range_size, first, less_comparer,
          subranges_tmp_buf2.get_ptr(), subranges_count, subrange_size);

      if (subrange_size > range_size / subranges_count) {
        break;
      }
      subrange_size *= subranges_count;

      // Second pass: merge items from the original location
      // to the temporary buffer.
      _merge_subrange_tuples(
          first, last, items_tmp_buf, less_comparer,
          subranges_tmp_buf1.get_ptr(), subranges_count, subrange_size);

      if (subrange_size > range_size / subranges_count) {
        // Move items from the temporary buffer to the original location.
        _move_items(items_tmp_buf, items_tmp_buf + range_size, first);
        break;
      }
      subrange_size *= subranges_count;
    }

    // Destroy dummy items in the temporary buffer.
    for (size_t i = 0; i < range_size; ++i) {
      items_tmp_buf[i].~value_type();
    }
  }

  // Performs n-way mergesort.
  //
  // Uses:
  // - less_comparer for items' comparison.
  // - small_range_sorter for sorting ranges containing no more
  //   than small_range_size items.
  //
  // Splits the input range into subranges with small_range_size size,
  // sorts them using small_range_sorter and then merges them back
  // using n-way merge with n = subranges_count.
  //
  // May raise std::bad_alloc on unsuccessful attempt to allocate a temporary
  // buffer for (last - first) items.
  template <class ForwardIterator, class LessComparer, class SmallRangeSorter>
  static void nway_mergesort(const ForwardIterator &first,
      const ForwardIterator &last, const LessComparer &less_comparer,
      const SmallRangeSorter &small_range_sorter,
      const size_t small_range_size = 32, const size_t subranges_count = 15)
  {
    assert(first <= last);

    typedef typename std::iterator_traits<ForwardIterator>::value_type
        value_type;

    const size_t range_size = last - first;

    const _temporary_buffer<value_type> tmp_buf(range_size);
    value_type *const items_tmp_buf = tmp_buf.get_ptr();

    nway_mergesort(first, last, less_comparer, small_range_sorter,
        small_range_size, subranges_count, items_tmp_buf);
  }

  // Performs n-way mergesort.
  //
  // Uses less_comparer for items' comparison.
  //
  // May raise std::bad_alloc on unsuccessful attempt to allocate a temporary
  // buffer for (last - first) items.
  template <class ForwardIterator, class LessComparer>
  static void nway_mergesort(const ForwardIterator &first,
      const ForwardIterator &last, const LessComparer &less_comparer)
  {
    typedef typename std::iterator_traits<ForwardIterator>::value_type
        value_type;

    nway_mergesort(first, last, less_comparer,
        _std_small_range_sorter<value_type, LessComparer>);
  }

  // Performs n-way mergesort.
  //
  // Uses operator< for items' comparison.
  //
  // May raise std::bad_alloc on unsuccessful attempt to allocate a temporary
  // buffer for (last - first) items.
  template <class ForwardIterator>
  static void nway_mergesort(const ForwardIterator &first,
      const ForwardIterator &last)
  {
    nway_mergesort(first, last, _std_less_comparer<ForwardIterator>);
  }
};
#endif
