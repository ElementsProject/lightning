// Priority queue on top of Heap.
//
// Pass -DGHEAP_CPP11 to compiler for enabling C++11 optimization,
// otherwise C++03 optimization will be enabled.

#include <cassert>
#include <functional>   // for std::less
#include <vector>

#ifdef GHEAP_CPP11
#  include <utility>    // for std::swap(), std::move(), std::forward()
#else
#  include <algorithm>  // for std::swap()
#endif

template <class Heap, class T, class Container = std::vector<T>,
    class LessComparer = std::less<typename Container::value_type> >
struct gpriority_queue
{
public:

  typedef Container container_type;
  typedef typename Container::value_type value_type;
  typedef typename Container::size_type size_type;
  typedef typename Container::reference reference;
  typedef typename Container::const_reference const_reference;

  LessComparer comp;
  Container c;

private:

  void _make_heap()
  {
    Heap::make_heap(c.begin(), c.end(), comp);
  }

  void _push_heap()
  {
    Heap::push_heap(c.begin(), c.end(), comp);
  }

  void _pop_heap()
  {
    Heap::pop_heap(c.begin(), c.end(), comp);
  }

public:
  explicit gpriority_queue(
      const LessComparer &less_comparer = LessComparer(),
      const Container &container = Container()) :
          comp(less_comparer), c(container)
  {
    _make_heap();
  }

  template <class InputIterator>
  gpriority_queue(const InputIterator &first, const InputIterator &last,
      const LessComparer &less_comparer = LessComparer(),
      const Container &container = Container()) :
          comp(less_comparer), c(container)
  {
    c.insert(c.end(), first, last);
    _make_heap();
  }

  bool empty() const
  {
    return c.empty();
  }

  size_type size() const
  {
    return c.size();
  }

  const_reference top() const
  {
    assert(!empty());

    return c.front();
  }

  void push(const T &v)
  {
    c.push_back(v);
    _push_heap();
  }

  void pop()
  {
    assert(!empty());

    _pop_heap();
    c.pop_back();
  }

  void swap(gpriority_queue &q)
  {
    std::swap(c, q.c);
    std::swap(comp, q.comp);
  }

#ifdef GHEAP_CPP11
  void push(T &&v)
  {
    c.push_back(std::move(v));
    _push_heap();
  }
#endif

  // Copy constructors and assignment operators are implicitly defined.
};

namespace std
{
  template <class Heap, class T, class Container, class LessComparer>
  void swap(
      gpriority_queue<Heap, T, Container, LessComparer> &a,
      gpriority_queue<Heap, T, Container, LessComparer> &b)
  {
    a.swap(b);
  }
}
