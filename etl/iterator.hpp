// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_ITERATOR_HPP
#define TETL_ITERATOR_HPP

#include "etl/cstddef.hpp"
#include "etl/memory.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"
#include "etl/warning.hpp"

namespace etl
{
template <typename Iter>
struct reverse_iterator;

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct input_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct output_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct forward_iterator_tag : input_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct bidirectional_iterator_tag : forward_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct random_access_iterator_tag : bidirectional_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
/// \module Iterator
struct contiguous_iterator_tag : random_access_iterator_tag
{
};

/// \brief iterator_traits is the type trait class that provides uniform
/// interface to the properties of LegacyIterator types. This makes it possible
/// to implement algorithms only in terms of iterators.
///
/// \details The template can be specialized for user-defined iterators so that
/// the information about the iterator can be retrieved even if the type does
/// not provide the usual typedefs.
///
/// \notes
/// [cppreference.com/w/cpp/iterator/iterator_traits](https://en.cppreference.com/w/cpp/iterator/iterator_traits)
/// \group iterator_traits
/// \module Iterator
template <typename Iter>
struct iterator_traits;

/// \group iterator_traits
template <typename T>
struct iterator_traits<T*>
{
  using iterator_concept  = contiguous_iterator_tag;
  using iterator_category = random_access_iterator_tag;
  using value_type        = remove_cv_t<T>;
  using difference_type   = ptrdiff_t;
  using pointer           = T*;
  using reference         = T&;
};

/// \brief Increments given iterator it by n elements. If n is negative, the
/// iterator is decremented. In this case, InputIt must meet the requirements of
/// LegacyBidirectionalIterator, otherwise the behavior is undefined.
///
/// \notes
/// [cppreference.com/w/cpp/iterator/advance](https://en.cppreference.com/w/cpp/iterator/advance)
/// \module Iterator
template <typename It, typename Distance>
constexpr auto advance(It& it, Distance n) -> void
{
  using category = typename iterator_traits<It>::iterator_category;
  static_assert(is_base_of_v<input_iterator_tag, category>);

  auto dist = typename iterator_traits<It>::difference_type(n);
  if constexpr (is_base_of_v<random_access_iterator_tag, category>)
  {
    it += dist;
  }
  else
  {
    while (dist > 0)
    {
      --dist;
      ++it;
    }
    if constexpr (is_base_of_v<bidirectional_iterator_tag, category>)
    {
      while (dist < 0)
      {
        ++dist;
        --it;
      }
    }
  }
}

/// \brief Returns the number of hops from first to last.
///
/// \notes
/// [cppreference.com/w/cpp/iterator/distance](https://en.cppreference.com/w/cpp/iterator/distance)
/// \module Iterator
template <typename It>
constexpr auto distance(It first, It last) ->
  typename iterator_traits<It>::difference_type
{
  using category = typename iterator_traits<It>::iterator_category;
  static_assert(is_base_of_v<input_iterator_tag, category>);

  if constexpr (is_base_of_v<random_access_iterator_tag, category>)
  {
    return last - first;
  }
  else
  {
    typename iterator_traits<It>::difference_type result = 0;
    while (first != last)
    {
      ++first;
      ++result;
    }
    return result;
  }
}

/// \brief Return the nth successor of iterator it.
/// \module Iterator
template <typename InputIt>
[[nodiscard]] constexpr auto
next(InputIt it, typename iterator_traits<InputIt>::difference_type n = 1)
  -> InputIt
{
  advance(it, n);
  return it;
}

/// \brief Return the nth predecessor of iterator it.
/// \module Iterator
template <typename BidirIt>
[[nodiscard]] constexpr auto
prev(BidirIt it, typename iterator_traits<BidirIt>::difference_type n = 1)
  -> BidirIt
{
  advance(it, -n);
  return it;
}

/// \brief Returns an iterator to the beginning of the given container c or
/// array array. These templates rely on `C::begin()` having a reasonable
/// implementation. Returns exactly c.begin(), which is typically an iterator to
/// the beginning of the sequence represented by c. If C is a standard
/// Container, this returns `C::iterator` when c is not const-qualified, and
/// `C::const_iterator` otherwise. Custom overloads of begin may be provided for
/// classes that do not expose a suitable begin() member function, yet can be
/// iterated. \group begin \module Iterator
template <typename C>
constexpr auto begin(C& c) -> decltype(c.begin())
{
  return c.begin();
}

/// \group begin
template <typename C>
constexpr auto begin(C const& c) -> decltype(c.begin())
{
  return c.begin();
}

/// \group begin
template <typename T, size_t N>
constexpr auto begin(T (&array)[N]) noexcept -> T*
{
  return &array[0];
}

/// \group begin
template <typename C>
constexpr auto cbegin(C const& c) noexcept(noexcept(begin(c)))
  -> decltype(begin(c))
{
  return begin(c);
}

/// \brief Returns an iterator to the end (i.e. the element after the last
/// element) of the given container c or array array. These templates rely on
/// `C::end()` having a reasonable implementation. \group end \module Iterator
template <typename C>
constexpr auto end(C& c) -> decltype(c.end())
{
  return c.end();
}

/// \group end
template <typename C>
constexpr auto end(C const& c) -> decltype(c.end())
{
  return c.end();
}

/// \group end
template <typename T, size_t N>
constexpr auto end(T (&array)[N]) noexcept -> T*
{
  return &array[N];
}

/// \group end
template <typename C>
constexpr auto cend(C const& c) noexcept(noexcept(end(c))) -> decltype(end(c))
{
  return end(c);
}

/// \brief Returns an iterator to the reverse-beginning of the given container.
/// \group rbegin
/// \module Iterator
template <typename Container>
constexpr auto rbegin(Container& c) -> decltype(c.rbegin())
{
  return c.rbegin();
}

/// \group rbegin
template <typename Container>
constexpr auto rbegin(Container const& c) -> decltype(c.rbegin())
{
  return c.rbegin();
}

/// \group rbegin
template <typename T, size_t N>
constexpr auto rbegin(T (&array)[N]) -> reverse_iterator<T*>
{
  return reverse_iterator<T*>(end(array));
}

/// \group rbegin
template <typename Container>
constexpr auto crbegin(Container const& c) -> decltype(rbegin(c))
{
  return rbegin(c);
}

/// \brief Returns an iterator to the reverse-end of the given container.
/// \group rend
/// \module Iterator
template <typename Container>
constexpr auto rend(Container& c) -> decltype(c.rend())
{
  return c.rend();
}

/// \group rend
template <typename Container>
constexpr auto rend(Container const& c) -> decltype(c.rend())
{
  return c.rend();
}

/// \group rend
template <typename T, size_t N>
constexpr auto rend(T (&array)[N]) -> reverse_iterator<T*>
{
  return reverse_iterator<T*>(begin(array));
}

/// \brief Returns an iterator to the reverse-end of the given container.
/// \group rend
template <typename Container>
constexpr auto crend(Container const& c) -> decltype(rend(c))
{
  return rend(c);
}

/// \brief Returns the size of the given container c or array array. Returns
/// c.size(), converted to the return type if necessary.
/// \group size
/// \module Iterator
template <typename C>
constexpr auto size(C const& c) noexcept(noexcept(c.size()))
  -> decltype(c.size())
{
  return c.size();
}

/// \group size
template <typename T, size_t N>
constexpr auto size(T const (&array)[N]) noexcept -> size_t
{
  ignore_unused(&array[0]);
  return N;
}

/// \brief Returns whether the given container is empty.
/// \group empty
/// \module Iterator
template <typename C>
constexpr auto empty(C const& c) noexcept(noexcept(c.empty()))
  -> decltype(c.empty())
{
  return c.empty();
}

/// \group empty
template <typename T, size_t N>
constexpr auto empty(T (&array)[N]) noexcept -> bool
{
  ignore_unused(&array);
  return false;
}

/// \brief Returns a pointer to the block of memory containing the elements of
/// the container.
/// \group data
/// \module Iterator
template <typename C>
constexpr auto data(C& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
  return c.data();
}

/// \group data
template <typename C>
constexpr auto data(C const& c) noexcept(noexcept(c.data()))
  -> decltype(c.data())
{
  return c.data();
}

/// \group data
template <typename T, size_t N>
constexpr auto data(T (&array)[N]) noexcept -> T*
{
  return &array[0];
}

/// \brief reverse_iterator is an iterator adaptor that reverses the direction
/// of a given iterator. In other words, when provided with a bidirectional
/// iterator, `reverse_iterator` produces a new iterator that moves from the end
/// to the beginning of the sequence defined by the underlying bidirectional
/// iterator. This is the iterator returned by member functions `rbegin()` and
/// `rend()` of the standard library containers. \notes
/// [cppreference.com/w/cpp/iterator/reverse_iterator](https://en.cppreference.com/w/cpp/iterator/reverse_iterator)
/// \module Iterator
template <typename Iter>
struct reverse_iterator
{
  /// The underlying iterator type
  using iterator_type = Iter;
  /// The underlying value type
  using value_type = typename iterator_traits<Iter>::value_type;
  /// The type of subtracting to iterators
  using difference_type = typename etl::iterator_traits<Iter>::difference_type;
  /// The underlying reference type
  using reference = typename etl::iterator_traits<Iter>::reference;
  /// The underlying pointer type
  using pointer = typename etl::iterator_traits<Iter>::pointer;

  /// \brief Constructs a new iterator adaptor.
  ///
  /// \details Default constructor. The underlying iterator is
  /// value-initialized. Operations on the resulting iterator have defined
  /// behavior if and only if the corresponding operations on a
  /// value-initialized Iterator also have defined behavior.
  constexpr reverse_iterator() : current_() { }

  /// \brief Constructs a new iterator adaptor.
  ///
  /// \details The underlying iterator is initialized with x.
  constexpr explicit reverse_iterator(Iter x) : current_(x) { }

  /// \brief Constructs a new iterator adaptor.
  ///
  /// \details The underlying iterator is initialized with that of other.
  template <typename Other>
  constexpr reverse_iterator(reverse_iterator<Other> const& other)
      : current_(other.base())
  {
  }

  /// \brief The underlying iterator is assigned the value of the underlying
  /// iterator of other, i.e. other.base().
  template <typename Other>
  constexpr auto operator=(reverse_iterator<Other> const& other)
    -> reverse_iterator&
  {
    current_ = other.base();
    return *this;
  }

  /// \brief Returns the underlying base iterator.
  [[nodiscard]] constexpr auto base() const -> Iter { return current_; }

  /// \brief Returns a reference to the element previous to current.
  constexpr auto operator*() const -> reference
  {
    auto tmp = current_;
    return *--tmp;
  }

  /// \brief Returns a pointer to the element previous to current.
  constexpr auto operator->() const -> pointer
  {
    return etl::addressof(operator*());
  }

  /// \brief Pre-increments by one respectively.
  constexpr auto operator++() -> reverse_iterator&
  {
    --current_;
    return *this;
  }

  /// \brief Pre-increments by one respectively.
  constexpr auto operator++(int) -> reverse_iterator
  {
    auto tmp(*this);
    --current_;
    return tmp;
  }

  /// \brief Pre-decrements by one respectively.
  constexpr auto operator--() -> reverse_iterator&
  {
    ++current_;
    return *this;
  }

  /// \brief Pre-decrements by one respectively.
  constexpr auto operator--(int) -> reverse_iterator
  {
    auto tmp(*this);
    ++current_;
    return tmp;
  }

  /// \brief Returns an iterator which is advanced by n positions.
  constexpr auto operator+(difference_type n) const -> reverse_iterator
  {
    return reverse_iterator(current_ - n);
  }

  /// \brief Advances the iterator by n or -n positions respectively.
  constexpr auto operator+=(difference_type n) -> reverse_iterator&
  {
    current_ -= n;
    return *this;
  }

  /// \brief Returns an iterator which is advanced by -n positions.
  constexpr auto operator-(difference_type n) const -> reverse_iterator
  {
    return reverse_iterator(current_ + n);
  }

  /// \brief Advances the iterator by n or -n positions respectively.
  constexpr auto operator-=(difference_type n) -> reverse_iterator&
  {
    current_ += n;
    return *this;
  }

  /// \brief Returns a reference to the element at specified relative location.
  constexpr auto operator[](difference_type n) const -> reference
  {
    return *(*this + n);
  }

  private:
  Iter current_;
};

/// \brief Convenience function template that constructs a etl::reverse_iterator
/// for the given iterator i (which must be a LegacyBidirectionalIterator) with
/// the type deduced from the type of the argument.
template <typename Iter>
[[nodiscard]] constexpr auto make_reverse_iterator(Iter i) noexcept
  -> etl::reverse_iterator<Iter>
{
  return etl::reverse_iterator<Iter>(i);
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator==(etl::reverse_iterator<Iter1> const& lhs,
                                        etl::reverse_iterator<Iter2> const& rhs)
  -> bool
{
  return lhs.base() == rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator!=(etl::reverse_iterator<Iter1> const& lhs,
                                        etl::reverse_iterator<Iter2> const& rhs)
  -> bool
{
  return lhs.base() != rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator<(etl::reverse_iterator<Iter1> const& lhs,
                                       etl::reverse_iterator<Iter2> const& rhs)
  -> bool
{
  return lhs.base() < rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator<=(etl::reverse_iterator<Iter1> const& lhs,
                                        etl::reverse_iterator<Iter2> const& rhs)
  -> bool
{
  return lhs.base() <= rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator>(etl::reverse_iterator<Iter1> const& lhs,
                                       etl::reverse_iterator<Iter2> const& rhs)
  -> bool
{
  return lhs.base() > rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator>=(etl::reverse_iterator<Iter1> const& lhs,
                                        etl::reverse_iterator<Iter2> const& rhs)
  -> bool
{
  return lhs.base() >= rhs.base();
}

/// \brief etl::back_insert_iterator is a LegacyOutputIterator that appends to a
/// container for which it was constructed. The container's push_back() member
/// function is called whenever the iterator (whether dereferenced or not) is
/// assigned to. Incrementing the etl::back_insert_iterator is a no-op.
/// \module Iterator
template <typename Container>
class back_insert_iterator
{
  public:
  using iterator_category = output_iterator_tag;
  using value_type        = void;
  using difference_type   = ptrdiff_t;
  using pointer           = void;
  using reference         = void;
  using container_type    = Container;

  /// \brief Initializes the underlying pointer to container with nullptr.
  constexpr back_insert_iterator() noexcept = default;

  /// \brief Initializes the underlying pointer to the container to
  /// etl::addressof(c).
  constexpr explicit back_insert_iterator(Container& container)
      : container_ {etl::addressof(container)}
  {
  }

  /// \brief Inserts the given value value to the container.
  constexpr auto operator=(typename Container::value_type const& value)
    -> back_insert_iterator&
  {
    container_->push_back(value);
    return *this;
  }

  /// \brief Inserts the given value value to the container.
  constexpr auto operator=(typename Container::value_type&& value)
    -> back_insert_iterator&
  {
    container_->push_back(etl::move(value));
    return *this;
  }

  /// \brief Does nothing, this member function is provided to satisfy the
  /// requirements of LegacyOutputIterator. It returns the iterator itself,
  /// which makes it possible to use code such as *iter = value to output
  /// (insert) the value into the underlying container.
  constexpr auto operator*() -> back_insert_iterator& { return *this; }

  /// \brief Does nothing. These operator overloads are provided to satisfy the
  /// requirements of LegacyOutputIterator. They make it possible for the
  /// expressions *iter++=value and *++iter=value to be used to output (insert)
  /// a value into the underlying container.
  constexpr auto operator++() -> back_insert_iterator& { return *this; }

  /// \brief Does nothing. These operator overloads are provided to satisfy the
  /// requirements of LegacyOutputIterator. They make it possible for the
  /// expressions *iter++=value and *++iter=value to be used to output (insert)
  /// a value into the underlying container.
  constexpr auto operator++(int) -> back_insert_iterator { return *this; }

  private:
  Container* container_ = nullptr;
};

/// back_inserter is a convenience function template that constructs a
/// back_insert_iterator for the container c with the type deduced from the
/// type of the argument.
/// \module Iterator
template <typename Container>
[[nodiscard]] constexpr auto back_inserter(Container& container)
  -> back_insert_iterator<Container>
{
  return back_insert_iterator<Container>(container);
}

/// \brief front_insert_iterator is an LegacyOutputIterator that prepends
/// elements to a container for which it was constructed. The container's
/// push_front() member function is called whenever the iterator (whether
/// dereferenced or not) is assigned to. Incrementing the
/// front_insert_iterator is a no-op.
///
/// \todo Add tests when a container with push_front has been implemented.
/// \module Iterator
template <typename Container>
class front_insert_iterator
{
  protected:
  Container* container_ = nullptr;

  public:
  using iterator_category = output_iterator_tag;
  using value_type        = void;
  using difference_type   = void;
  using pointer           = void;
  using reference         = void;
  using container_type    = Container;

  /// \brief Initializes the underlying pointer to container with nullptr.
  constexpr front_insert_iterator() noexcept = default;

  /// \brief Initializes the underlying pointer to the container to
  /// addressof(c).
  constexpr explicit front_insert_iterator(Container& container)
      : container_ {addressof(container)}
  {
  }

  /// \brief Inserts the given value value to the container.
  constexpr auto operator=(typename Container::value_type const& value)
    -> front_insert_iterator&
  {
    container_->push_front(value);
    return *this;
  }

  /// \brief Inserts the given value value to the container.
  constexpr auto operator=(typename Container::value_type&& value)
    -> front_insert_iterator&
  {
    container_->push_front(move(value));
    return *this;
  }

  /// \brief Does nothing, this member function is provided to satisfy the
  /// requirements of LegacyOutputIterator. It returns the iterator itself,
  /// which makes it possible to use code such as *iter = value to output
  /// (insert) the value into the underlying container.
  constexpr auto operator*() -> front_insert_iterator& { return *this; }

  /// \brief Does nothing. These operator overloads are provided to satisfy the
  /// requirements of LegacyOutputIterator. They make it possible for the
  /// expressions *iter++=value and *++iter=value to be used to output (insert)
  /// a value into the underlying container.
  constexpr auto operator++() -> front_insert_iterator& { return *this; }

  /// \brief Does nothing. These operator overloads are provided to satisfy the
  /// requirements of LegacyOutputIterator. They make it possible for the
  /// expressions *iter++=value and *++iter=value to be used to output (insert)
  /// a value into the underlying container.
  constexpr auto operator++(int) -> front_insert_iterator { return *this; }
};

/// \brief front_inserter is a convenience function template that constructs a
/// front_insert_iterator for the container c with the type deduced from
/// the type of the argument.
/// \module Iterator
template <typename Container>
[[nodiscard]] constexpr auto front_inserter(Container& c)
  -> front_insert_iterator<Container>
{
  return front_insert_iterator<Container>(c);
}

}  // namespace etl

#endif  // TETL_ITERATOR_HPP
