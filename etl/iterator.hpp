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

#ifndef TAETL_ITERATOR_HPP
#define TAETL_ITERATOR_HPP

#include "etl/cstddef.hpp"
#include "etl/memory.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"
#include "etl/warning.hpp"

namespace etl
{
/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct input_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct output_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct forward_iterator_tag : public input_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct bidirectional_iterator_tag : public forward_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct random_access_iterator_tag : public bidirectional_iterator_tag
{
};

/// \brief Defines the category of an iterator. Each tag is an empty type and
/// corresponds to one of the five (until C++20) six (since C++20) iterator
/// categories.
struct contiguous_iterator_tag : public random_access_iterator_tag
{
};

/// \brief etl::iterator_traits is the type trait class that provides uniform
/// interface to the properties of LegacyIterator types. This makes it possible
/// to implement algorithms only in terms of iterators.
///
/// \details The template can be specialized for user-defined iterators so that
/// the information about the iterator can be retrieved even if the type does
/// not provide the usual typedefs.
///
/// https://en.cppreference.com/w/cpp/iterator/iterator_traits
template <typename Iter>
struct iterator_traits;

/// \brief etl::iterator_traits is the type trait class that provides uniform
/// interface to the properties of LegacyIterator types. This makes it possible
/// to implement algorithms only in terms of iterators.
///
/// \details The template can be specialized for user-defined iterators so that
/// the information about the iterator can be retrieved even if the type does
/// not provide the usual typedefs.
///
/// https://en.cppreference.com/w/cpp/iterator/iterator_traits
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
/// https://en.cppreference.com/w/cpp/iterator/advance
template <typename It, typename Distance>
constexpr auto advance(It& it, Distance n) -> void
{
  using category = typename etl::iterator_traits<It>::iterator_category;
  static_assert(etl::is_base_of_v<etl::input_iterator_tag, category>);

  auto dist = typename etl::iterator_traits<It>::difference_type(n);
  if constexpr (etl::is_base_of_v<etl::random_access_iterator_tag, category>)
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
    if constexpr (etl::is_base_of_v<etl::bidirectional_iterator_tag, category>)
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
/// https://en.cppreference.com/w/cpp/iterator/distance
template <typename It>
constexpr auto distance(It first, It last) ->
  typename etl::iterator_traits<It>::difference_type
{
  using category = typename etl::iterator_traits<It>::iterator_category;
  static_assert(etl::is_base_of_v<etl::input_iterator_tag, category>);

  if constexpr (etl::is_base_of_v<etl::random_access_iterator_tag, category>)
  {
    return last - first;
  }
  else
  {
    typename etl::iterator_traits<It>::difference_type result = 0;
    while (first != last)
    {
      ++first;
      ++result;
    }
    return result;
  }
}

/// \brief Return the nth successor of iterator it.
template <typename InputIt>
[[nodiscard]] constexpr auto
next(InputIt it, typename etl::iterator_traits<InputIt>::difference_type n = 1)
  -> InputIt
{
  etl::advance(it, n);
  return it;
}

/// \brief Return the nth predecessor of iterator it.
template <typename BidirIt>
[[nodiscard]] constexpr auto
prev(BidirIt it, typename etl::iterator_traits<BidirIt>::difference_type n = 1)
  -> BidirIt
{
  etl::advance(it, -n);
  return it;
}

/// \brief etl::reverse_iterator is an iterator adaptor that reverses the
/// direction of a given iterator. In other words, when provided with a
/// bidirectional iterator, etl::reverse_iterator produces a new iterator that
/// moves from the end to the beginning of the sequence defined by the
/// underlying bidirectional iterator.
///
/// \details This is the iterator returned by member functions rbegin() and
/// rend() of the standard library containers.
template <class Iter>
class reverse_iterator
{
  public:
  using iterator_type   = Iter;
  using value_type      = typename etl::iterator_traits<Iter>::value_type;
  using difference_type = typename etl::iterator_traits<Iter>::difference_type;
  using reference       = typename etl::iterator_traits<Iter>::reference;
  using pointer         = typename etl::iterator_traits<Iter>::pointer;

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
  template <class Other>
  constexpr reverse_iterator(reverse_iterator<Other> const& other)
      : current_(other.base())
  {
  }

  /// \brief The underlying iterator is assigned the value of the underlying
  /// iterator of other, i.e. other.base().
  template <class Other>
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
/// etl::back_insert_iterator for the container c with the type deduced from the
/// type of the argument.
template <typename Container>
[[nodiscard]] constexpr auto back_inserter(Container& container)
  -> back_insert_iterator<Container>
{
  return etl::back_insert_iterator<Container>(container);
}

/// \brief etl::front_insert_iterator is an LegacyOutputIterator that prepends
/// elements to a container for which it was constructed. The container's
/// push_front() member function is called whenever the iterator (whether
/// dereferenced or not) is assigned to. Incrementing the
/// etl::front_insert_iterator is a no-op.
///
/// \todo Add tests when a container with push_front has been implemented.
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
  /// etl::addressof(c).
  constexpr explicit front_insert_iterator(Container& container)
      : container_ {etl::addressof(container)}
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
    container_->push_front(etl::move(value));
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
/// etl::front_insert_iterator for the container c with the type deduced from
/// the type of the argument.
template <typename Container>
[[nodiscard]] constexpr auto front_inserter(Container& c)
  -> etl::front_insert_iterator<Container>
{
  return etl::front_insert_iterator<Container>(c);
}

/// \brief Returns an iterator to the beginning of the given container c or
/// array array. These templates rely on C::begin() having a reasonable
/// implementation. Returns exactly c.begin(), which is typically an iterator to
/// the beginning of the sequence represented by c. If C is a standard
/// Container, this returns C::iterator when c is not const-qualified, and
/// C::const_iterator otherwise.
///
/// \details Custom overloads of begin may be provided for classes that do not
/// expose a suitable begin() member function, yet can be iterated.
template <typename C>
constexpr auto begin(C& c) -> decltype(c.begin())
{
  return c.begin();
}

/// \brief Returns an iterator to the beginning of the given container c or
/// array array. These templates rely on C::begin() having a reasonable
/// implementation. Returns exactly c.begin(), which is typically an iterator to
/// the beginning of the sequence represented by c. If C is a standard
/// Container, this returns C::iterator when c is not const-qualified, and
/// C::const_iterator otherwise.
///
/// \details Custom overloads of begin may be provided for classes that do not
/// expose a suitable begin() member function, yet can be iterated.
template <typename C>
constexpr auto begin(C const& c) -> decltype(c.begin())
{
  return c.begin();
}

/// \brief Returns an iterator to the beginning of the given container c or
/// array array. These templates rely on C::begin() having a reasonable
/// implementation. Returns a pointer to the beginning of the array.
///
/// \details Custom overloads of begin may be provided for classes that do not
/// expose a suitable begin() member function, yet can be iterated.
template <typename T, etl::size_t N>
constexpr auto begin(T (&array)[N]) noexcept -> T*
{
  return &array[0];
}

/// \brief Returns an iterator to the beginning of the given container c or
/// array array. These templates rely on C::begin() having a reasonable
/// implementation. Returns exactly etl::begin(c), with c always treated as
/// const-qualified. If C is a standard Container, this always returns
/// C::const_iterator.
///
/// \details Custom overloads of begin may be provided for classes that do
/// not expose a suitable begin() member function, yet can be iterated.
template <typename C>
constexpr auto cbegin(C const& c) noexcept(noexcept(etl::begin(c)))
  -> decltype(etl::begin(c))
{
  return etl::begin(c);
}

/// \brief Returns an iterator to the end (i.e. the element after the last
/// element) of the given container c or array array. These templates rely on
/// C::end() having a reasonable implementation.
template <typename C>
constexpr auto end(C& c) -> decltype(c.end())
{
  return c.end();
}

/// \brief Returns an iterator to the end (i.e. the element after the last
/// element) of the given container c or array array. These templates rely on
/// C::end() having a reasonable implementation.
template <typename C>
constexpr auto end(C const& c) -> decltype(c.end())
{
  return c.end();
}

/// \brief Returns an iterator to the end (i.e. the element after the last
/// element) of the given container c or array array. These templates rely on
/// C::end() having a reasonable implementation.
template <typename T, etl::size_t N>
constexpr auto end(T (&array)[N]) noexcept -> T*
{
  return &array[N];
}

/// \brief Returns an iterator to the end (i.e. the element after the last
/// element) of the given container c or array array. These templates rely on
/// C::end() having a reasonable implementation.
template <typename C>
constexpr auto cend(C const& c) noexcept(noexcept(etl::end(c)))
  -> decltype(etl::end(c))
{
  return etl::end(c);
}

/// \brief Returns an iterator to the reverse-beginning of the given container.
template <typename Container>
constexpr auto rbegin(Container& c) -> decltype(c.rbegin())
{
  return c.rbegin();
}

/// \brief Returns an iterator to the reverse-beginning of the given container.
template <typename Container>
constexpr auto rbegin(Container const& c) -> decltype(c.rbegin())
{
  return c.rbegin();
}

/// \brief Returns an iterator to the reverse-beginning of the given array.
template <typename T, etl::size_t N>
constexpr auto rbegin(T (&array)[N]) -> reverse_iterator<T*>
{
  return reverse_iterator<T*>(end(array));
}

/// \brief Returns an iterator to the reverse-beginning of the given container.
template <typename Container>
constexpr auto crbegin(Container const& c) -> decltype(etl::rbegin(c))
{
  return etl::rbegin(c);
}

/// \brief Returns an iterator to the reverse-end of the given container.
template <typename Container>
constexpr auto rend(Container& c) -> decltype(c.rend())
{
  return c.rend();
}

/// \brief Returns an iterator to the reverse-end of the given container.
template <typename Container>
constexpr auto rend(Container const& c) -> decltype(c.rend())
{
  return c.rend();
}

/// \brief Returns an iterator to the reverse-end of the given array.
template <typename T, etl::size_t N>
constexpr auto rend(T (&array)[N]) -> reverse_iterator<T*>
{
  return reverse_iterator<T*>(begin(array));
}

/// \brief Returns an iterator to the reverse-end of the given container.
template <typename Container>
constexpr auto crend(Container const& c) -> decltype(etl::rend(c))
{
  return etl::rend(c);
}

/// \brief Returns the size of the given container c or array array. Returns
/// c.size(), converted to the return type if necessary.
template <typename C>
constexpr auto size(C const& c) noexcept(noexcept(c.size()))
  -> decltype(c.size())
{
  return c.size();
}

/// \brief Returns the size of the given container c or array array. Returns N.
template <typename T, etl::size_t N>
constexpr auto size(T const (&array)[N]) noexcept -> etl::size_t
{
  etl::ignore_unused(&array[0]);
  return N;
}

/// \brief Returns whether the given container is empty.
template <typename C>
constexpr auto empty(C const& c) noexcept(noexcept(c.empty()))
  -> decltype(c.empty())
{
  return c.empty();
}

/// \brief Returns whether the given container is empty.
template <typename T, etl::size_t N>
constexpr auto empty(T (&array)[N]) noexcept -> bool
{
  etl::ignore_unused(&array);
  return false;
}

/// \brief Returns a pointer to the block of memory containing the elements of
/// the container. Returns c.data().
template <typename C>
constexpr auto data(C& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
  return c.data();
}

/// \brief Returns a pointer to the block of memory containing the elements of
/// the container. Returns c.data().
template <typename C>
constexpr auto data(C const& c) noexcept(noexcept(c.data()))
  -> decltype(c.data())
{
  return c.data();
}

/// \brief Returns a pointer to the block of memory containing the elements of
/// the container. Returns &array[0].
template <typename T, etl::size_t N>
constexpr auto data(T (&array)[N]) noexcept -> T*
{
  return &array[0];
}

}  // namespace etl

#endif  // TAETL_ITERATOR_HPP
