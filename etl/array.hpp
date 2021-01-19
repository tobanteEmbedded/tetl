/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

/**
 * @file array.hpp
 * @example array.cpp
 */

#ifndef TAETL_ARRAY_HPP
#define TAETL_ARRAY_HPP

#include "etl/algorithm.hpp"
#include "etl/cassert.hpp"
#include "etl/definitions.hpp"
#include "etl/iterator.hpp"
#include "etl/type_traits.hpp"

#include "etl/detail/tuple_size.hpp"

namespace etl
{
/**
 * @brief etl::array is a container that encapsulates fixed size arrays.
 *
 * @details This container is an aggregate type with the same semantics as a
 * struct holding a C-style array Type[N] as its only non-static data member.
 * Unlike a C-style array, it doesn't decay to Type* automatically. As an
 * aggregate type, it can be initialized with aggregate-initialization given at
 * most N initializers that are convertible to Type: etl::array<int, 3> a =
 * {1,2,3};.
 *
 * @include array.cpp
 */
template <typename Type, etl::size_t Size>
struct array
{
  using value_type             = Type;
  using size_type              = etl::size_t;
  using difference_type        = etl::ptrdiff_t;
  using pointer                = Type*;
  using const_pointer          = const Type*;
  using reference              = Type&;
  using const_reference        = const Type&;
  using iterator               = Type*;
  using const_iterator         = const Type*;
  using reverse_iterator       = typename etl::reverse_iterator<iterator>;
  using const_reverse_iterator = typename etl::reverse_iterator<const_iterator>;

  /**
   * @brief Accesses the specified item with bounds checking.
   */
  [[nodiscard]] constexpr auto at(size_type const pos) noexcept -> reference
  {
    assert(pos < Size);
    return _data[pos];
  }

  /**
   * @brief Accesses the specified const item with bounds checking.
   */
  [[nodiscard]] constexpr auto at(size_type const pos) const noexcept
    -> const_reference
  {
    assert(pos < Size);
    return _data[pos];
  }

  /**
   * @brief Accesses the specified item with bounds checking.
   */
  [[nodiscard]] constexpr auto operator[](size_type const pos) noexcept
    -> reference
  {
    assert(pos < Size);
    return _data[pos];
  }

  /**
   * @brief Accesses the specified item with bounds checking.
   */
  [[nodiscard]] constexpr auto operator[](size_type const pos) const noexcept
    -> const_reference
  {
    assert(pos < Size);
    return _data[pos];
  }

  /**
   * @brief Accesses the first item.
   */
  [[nodiscard]] constexpr auto front() noexcept -> reference
  {
    return _data[0];
  }

  /**
   * @brief Accesses the first item.
   */
  [[nodiscard]] constexpr auto front() const noexcept -> const_reference
  {
    return _data[0];
  }

  /**
   * @brief Accesses the last item.
   */
  [[nodiscard]] constexpr auto back() noexcept -> reference
  {
    return _data[Size - 1];
  }

  /**
   * @brief Accesses the last item.
   */
  [[nodiscard]] constexpr auto back() const noexcept -> const_reference
  {
    return _data[Size - 1];
  }

  /**
   * @brief Returns pointer to the underlying array serving as element
   * storage. The pointer is such that range [data(); data() + size()) is
   * always a valid range, even if the container is empty (data() is not
   * dereferenceable in that case).
   */
  [[nodiscard]] constexpr auto data() noexcept -> pointer { return &_data[0]; }

  /**
   * @brief Returns pointer to the underlying array serving as element
   * storage. The pointer is such that range [data(); data() + size()) is
   * always a valid range, even if the container is empty (data() is not
   * dereferenceable in that case).
   */
  [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
  {
    return &_data[0];
  }

  /**
   * @brief Returns an iterator to the beginning.
   */
  [[nodiscard]] constexpr auto begin() noexcept -> iterator
  {
    return &_data[0];
  }

  /**
   * @brief Returns an iterator to the beginning.
   */
  [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
  {
    return &_data[0];
  }

  /**
   * @brief Returns an const iterator to the beginning.
   */
  [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
  {
    return &_data[0];
  }

  /**
   * @brief Returns an iterator to the end.
   */
  [[nodiscard]] constexpr auto end() noexcept -> iterator
  {
    return &_data[0] + size();
  }

  /**
   * @brief Returns an iterator to the end.
   */
  [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
  {
    return &_data[0] + size();
  }

  /**
   * @brief Returns an const iterator to the end.
   */
  [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
  {
    return &_data[0] + size();
  }

  /**
   * @brief Returns a reverse iterator to the first element of the reversed
   * array. It corresponds to the last element of the non-reversed array. If the
   * array is empty, the returned iterator is equal to rend().
   */
  [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
  {
    return reverse_iterator(end());
  }

  /**
   * @brief Returns a reverse iterator to the first element of the reversed
   * array. It corresponds to the last element of the non-reversed array. If the
   * array is empty, the returned iterator is equal to rend().
   */
  [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
  {
    return const_reverse_iterator(end());
  }

  /**
   * @brief Returns a reverse iterator to the first element of the reversed
   * array. It corresponds to the last element of the non-reversed array. If the
   * array is empty, the returned iterator is equal to rend().
   */
  [[nodiscard]] constexpr auto crbegin() const noexcept
    -> const_reverse_iterator
  {
    return rbegin();
  }

  /**
   * @brief Returns a reverse iterator to the element following the last element
   * of the reversed array. It corresponds to the element preceding the first
   * element of the non-reversed array. This element acts as a placeholder,
   * attempting to access it results in undefined behavior.
   */
  [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
  {
    return reverse_iterator(begin());
  }

  /**
   * @brief Returns a reverse iterator to the element following the last element
   * of the reversed array. It corresponds to the element preceding the first
   * element of the non-reversed array. This element acts as a placeholder,
   * attempting to access it results in undefined behavior.
   */
  [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
  {
    return const_reverse_iterator(begin());
  }

  /**
   * @brief Returns a reverse iterator to the element following the last element
   * of the reversed array. It corresponds to the element preceding the first
   * element of the non-reversed array. This element acts as a placeholder,
   * attempting to access it results in undefined behavior.
   */
  [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator
  {
    return rend();
  }

  /**
   * @brief Checks if the container has no elements, i.e. whether begin() ==
   * end().
   */
  [[nodiscard]] constexpr auto empty() const noexcept -> bool
  {
    return begin() == end();
  }

  /**
   * @brief Returns the number of elements in the container, i.e.
   * etl::distance(begin(), end()).
   */
  [[nodiscard]] constexpr auto size() const noexcept -> size_type
  {
    return Size;
  }

  /**
   * @brief Returns the maximum number of elements the container is able to hold
   * due to system or library implementation limitations, i.e.
   * etl::distance(begin(), end()) for the largest container.
   *
   * @details Because each etl::array<T, N> is a fixed-size container, the value
   * returned by max_size equals N (which is also the value returned by size)
   */
  [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
  {
    return Size;
  }

  /**
   * @brief Assigns the given value value to all elements in the container.
   */
  constexpr auto fill(const_reference value) -> void
  {
    for (auto& item : (*this)) { item = value; }
  }

  /**
   * @brief Exchanges the contents of the container with those of other. Does
   * not cause iterators and references to associate with the other container.
   */
  constexpr auto swap(array& other) noexcept(etl::is_nothrow_swappable_v<Type>)
    -> void
  {
    using etl::swap;
    for (auto i = size_type {0}; i < size(); ++i)
    { swap((*this)[i], other[i]); }
  }

  Type _data[Size];
};

/**
 * @brief Specializes the etl::swap algorithm for etl::array. Swaps the contents
 * of lhs and rhs.
 */
template <typename T, etl::size_t N>
constexpr auto swap(etl::array<T, N>& lhs,
                    etl::array<T, N>& rhs) noexcept(noexcept(lhs.swap(rhs)))
  -> void
{
  lhs.swap(rhs);
}

/**
 * @brief Provides access to the number of elements in an etl::array as a
 * compile-time constant expression.
 */
template <typename T, etl::size_t N>
struct tuple_size<etl::array<T, N>> : etl::integral_constant<etl::size_t, N>
{
};

/**
 * @brief Provides compile-time indexed access to the type of the elements of
 * the array using tuple-like interface.
 */
template <etl::size_t I, typename T>
struct tuple_element;

/**
 * @brief Provides compile-time indexed access to the type of the elements of
 * the array using tuple-like interface.
 */
template <etl::size_t I, typename T, etl::size_t N>
struct tuple_element<I, etl::array<T, N>>
{
  using type = T;
};

/**
 * @brief Checks if the contents of lhs and rhs are equal, that is, they have
 * the same number of elements and each element in lhs compares equal with the
 * element in rhs at the same position.
 */
template <typename T, etl::size_t N>
[[nodiscard]] constexpr auto operator==(etl::array<T, N> const& lhs,
                                        etl::array<T, N> const& rhs) -> bool
{
  return etl::equal(lhs.begin(), lhs.end(), rhs.begin());
}

/**
 * @brief Compares the contents of lhs and rhs lexicographically. The comparison
 * is performed by a function equivalent to etl::lexicographical_compare.
 */
template <typename T, etl::size_t N>
[[nodiscard]] constexpr auto operator!=(etl::array<T, N> const& lhs,
                                        etl::array<T, N> const& rhs) -> bool
{
  return !(lhs == rhs);
}

/**
 * @brief Compares the contents of lhs and rhs lexicographically. The comparison
 * is performed by a function equivalent to etl::lexicographical_compare.
 */
template <typename T, etl::size_t N>
[[nodiscard]] constexpr auto operator<(etl::array<T, N> const& lhs,
                                       etl::array<T, N> const& rhs) -> bool
{
  return etl::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(),
                                      rhs.end());
}

/**
 * @brief Compares the contents of lhs and rhs lexicographically. The comparison
 * is performed by a function equivalent to etl::lexicographical_compare.
 */
template <typename T, etl::size_t N>
[[nodiscard]] constexpr auto operator<=(etl::array<T, N> const& lhs,
                                        etl::array<T, N> const& rhs) -> bool
{
  return !(rhs < lhs);
}

/**
 * @brief Compares the contents of lhs and rhs lexicographically. The comparison
 * is performed by a function equivalent to etl::lexicographical_compare.
 */
template <typename T, etl::size_t N>
[[nodiscard]] constexpr auto operator>(etl::array<T, N> const& lhs,
                                       etl::array<T, N> const& rhs) -> bool
{
  return rhs < lhs;
}

/**
 * @brief Compares the contents of lhs and rhs lexicographically. The comparison
 * is performed by a function equivalent to etl::lexicographical_compare.
 */
template <typename T, etl::size_t N>
[[nodiscard]] constexpr auto operator>=(etl::array<T, N> const& lhs,
                                        etl::array<T, N> const& rhs) -> bool
{
  return !(lhs < rhs);
}

/**
 * @brief Deduction guide.
 */
template <typename T, typename... U>
array(T, U...) -> array<T, 1 + sizeof...(U)>;

}  // namespace etl

#endif  // TAETL_ARRAY_HPP