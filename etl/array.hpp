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

#ifndef TETL_ARRAY_HPP
#define TETL_ARRAY_HPP

#include "etl/version.hpp"

#include "etl/_assert/macro.hpp"

#include "etl/algorithm.hpp"
#include "etl/cstddef.hpp"
#include "etl/iterator.hpp"
#include "etl/type_traits.hpp"

#include "etl/_tuple/tuple_size.hpp"

/// \file This header is part of the containers library.

namespace etl {
/// \brief array is a container that encapsulates fixed size arrays.
///
/// \details This container is an aggregate type with the same semantics as a
/// struct holding a C-style array Type[N] as its only non-static data member.
/// Unlike a C-style array, it doesn't decay to Type* automatically. As an
/// aggregate type, it can be initialized with aggregate-initialization given at
/// most N initializers that are convertible to
/// Type: `array<int, 3> a = {1,2,3};`
///
/// \module Containers
template <typename Type, size_t Size>
struct array {
    using value_type       = Type;
    using size_type        = size_t;
    using difference_type  = ptrdiff_t;
    using pointer          = Type*;
    using const_pointer    = const Type*;
    using reference        = Type&;
    using const_reference  = const Type&;
    using iterator         = Type*;
    using const_iterator   = const Type*;
    using reverse_iterator = typename etl::reverse_iterator<iterator>;
    using const_reverse_iterator =
        typename etl::reverse_iterator<const_iterator>;

    /// \brief Accesses the specified item with range checking.
    [[nodiscard]] constexpr auto at(size_type const pos) noexcept -> reference
    {
        TETL_ASSERT(pos < Size);
        return _internal_data[pos];
    }

    /// \brief Accesses the specified const item with range checking.
    [[nodiscard]] constexpr auto at(size_type const pos) const noexcept
        -> const_reference
    {
        TETL_ASSERT(pos < Size);
        return _internal_data[pos];
    }

    /// \brief Accesses the specified item with range checking.
    [[nodiscard]] constexpr auto operator[](size_type const pos) noexcept
        -> reference
    {
        TETL_ASSERT(pos < Size);
        return _internal_data[pos];
    }

    /// \brief Accesses the specified item with range checking.
    [[nodiscard]] constexpr auto operator[](size_type const pos) const noexcept
        -> const_reference
    {
        TETL_ASSERT(pos < Size);
        return _internal_data[pos];
    }

    /// \brief Accesses the first item.
    [[nodiscard]] constexpr auto front() noexcept -> reference
    {
        return _internal_data[0];
    }

    /// \brief Accesses the first item.
    [[nodiscard]] constexpr auto front() const noexcept -> const_reference
    {
        return _internal_data[0];
    }

    /// \brief Accesses the last item.
    [[nodiscard]] constexpr auto back() noexcept -> reference
    {
        return _internal_data[Size - 1];
    }

    /// \brief Accesses the last item.
    [[nodiscard]] constexpr auto back() const noexcept -> const_reference
    {
        return _internal_data[Size - 1];
    }

    /// \brief Returns pointer to the underlying array serving as element
    /// storage. The pointer is such that range [data(); data() + size()) is
    /// always a valid range, even if the container is empty (data() is not
    /// dereferenceable in that case).
    [[nodiscard]] constexpr auto data() noexcept -> pointer
    {
        return &_internal_data[0];
    }

    /// \brief Returns pointer to the underlying array serving as element
    /// storage. The pointer is such that range [data(); data() + size()) is
    /// always a valid range, even if the container is empty (data() is not
    /// dereferenceable in that case).
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
    {
        return &_internal_data[0];
    }

    /// \brief Returns an iterator to the beginning.
    [[nodiscard]] constexpr auto begin() noexcept -> iterator
    {
        return &_internal_data[0];
    }

    /// \brief Returns an iterator to the beginning.
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return &_internal_data[0];
    }

    /// \brief Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return &_internal_data[0];
    }

    /// \brief Returns an iterator to the end.
    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        return &_internal_data[0] + size();
    }

    /// \brief Returns an iterator to the end.
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return &_internal_data[0] + size();
    }

    /// \brief Returns an const iterator to the end.
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return &_internal_data[0] + size();
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// array. It corresponds to the last element of the non-reversed array. If
    /// the array is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
    {
        return reverse_iterator(end());
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// array. It corresponds to the last element of the non-reversed array. If
    /// the array is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto rbegin() const noexcept
        -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// array. It corresponds to the last element of the non-reversed array. If
    /// the array is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto crbegin() const noexcept
        -> const_reverse_iterator
    {
        return rbegin();
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed array. It corresponds to the element preceding
    /// the first element of the non-reversed array. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
    {
        return reverse_iterator(begin());
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed array. It corresponds to the element preceding
    /// the first element of the non-reversed array. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed array. It corresponds to the element preceding
    /// the first element of the non-reversed array. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto crend() const noexcept
        -> const_reverse_iterator
    {
        return rend();
    }

    /// \brief Checks if the container has no elements, i.e. whether begin() ==
    /// end().
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return begin() == end();
    }

    /// \brief Returns the number of elements in the container, i.e.
    /// distance(begin(), end()).
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return Size;
    }

    /// \brief Returns the maximum number of elements the container is able to
    /// hold due to system or library implementation limitations, i.e.
    /// distance(begin(), end()) for the largest container.
    ///
    /// \details Because each array<T, N> is a fixed-size container, the value
    /// returned by max_size equals N (which is also the value returned by size)
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return Size;
    }

    /// \brief Assigns the given value value to all elements in the container.
    constexpr auto fill(const_reference value) -> void
    {
        for (auto& item : (*this)) { item = value; }
    }

    /// \brief Exchanges the contents of the container with those of other. Does
    /// not cause iterators and references to associate with the other
    /// container.
    constexpr auto swap(array& other) noexcept(is_nothrow_swappable_v<Type>)
        -> void
    {
        using etl::swap;
        for (auto i = size_type { 0 }; i < size(); ++i) {
            swap((*this)[i], other[i]);
        }
    }

    // NOLINTNEXTLINE(readability-identifier-naming)
    Type _internal_data[Size];
};

// One deduction guide is provided for array to provide an equivalent of
// experimental::make_array for construction of array from a variadic parameter
// pack. The program is ill-formed if (is_same_v<T, U> && ...) is not true.
// Note that it is true when sizeof...(U) is zero.
template <typename T, typename... U>
array(T, U...) -> array<T, 1 + sizeof...(U)>;

/// \brief Specializes the swap algorithm for array. Swaps the contents
/// of lhs and rhs.
/// \group swap
template <typename T, size_t N>
constexpr auto swap(array<T, N>& lhs, array<T, N>& rhs) noexcept(
    noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// \brief Provides access to the number of elements in an array as a
/// compile-time constant expression.
/// \group tuple_size
template <typename T, size_t N>
struct tuple_size<array<T, N>> : integral_constant<size_t, N> {
};

/// \brief Provides compile-time indexed access to the type of the elements of
/// the array using tuple-like interface.
/// \group tuple_element
template <size_t I, typename T>
struct tuple_element;

/// \group tuple_element
template <size_t I, typename T, size_t N>
struct tuple_element<I, array<T, N>> {
    using type = T;
};

/// \brief Checks if the contents of lhs and rhs are equal, that is, they have
/// the same number of elements and each element in lhs compares equal with the
/// element in rhs at the same position.
/// \group array_eqaulity
template <typename T, size_t N>
[[nodiscard]] constexpr auto operator==(
    array<T, N> const& lhs, array<T, N> const& rhs) -> bool
{
    return equal(lhs.begin(), lhs.end(), rhs.begin());
}

/// \group array_eqaulity
template <typename T, size_t N>
[[nodiscard]] constexpr auto operator!=(
    array<T, N> const& lhs, array<T, N> const& rhs) -> bool
{
    return !(lhs == rhs);
}

/// \brief Compares the contents of lhs and rhs lexicographically. The
/// comparison is performed by a function equivalent to lexicographical_compare.
/// \group array_compare
template <typename T, size_t N>
[[nodiscard]] constexpr auto operator<(
    array<T, N> const& lhs, array<T, N> const& rhs) -> bool
{
    return lexicographical_compare(
        lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

/// \group array_compare
template <typename T, size_t N>
[[nodiscard]] constexpr auto operator<=(
    array<T, N> const& lhs, array<T, N> const& rhs) -> bool
{
    return !(rhs < lhs);
}

/// \group array_compare
template <typename T, size_t N>
[[nodiscard]] constexpr auto operator>(
    array<T, N> const& lhs, array<T, N> const& rhs) -> bool
{
    return rhs < lhs;
}

/// \group array_compare
template <typename T, size_t N>
[[nodiscard]] constexpr auto operator>=(
    array<T, N> const& lhs, array<T, N> const& rhs) -> bool
{
    return !(lhs < rhs);
}

/// \brief Extracts the Ith element element from the array. I must be an integer
/// value in range [0, N). This is enforced at compile time as opposed to at()
/// or operator[].
/// \group get
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size>& array) noexcept -> T&
{
    static_assert(Index < Size, "array index out of range");
    return array[Index];
}

/// \group get
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size> const& array) noexcept
    -> const T&
{
    static_assert(Index < Size, "array index out of range");
    return array[Index];
}

/// \group get
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size>&& array) noexcept -> T&&
{
    static_assert(Index < Size, "array index out of range");
    return move(array[Index]);
}

/// \group get
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size> const&& array) noexcept
    -> const T&&
{
    static_assert(Index < Size, "array index out of range");
    return move(array[Index]);
}

namespace detail {
template <typename T, size_t N, size_t... I>
[[nodiscard]] constexpr auto to_array_impl(
    T (&a)[N], index_sequence<I...> /*unused*/) -> array<remove_cv_t<T>, N>
{
    return { { a[I]... } };
}

template <typename T, size_t N, size_t... I>
[[nodiscard]] constexpr auto to_array_impl(
    T(&&a)[N], index_sequence<I...> /*unused*/) -> array<remove_cv_t<T>, N>
{
    return { { move(a[I])... } };
}

} // namespace detail

/// \brief Creates a array from the one dimensional built-in array a. The
/// elements of the array are copy-initialized from the corresponding element of
/// a. Copying or moving multidimensional built-in array is not supported.
/// \group to_array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&a)[N]) -> array<remove_cv_t<T>, N>
{
    return detail::to_array_impl(a, make_index_sequence<N> {});
}

/// \group to_array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T(&&a)[N])
{
    return detail::to_array_impl(move(a), make_index_sequence<N> {});
}

} // namespace etl

#endif // TETL_ARRAY_HPP