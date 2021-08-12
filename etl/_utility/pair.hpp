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

#ifndef TETL_UTILITY_PAIR_HPP
#define TETL_UTILITY_PAIR_HPP

#include "etl/_algorithm/swap.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_tuple/tuple_element.hpp"
#include "etl/_tuple/tuple_size.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/integral_constant.hpp"
#include "etl/_type_traits/is_assignable.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_default_constructible.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief etl::pair is a class template that provides a way to store two
/// heterogeneous objects as a single unit. A pair is a specific case of a
/// etl::tuple with two elements. If neither T1 nor T2 is a possibly
/// cv-qualified class type with non-trivial destructor, or array thereof, the
/// destructor of pair is trivial.
///
/// \notes
/// [cppreference.com/w/cpp/utility/pair](https://en.cppreference.com/w/cpp/utility/pair)
///
/// \todo Add conditional explicit when C++20 is available.
template <typename T1, typename T2>
struct pair {
    using first_type  = T1;
    using second_type = T2;

    /// \brief Default constructor. Value-initializes both elements of the pair,
    /// first and second.
    TETL_REQUIRES(
        is_default_constructible_v<T1>&& is_default_constructible_v<T2>)
    constexpr pair() : first {}, second {} { }

    /// \brief Initializes first with x and second with y.
    TETL_REQUIRES(is_copy_constructible_v<T1>&& is_copy_constructible_v<T2>)
    constexpr pair(T1 const& t1, T2 const& t2) : first { t1 }, second { t2 } { }

    /// \brief Initializes first with etl::forward<U1>(x) and second with
    /// etl::forward<U2>(y).
    template <typename U1 = T1, typename U2 = T2,
        TETL_REQUIRES_(is_constructible_v<U1&&, first_type>&&
                is_constructible_v<U2&&, second_type>)>
    constexpr pair(U1&& x, U2&& y)
        : first(etl::forward<U1>(x)), second(etl::forward<U2>(y))
    {
    }

    /// \brief Initializes first with p.first and second with p.second.
    template <typename U1, typename U2,
        TETL_REQUIRES_(is_constructible_v<first_type, U1 const&>&&
                is_constructible_v<second_type, U2 const&>)>
    constexpr pair(pair<U1, U2> const& p)
        : first { static_cast<T1>(p.first) }
        , second { static_cast<T2>(p.second) }
    {
    }

    /// \brief Initializes first with etl::forward<U1>(p.first) and second with
    /// etl::forward<U2>(p.second).
    template <typename U1, typename U2,
        TETL_REQUIRES_(is_constructible_v<first_type, U1&&>&&
                is_constructible_v<second_type, U2&&>)>
    constexpr pair(pair<U1, U2>&& p)
        : first(etl::forward<U1>(p.first)), second(etl::forward<U2>(p.second))
    {
    }

    /// \brief Copy constructor is defaulted, and is constexpr if copying of
    /// both elements satisfies the requirements on constexpr functions.
    constexpr pair(pair const& p) = default;

    /// \brief Move constructor is defaulted, and is constexpr if moving of both
    /// elements satisfies the requirements on constexpr functions.
    constexpr pair(pair&& p) noexcept = default;

    /// \brief Defaulted destructor.
    ~pair() noexcept = default;

    constexpr auto operator=(pair const& p) -> pair&
    {
        if (&p == this) { return *this; }
        first  = p.first;
        second = p.second;
        return *this;
    }

    template <typename U1, typename U2,
        TETL_REQUIRES_(is_assignable_v<first_type&, U1 const&>&&
                is_assignable_v<second_type&, U2 const&>)>
    constexpr auto operator=(pair<U1, U2> const& p) -> pair&
    {
        first  = p.first;
        second = p.second;
        return *this;
    }

    TETL_REQUIRES(
        is_move_assignable_v<first_type>&& is_move_assignable_v<second_type>)
    constexpr auto operator=(pair&& p) noexcept -> pair&
    {
        first  = etl::move(p.first);
        second = etl::move(p.second);
        return *this;
    }

    template <typename U1, typename U2,
        TETL_REQUIRES_(is_assignable_v<first_type&, U1>&&
                is_assignable_v<second_type&, U2>)>
    constexpr auto operator=(pair<U1, U2>&& p) -> pair&
    {
        first  = etl::move(p.first);
        second = etl::move(p.second);
        return *this;
    }

    constexpr void swap(pair& other) noexcept(
        (is_nothrow_swappable_v<
             first_type> and is_nothrow_swappable_v<second_type>))
    {
        using ::etl::swap;
        swap(first, other.first);
        swap(second, other.second);
    }

    T1 first;  // NOLINT(modernize-use-default-member-init)
    T2 second; // NOLINT(modernize-use-default-member-init)

}; // namespace etl

// One deduction guide is provided for pair to account for the edge
// cases missed by the implicit deduction guides. In particular, non-copyable
// arguments and array to pointer conversion.
template <typename T1, typename T2>
pair(T1, T2) -> pair<T1, T2>;

/// \brief Swaps the contents of x and y. Equivalent to x.swap(y).
template <typename T1, typename T2>
constexpr auto swap(pair<T1, T2>& lhs, pair<T1, T2>& rhs) noexcept(
    noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// \brief Creates a etl::pair object, deducing the target type from the types
/// of arguments.
///
/// \details The deduced types V1 and V2 are etl::decay<T1>::type and
/// etl::decay<T2>::type (the usual type transformations applied to arguments of
/// functions passed by value).
///
/// \notes
/// [cppreference.com/w/cpp/utility/pair/make_pair](https://en.cppreference.com/w/cpp/utility/pair/make_pair)
template <typename T1, typename T2>
[[nodiscard]] constexpr auto make_pair(T1&& t, T2&& u)
    -> pair<decay_t<T1>, decay_t<T2>>
{
    return { forward<T1>(t), forward<T2>(u) };
}

/// \brief Tests if both elements of lhs and rhs are equal, that is, compares
/// lhs.first with rhs.first and lhs.second with rhs.second.
template <typename T1, typename T2>
constexpr auto operator==(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs)
    -> bool
{
    return (lhs.first == rhs.first) && (lhs.second == rhs.second);
}

/// \brief Tests if both elements of lhs and rhs are equal, that is, compares
/// lhs.first with rhs.first and lhs.second with rhs.second.
template <typename T1, typename T2>
constexpr auto operator!=(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs)
    -> bool
{
    return !(lhs == rhs);
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator<(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs)
    -> bool
{
    if (lhs.first < rhs.first) { return true; }
    if (rhs.first < lhs.first) { return false; }
    if (lhs.second < rhs.second) { return true; }
    return false;
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator<=(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs)
    -> bool
{
    return !(rhs < lhs);
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator>(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs)
    -> bool
{
    return rhs < lhs;
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator>=(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs)
    -> bool
{
    return !(lhs < rhs);
}

/// \brief The partial specialization of tuple_size for pairs provides a
/// compile-time way to obtain the number of elements in a pair, which is always
/// 2, using tuple-like syntax.
template <typename T1, typename T2>
struct tuple_size<pair<T1, T2>> : integral_constant<size_t, 2> {
};

/// \brief The partial specializations of tuple_element for pairs provide
/// compile-time access to the types of the pair's elements, using tuple-like
/// syntax. The program is ill-formed if I >= 2.
template <size_t I, typename T1, typename T2>
struct tuple_element<I, pair<T1, T2>> {
    static_assert(I < 2, "pair index out of range");
    using type = conditional_t<I == 0, T1, T2>;
};

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
constexpr auto get(pair<T1, T2>& p) noexcept
    -> tuple_element_t<I, pair<T1, T2>>&
{
    if constexpr (I == 0) {
        return p.first;
    } else {
        return p.second;
    }
}

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
[[nodiscard]] constexpr auto get(pair<T1, T2> const& p) noexcept
    -> tuple_element_t<I, pair<T1, T2>> const&
{
    if constexpr (I == 0) {
        return p.first;
    } else {
        return p.second;
    }
}

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
[[nodiscard]] constexpr auto get(pair<T1, T2>&& p) noexcept
    -> tuple_element_t<I, pair<T1, T2>>&&
{
    if constexpr (I == 0) {
        return move(p.first);
    } else {
        return move(p.second);
    }
}

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
[[nodiscard]] constexpr auto get(pair<T1, T2> const&& p) noexcept
    -> tuple_element_t<I, pair<T1, T2>> const&&
{
    if constexpr (I == 0) {
        return move(p.first);
    } else {
        return move(p.second);
    }
}

} // namespace etl

#endif // TETL_UTILITY_PAIR_HPP