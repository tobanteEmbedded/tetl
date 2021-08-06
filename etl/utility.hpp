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

#ifndef TETL_UTILITY_HPP
#define TETL_UTILITY_HPP

#include "etl/version.hpp"

#include "etl/limits.hpp"
#include "etl/type_traits.hpp"

#include "etl/detail/algo_swap.hpp"
#include "etl/detail/sfinae.hpp"
#include "etl/detail/tuple_size.hpp"

/// \file This header is part of the general utility library.

namespace etl {
/// \brief Converts any type T to a reference type, making it possible to use
/// member functions in decltype expressions without the need to go through
/// constructors.
template <typename T>
auto declval() noexcept -> add_rvalue_reference_t<T>; // NOLINT

/// \brief move is used to indicate that an object t may be "moved from",
/// i.e. allowing the efficient transfer of resources from t to another object.
/// In particular, move produces an xvalue expression that identifies its
/// argument t. It is exactly equivalent to a static_cast to an rvalue reference
/// type.
///
/// \returns `static_cast<remove_reference_t<T>&&>(t)`
template <typename T>
constexpr auto move(T&& t) noexcept -> remove_reference_t<T>&&
{
    return static_cast<remove_reference_t<T>&&>(t);
}

/// \brief Forwards lvalues as either lvalues or as rvalues, depending on T.
/// When t is a forwarding reference (a function argument that is declared as an
/// rvalue reference to a cv-unqualified function template parameter), this
/// overload forwards the argument to another function with the value category
/// it had when passed to the calling function.
///
/// \notes
/// [cppreference.com/w/cpp/utility/forward](https://en.cppreference.com/w/cpp/utility/forward)
/// \group forward
template <typename T>
constexpr auto forward(remove_reference_t<T>& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

/// \group forward
template <typename T>
constexpr auto forward(remove_reference_t<T>&& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

/// \brief Replaces the value of obj with new_value and returns the old value of
/// obj.
/// \returns The old value of obj.
template <typename T, typename U = T>
[[nodiscard]] constexpr auto exchange(T& obj, U&& newValue) -> T
{
    T oldValue = move(obj);
    obj        = forward<U>(newValue);
    return oldValue;
}

/// \brief Forms lvalue reference to const type of t.
/// \group as_const
template <typename T>
[[nodiscard]] constexpr auto as_const(T& t) noexcept -> add_const_t<T>&
{
    return t;
}

/// \group as_const
template <typename T>
constexpr auto as_const(T const&&) -> void
    = delete;

/// \brief Converts an enumeration to its underlying type.
///
/// https://en.cppreference.com/w/cpp/utility/to_underlying
template <typename Enum>
[[nodiscard]] constexpr auto to_underlying(Enum e) noexcept
    -> underlying_type_t<Enum>
{
    return static_cast<underlying_type_t<Enum>>(e);
}

namespace detail {
    // clang-format off
template <typename T>
struct is_integer_and_not_char
    : bool_constant<
        is_integral_v<T>
        && (!is_same_v<T, bool>
        && !is_same_v<T, char>
        && !is_same_v<T, char16_t>
        && !is_same_v<T, char32_t>
        && !is_same_v<T, wchar_t>)>
{
};

    // clang-format on

    template <typename T>
    inline constexpr auto is_integer_and_not_char_v
        = is_integer_and_not_char<T>::value;

} // namespace detail

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(detail::is_integer_and_not_char_v<T>&&
            detail::is_integer_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_equal(T t, U u) noexcept -> bool
{
    using UT = etl::make_unsigned_t<T>;
    using UU = etl::make_unsigned_t<U>;

    if constexpr (etl::is_signed_v<T> == etl::is_signed_v<U>) {
        return t == u;
    } else if constexpr (etl::is_signed_v<T>) {
        return t < 0 ? false : UT(t) == u;
    } else {
        return u < 0 ? false : t == UU(u);
    }
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(detail::is_integer_and_not_char_v<T>&&
            detail::is_integer_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_not_equal(T t, U u) noexcept -> bool
{
    return !cmp_equal(t, u);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(detail::is_integer_and_not_char_v<T>&&
            detail::is_integer_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_less(T t, U u) noexcept -> bool
{
    using UT = etl::make_unsigned_t<T>;
    using UU = etl::make_unsigned_t<U>;
    if constexpr (etl::is_signed_v<T> == etl::is_signed_v<U>) {
        return t < u;
    } else if constexpr (etl::is_signed_v<T>) {
        return t < 0 ? true : UT(t) < u;
    } else {
        return u < 0 ? false : t < UU(u);
    }
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(detail::is_integer_and_not_char_v<T>&&
            detail::is_integer_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_greater(T t, U u) noexcept -> bool
{
    return cmp_less(u, t);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(detail::is_integer_and_not_char_v<T>&&
            detail::is_integer_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_less_equal(T t, U u) noexcept -> bool
{
    return !cmp_greater(t, u);
}

/// \brief Compare the values of two integers t and u. Unlike builtin comparison
/// operators, negative signed integers always compare less than (and not equal
/// to) unsigned integers: the comparison is safe against lossy integer
/// conversion.
/// \details It is a compile-time error if either T or U is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type).
/// \notes
/// [cppreference.com/w/cpp/utility/intcmp](https://en.cppreference.com/w/cpp/utility/intcmp)
template <typename T, typename U,
    TETL_REQUIRES_(detail::is_integer_and_not_char_v<T>&&
            detail::is_integer_and_not_char_v<U>)>
[[nodiscard]] constexpr auto cmp_greater_equal(T t, U u) noexcept -> bool
{
    return !cmp_less(t, u);
}

/// \brief Returns true if the value of t is in the range of values that can be
/// represented in R, that is, if t can be converted to R without data loss.
///
/// \details It is a compile-time error if either T or R is not a signed or
/// unsigned integer type (including standard integer type and extended integer
/// type). This function cannot be used with etl::byte, char, char8_t, char16_t,
/// char32_t, wchar_t and bool.
///
/// \notes
/// [cppreference.com/w/cpp/utility/in_range](https://en.cppreference.com/w/cpp/utility/in_range)
template <typename R, typename T,
    TETL_REQUIRES_(detail::is_integer_and_not_char_v<T>)>
[[nodiscard]] constexpr auto in_range(T t) noexcept -> bool
{
    return etl::cmp_greater_equal(t, etl::numeric_limits<R>::min())
           && etl::cmp_less_equal(t, etl::numeric_limits<R>::max());
}

/// \brief etl::piecewise_construct_t is an empty class tag type used to
/// disambiguate between different functions that take two tuple arguments.
///
/// \details The overloads that do not use etl::piecewise_construct_t assume
/// that each tuple argument becomes the element of a pair. The overloads that
/// use etl::piecewise_construct_t assume that each tuple argument is used to
/// construct, piecewise, a new object of specified type, which will become the
/// element of the pair.
///
/// \notes
/// [cppreference.com/w/cpp/utility/piecewise_construct_t](https://en.cppreference.com/w/cpp/utility/piecewise_construct_t)
struct piecewise_construct_t {
    explicit piecewise_construct_t() = default;
};

/// \brief The constant etl::piecewise_construct is an instance of an empty
/// struct tag type etl::piecewise_construct_t.
inline constexpr piecewise_construct_t piecewise_construct {};

/// \brief Disambiguation tags that can be passed to the constructors of
/// `optional`, `variant`, and `any` to indicate that the contained
/// object should be constructed in-place, and (for the latter two) the type of
/// the object to be constructed.
///
/// The corresponding type/type templates `in_place_t`, `in_place_type_t`
/// and `in_place_index_t` can be used in the constructor's parameter list to
/// match the intended tag.
struct in_place_t {
    explicit in_place_t() = default;
};

inline constexpr auto in_place = in_place_t {};

/// \brief Disambiguation tags that can be passed to the constructors of
/// etl::optional, etl::variant, and etl::any to indicate that the contained
/// object should be constructed in-place, and (for the latter two) the type of
/// the object to be constructed.
///
/// \details The corresponding type/type templates etl::in_place_t,
/// etl::in_place_type_t and etl::in_place_index_t can be used in the
/// constructor's parameter list to match the intended tag.
template <typename T>
struct in_place_type_t {
    explicit in_place_type_t() = default;
};

template <typename T>
inline constexpr auto in_place_type = in_place_type_t<T> {};

/// \brief Disambiguation tags that can be passed to the constructors of
/// etl::optional, etl::variant, and etl::any to indicate that the contained
/// object should be constructed in-place, and (for the latter two) the type of
/// the object to be constructed.
///
/// \details The corresponding type/type templates etl::in_place_t,
/// etl::in_place_type_t and etl::in_place_index_t can be used in the
/// constructor's parameter list to match the intended tag.
template <size_t I>
struct in_place_index_t {
    explicit in_place_index_t() = default;
};

template <size_t I>
inline constexpr auto in_place_index = in_place_index_t<I> {};

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
    template <typename U1, typename U2,
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

#endif // TETL_UTILITY_HPP
