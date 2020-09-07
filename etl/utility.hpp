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

#ifndef TAETL_UTILITY_HPP
#define TAETL_UTILITY_HPP

#include "etl/limits.hpp"
#include "etl/type_traits.hpp"

namespace etl
{
/**
 * @brief Converts any type T to a reference type, making it possible to use
 * member functions in decltype expressions without the need to go through
 * constructors.
 */
template <class T>
auto declval() noexcept -> typename etl::add_rvalue_reference<T>::type;

/**
 * @brief etl::move is used to indicate that an object t may be "moved from",
 * i.e. allowing the efficient transfer of resources from t to another object.
 * In particular, etl::move produces an xvalue expression that identifies its
 * argument t. It is exactly equivalent to a static_cast to an rvalue reference
 * type.
 * @tparam T
 * @param t
 * @return static_cast<typename etl::remove_reference<T>::type&&>(t)
 */
template <class T>
constexpr auto move(T&& t) noexcept -> typename etl::remove_reference<T>::type&&
{
    return static_cast<typename etl::remove_reference<T>::type&&>(t);
}

/**
 * @brief Forwards lvalues as either lvalues or as rvalues, depending on T.
 *
 * @details When t is a forwarding reference (a function argument that is
 * declared as an rvalue reference to a cv-unqualified function template
 * parameter), this overload forwards the argument to another function with the
 * value category it had when passed to the calling function.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/forward
 */
template <class T>
constexpr auto forward(etl::remove_reference_t<T>& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

/**
 * @brief Forwards rvalues as rvalues and prohibits forwarding of rvalues as
 * lvalues.
 *
 * @details This overload makes it possible to forward a result of an expression
 * (such as function call), which may be rvalue or lvalue, as the original value
 * category of a forwarding reference argument.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/forward
 */
template <class T>
constexpr auto forward(etl::remove_reference_t<T>&& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

/**
 * @brief Replaces the value of obj with new_value and returns the old value of
 * obj.
 * @return The old value of obj.
 */
template <class T, class U = T>
[[nodiscard]] constexpr auto exchange(T& obj, U&& new_value) -> T
{
    T old_value = etl::move(obj);
    obj         = etl::forward<U>(new_value);
    return old_value;
}

/**
 * @brief Forms lvalue reference to const type of t.
 */
template <class T>
[[nodiscard]] constexpr auto as_const(T& t) noexcept -> etl::add_const_t<T>&
{
    return t;
}

/**
 * @brief Const rvalue reference overload is deleted to disallow rvalue
 * arguments.
 */
template <class T>
constexpr auto as_const(const T&&) -> void
    = delete;

namespace detail
{
template <class T>
struct is_integer_and_not_char
    : etl::integral_constant<
          bool,
          is_integral_v<
              T> && (!is_same_v<T, bool> && !is_same_v<T, char> && !is_same_v<T, char16_t> && !is_same_v<T, char32_t> && !is_same_v<T, wchar_t>)>
{
};
}  // namespace detail

/**
 * @brief Compare the values of two integers t and u. Unlike builtin comparison
 * operators, negative signed integers always compare less than (and not equal
 * to) unsigned integers: the comparison is safe against lossy integer
 * conversion.
 * @details It is a compile-time error if either T or U is not a signed or
 * unsigned integer type (including standard integer type and extended integer
 * type).
 * @ref https://en.cppreference.com/w/cpp/utility/intcmp
 */
template <class T, class U>
[[nodiscard]] constexpr auto cmp_equal(T t, U u) noexcept
    -> enable_if_t<detail::is_integer_and_not_char<T>::value
                       && detail::is_integer_and_not_char<U>::value,
                   bool>
{
    using UT = etl::make_unsigned_t<T>;
    using UU = etl::make_unsigned_t<U>;

    if constexpr (etl::is_signed_v<T> == etl::is_signed_v<U>) { return t == u; }
    else if constexpr (etl::is_signed_v<T>)
    {
        return t < 0 ? false : UT(t) == u;
    }
    else
    {
        return u < 0 ? false : t == UU(u);
    }
}

/**
 * @brief Compare the values of two integers t and u. Unlike builtin comparison
 * operators, negative signed integers always compare less than (and not equal
 * to) unsigned integers: the comparison is safe against lossy integer
 * conversion.
 * @details It is a compile-time error if either T or U is not a signed or
 * unsigned integer type (including standard integer type and extended integer
 * type).
 * @ref https://en.cppreference.com/w/cpp/utility/intcmp
 */
template <class T, class U>
[[nodiscard]] constexpr auto cmp_not_equal(T t, U u) noexcept
    -> enable_if_t<detail::is_integer_and_not_char<T>::value
                       && detail::is_integer_and_not_char<U>::value,
                   bool>
{
    return !cmp_equal(t, u);
}

/**
 * @brief Compare the values of two integers t and u. Unlike builtin comparison
 * operators, negative signed integers always compare less than (and not equal
 * to) unsigned integers: the comparison is safe against lossy integer
 * conversion.
 * @details It is a compile-time error if either T or U is not a signed or
 * unsigned integer type (including standard integer type and extended integer
 * type).
 * @ref https://en.cppreference.com/w/cpp/utility/intcmp
 */
template <class T, class U>
[[nodiscard]] constexpr auto cmp_less(T t, U u) noexcept
    -> enable_if_t<detail::is_integer_and_not_char<T>::value
                       && detail::is_integer_and_not_char<U>::value,
                   bool>
{
    using UT = etl::make_unsigned_t<T>;
    using UU = etl::make_unsigned_t<U>;
    if constexpr (etl::is_signed_v<T> == etl::is_signed_v<U>)
        return t < u;
    else if constexpr (etl::is_signed_v<T>)
        return t < 0 ? true : UT(t) < u;
    else
        return u < 0 ? false : t < UU(u);
}

/**
 * @brief Compare the values of two integers t and u. Unlike builtin comparison
 * operators, negative signed integers always compare less than (and not equal
 * to) unsigned integers: the comparison is safe against lossy integer
 * conversion.
 * @details It is a compile-time error if either T or U is not a signed or
 * unsigned integer type (including standard integer type and extended integer
 * type).
 * @ref https://en.cppreference.com/w/cpp/utility/intcmp
 */
template <class T, class U>
[[nodiscard]] constexpr auto cmp_greater(T t, U u) noexcept
    -> enable_if_t<detail::is_integer_and_not_char<T>::value
                       && detail::is_integer_and_not_char<U>::value,
                   bool>
{
    return cmp_less(u, t);
}

/**
 * @brief Compare the values of two integers t and u. Unlike builtin comparison
 * operators, negative signed integers always compare less than (and not equal
 * to) unsigned integers: the comparison is safe against lossy integer
 * conversion.
 * @details It is a compile-time error if either T or U is not a signed or
 * unsigned integer type (including standard integer type and extended integer
 * type).
 * @ref https://en.cppreference.com/w/cpp/utility/intcmp
 */
template <class T, class U>
[[nodiscard]] constexpr auto cmp_less_equal(T t, U u) noexcept
    -> enable_if_t<detail::is_integer_and_not_char<T>::value
                       && detail::is_integer_and_not_char<U>::value,
                   bool>
{
    return !cmp_greater(t, u);
}

/**
 * @brief Compare the values of two integers t and u. Unlike builtin comparison
 * operators, negative signed integers always compare less than (and not equal
 * to) unsigned integers: the comparison is safe against lossy integer
 * conversion.
 * @details It is a compile-time error if either T or U is not a signed or
 * unsigned integer type (including standard integer type and extended integer
 * type).
 * @ref https://en.cppreference.com/w/cpp/utility/intcmp
 */
template <class T, class U>
[[nodiscard]] constexpr auto cmp_greater_equal(T t, U u) noexcept
    -> enable_if_t<detail::is_integer_and_not_char<T>::value
                       && detail::is_integer_and_not_char<U>::value,
                   bool>
{
    return !cmp_less(t, u);
}

/**
 * @brief Returns true if the value of t is in the range of values that can be
 * represented in R, that is, if t can be converted to R without data loss.
 *
 * @details It is a compile-time error if either T or R is not a signed or
 * unsigned integer type (including standard integer type and extended integer
 * type). This function cannot be used with etl::byte, char, char8_t, char16_t,
 * char32_t, wchar_t and bool.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/in_range
 */
template <class R, class T>
[[nodiscard]] constexpr auto in_range(T t) noexcept
    -> enable_if_t<detail::is_integer_and_not_char<T>::value, bool>
{
    return etl::cmp_greater_equal(t, etl::numeric_limits<R>::min())
           && etl::cmp_less_equal(t, etl::numeric_limits<R>::max());
}

/**
 * @brief etl::pair is a class template that provides a way to store two
 * heterogeneous objects as a single unit. A pair is a specific case of a
 * etl::tuple with two elements. If neither T1 nor T2 is a possibly cv-qualified
 * class type with non-trivial destructor, or array thereof, the destructor of
 * pair is trivial.
 * @ref https://en.cppreference.com/w/cpp/utility/pair
 */
template <class T1, class T2>
struct pair
{
    using first_type  = T1;
    using second_type = T2;

    constexpr pair() = default;
    constexpr pair(T1 const& t1, T2 const& t2) : first {t1}, second {t2} { }

    template <class U1, class U2>
    constexpr pair(pair<U1, U2> const& p) : first {p.first}, second {p.second}
    {
    }

    constexpr pair(pair const& p) = default;

    constexpr auto operator=(pair const& p) -> pair&
    {
        if (&p == this) { return *this; }
        first  = p.first;
        second = p.second;
        return *this;
    }

    template <class U1, class U2>
    constexpr auto operator=(pair<U1, U2> const& p) -> pair&
    {
        first  = p.first;
        second = p.second;
        return *this;
    }

    constexpr pair(pair&& p) noexcept = default;

    constexpr auto operator=(pair&& p) noexcept -> pair&
    {
        first  = etl::move(p.first);
        second = etl::move(p.second);
        return *this;
    }

    template <class U1, class U2>
    constexpr auto operator=(pair<U1, U2>&& p) -> pair&
    {
        first  = etl::move(p.first);
        second = etl::move(p.second);
        return *this;
    }

    ~pair() noexcept = default;

    T1 first {};
    T2 second {};
};

/**
 * @brief Creates a etl::pair object, deducing the target type from the types of
 * arguments.
 *
 * @details The deduced types V1 and V2 are etl::decay<T1>::type and
 * etl::decay<T2>::type (the usual type transformations applied to arguments of
 * functions passed by value).
 *
 * @ref https://en.cppreference.com/w/cpp/utility/pair/make_pair
 */
template <class T1, class T2>
[[nodiscard]] constexpr auto make_pair(T1&& t, T2&& u)
    -> etl::pair<typename etl::decay<T1>::type, typename etl::decay<T2>::type>
{
    return {t, u};
}

/**
 * @brief Tests if both elements of lhs and rhs are equal, that is, compares
 * lhs.first with rhs.first and lhs.second with rhs.second.
 */
template <class T1, class T2>
constexpr auto operator==(etl::pair<T1, T2> const& lhs,
                          etl::pair<T1, T2> const& rhs) -> bool
{
    return (lhs.first == rhs.first) && (lhs.second == rhs.second);
}

/**
 * @brief Tests if both elements of lhs and rhs are equal, that is, compares
 * lhs.first with rhs.first and lhs.second with rhs.second.
 */
template <class T1, class T2>
constexpr auto operator!=(etl::pair<T1, T2> const& lhs,
                          etl::pair<T1, T2> const& rhs) -> bool
{
    return !(lhs == rhs);
}

/**
 * @brief Compares lhs and rhs lexicographically by operator<, that is, compares
 * the first elements and only if they are equivalent, compares the second
 * elements.
 */
template <class T1, class T2>
constexpr auto operator<(etl::pair<T1, T2> const& lhs,
                         etl::pair<T1, T2> const& rhs) -> bool
{
    if (lhs.first < rhs.first) { return true; }
    if (rhs.first < lhs.first) { return false; }
    if (lhs.second < rhs.second) { return true; }
    return false;
}

/**
 * @brief Compares lhs and rhs lexicographically by operator<, that is, compares
 * the first elements and only if they are equivalent, compares the second
 * elements.
 */
template <class T1, class T2>
constexpr auto operator<=(etl::pair<T1, T2> const& lhs,
                          etl::pair<T1, T2> const& rhs) -> bool
{
    return !(rhs < lhs);
}

/**
 * @brief Compares lhs and rhs lexicographically by operator<, that is, compares
 * the first elements and only if they are equivalent, compares the second
 * elements.
 */
template <class T1, class T2>
constexpr auto operator>(etl::pair<T1, T2> const& lhs,
                         etl::pair<T1, T2> const& rhs) -> bool
{
    return rhs < lhs;
}

/**
 * @brief Compares lhs and rhs lexicographically by operator<, that is, compares
 * the first elements and only if they are equivalent, compares the second
 * elements.
 */
template <class T1, class T2>
constexpr auto operator>=(etl::pair<T1, T2> const& lhs,
                          etl::pair<T1, T2> const& rhs) -> bool
{
    return !(lhs < rhs);
}
}  // namespace etl

#endif  // TAETL_UTILITY_HPP
