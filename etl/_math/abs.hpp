/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MATH_ABS_HPP
#define TETL_MATH_ABS_HPP

namespace etl {
namespace detail {

template <typename T>
[[nodiscard]] constexpr auto abs_impl(T n) noexcept -> T
{
    // constexpr auto isInt      = is_same_v<T, int>;
    // constexpr auto isLong     = is_same_v<T, long>;
    // constexpr auto isLongLong = is_same_v<T, long long>;
    // static_assert(isInt || isLong || isLongLong);

    if (n >= T(0)) { return n; }
    return n * T(-1);
}

} // namespace detail

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
/// \group abs
/// \module Numeric
[[nodiscard]] constexpr auto abs(int n) noexcept -> int
{
    return detail::abs_impl<int>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long n) noexcept -> long
{
    return detail::abs_impl<long>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long long n) noexcept -> long long
{
    return detail::abs_impl<long long>(n);
}

[[nodiscard]] constexpr auto abs(float n) noexcept -> float
{
    return detail::abs_impl<float>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(double n) noexcept -> double
{
    return detail::abs_impl<double>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long double n) noexcept -> long double
{
    return detail::abs_impl<long double>(n);
}

[[nodiscard]] constexpr auto fabs(float n) noexcept -> float
{
    return detail::abs_impl<float>(n);
}

[[nodiscard]] constexpr auto fabsf(float n) noexcept -> float
{
    return detail::abs_impl<float>(n);
}

[[nodiscard]] constexpr auto fabs(double n) noexcept -> double
{
    return detail::abs_impl<double>(n);
}

[[nodiscard]] constexpr auto fabs(long double n) noexcept -> long double
{
    return detail::abs_impl<long double>(n);
}

[[nodiscard]] constexpr auto fabsl(long double n) noexcept -> long double
{
    return detail::abs_impl<long double>(n);
}

} // namespace etl

#endif // TETL_MATH_ABS_HPP