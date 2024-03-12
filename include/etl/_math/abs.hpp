// SPDX-License-Identifier: BSL-1.0

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

    if (n >= T(0)) {
        return n;
    }
    return n * T(-1);
}

} // namespace detail

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
[[nodiscard]] constexpr auto abs(int n) noexcept -> int { return detail::abs_impl<int>(n); }

[[nodiscard]] constexpr auto abs(long n) noexcept -> long { return detail::abs_impl<long>(n); }

[[nodiscard]] constexpr auto abs(long long n) noexcept -> long long { return detail::abs_impl<long long>(n); }

[[nodiscard]] constexpr auto abs(float n) noexcept -> float { return detail::abs_impl<float>(n); }

[[nodiscard]] constexpr auto abs(double n) noexcept -> double { return detail::abs_impl<double>(n); }

[[nodiscard]] constexpr auto abs(long double n) noexcept -> long double { return detail::abs_impl<long double>(n); }

[[nodiscard]] constexpr auto fabs(float n) noexcept -> float { return detail::abs_impl<float>(n); }

[[nodiscard]] constexpr auto fabsf(float n) noexcept -> float { return detail::abs_impl<float>(n); }

[[nodiscard]] constexpr auto fabs(double n) noexcept -> double { return detail::abs_impl<double>(n); }

[[nodiscard]] constexpr auto fabs(long double n) noexcept -> long double { return detail::abs_impl<long double>(n); }

[[nodiscard]] constexpr auto fabsl(long double n) noexcept -> long double { return detail::abs_impl<long double>(n); }

} // namespace etl

#endif // TETL_MATH_ABS_HPP
