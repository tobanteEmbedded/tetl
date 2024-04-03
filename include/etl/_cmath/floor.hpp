
// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_FLOOR_HPP
#define TETL_CMATH_FLOOR_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// Computes the largest integer value not greater than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/floor
/// \ingroup cmath
[[nodiscard]] constexpr auto floor(float arg) noexcept -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_floorf)
        return __builtin_floorf(arg);
#else
        return etl::detail::gcem::floor(arg);
#endif
    }
#if __has_builtin(__builtin_floorf)
    return __builtin_floorf(arg);
#else
    return etl::detail::gcem::floor(arg);
#endif
}

/// Computes the largest integer value not greater than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/floor
/// \ingroup cmath
[[nodiscard]] constexpr auto floorf(float arg) noexcept -> float { return etl::floor(arg); }

/// Computes the largest integer value not greater than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/floor
/// \ingroup cmath
[[nodiscard]] constexpr auto floor(double arg) noexcept -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_floor)
        return __builtin_floor(arg);
#else
        return etl::detail::gcem::floor(arg);
#endif
    }
#if __has_builtin(__builtin_floor)
    return __builtin_floor(arg);
#else
    return etl::detail::gcem::floor(arg);
#endif
}

/// Computes the largest integer value not greater than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/floor
/// \ingroup cmath
[[nodiscard]] constexpr auto floor(long double arg) noexcept -> long double { return etl::detail::gcem::floor(arg); }

/// Computes the largest integer value not greater than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/floor
/// \ingroup cmath
[[nodiscard]] constexpr auto floorl(long double arg) noexcept -> long double { return etl::floor(arg); }

/// Computes the largest integer value not greater than arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/floor
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto floor(T arg) noexcept -> double
{
    return etl::floor(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_FLOOR_HPP
