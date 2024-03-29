// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_SIN_HPP
#define TETL_CMATH_SIN_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// \brief Computes the sine of num (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/sin
[[nodiscard]] constexpr auto sin(float num) noexcept -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_sinf)
        return __builtin_sinf(num);
#else
        return etl::detail::gcem::sin(num);
#endif
    }
#if __has_builtin(__builtin_sinf)
    return __builtin_sinf(num);
#else
    return etl::detail::gcem::sin(num);
#endif
}

/// \brief Computes the sine of num (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/sin
[[nodiscard]] constexpr auto sinf(float num) noexcept -> float { return etl::sin(num); }

/// \brief Computes the sine of num (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/sin
[[nodiscard]] constexpr auto sin(double num) noexcept -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_sin)
        return __builtin_sin(num);
#else
        return etl::detail::gcem::sin(num);
#endif
    }
#if __has_builtin(__builtin_sin)
    return __builtin_sin(num);
#else
    return etl::detail::gcem::sin(num);
#endif
}

/// \brief Computes the sine of num (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/sin
[[nodiscard]] constexpr auto sin(long double num) noexcept -> long double { return etl::detail::gcem::sin(num); }

/// \brief Computes the sine of num (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/sin
[[nodiscard]] constexpr auto sinl(long double num) noexcept -> long double { return etl::sin(num); }

/// \brief Computes the sine of num (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/sin
template <integral T>
[[nodiscard]] constexpr auto sin(T num) noexcept -> double
{
    return etl::sin(static_cast<double>(num));
}

} // namespace etl

#endif // TETL_CMATH_SIN_HPP
