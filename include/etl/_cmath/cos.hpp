// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_CMATH_HPP
#define TETL_CMATH_CMATH_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// Computes the cosine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/cos
/// \ingroup cmath
[[nodiscard]] constexpr auto cos(float arg) noexcept -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_cosf)
        return __builtin_cosf(arg);
#else
        return etl::detail::gcem::cos(arg);
#endif
    }
#if __has_builtin(__builtin_cosf)
    return __builtin_cosf(arg);
#else
    return etl::detail::gcem::cos(arg);
#endif
}

/// Computes the cosine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/cos
/// \ingroup cmath
[[nodiscard]] constexpr auto cosf(float arg) noexcept -> float { return etl::cos(arg); }

/// Computes the cosine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/cos
/// \ingroup cmath
[[nodiscard]] constexpr auto cos(double arg) noexcept -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_cos)
        return __builtin_cos(arg);
#else
        return etl::detail::gcem::cos(arg);
#endif
    }
#if __has_builtin(__builtin_cos)
    return __builtin_cos(arg);
#else
    return etl::detail::gcem::cos(arg);
#endif
}

/// Computes the cosine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/cos
/// \ingroup cmath
[[nodiscard]] constexpr auto cos(long double arg) noexcept -> long double { return etl::detail::gcem::cos(arg); }

/// Computes the cosine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/cos
/// \ingroup cmath
[[nodiscard]] constexpr auto cosl(long double arg) noexcept -> long double { return etl::cos(arg); }

/// Computes the cosine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/cos
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto cos(T arg) noexcept -> double
{
    return etl::cos(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_CMATH_HPP
