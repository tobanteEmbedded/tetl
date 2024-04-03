// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_EXP_HPP
#define TETL_CMATH_EXP_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// Computes e (Euler's number, 2.7182...) raised to the given power v
/// \details https://en.cppreference.com/w/cpp/numeric/math/exp
/// \ingroup cmath
[[nodiscard]] constexpr auto exp(float v) noexcept -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_expf)
        return __builtin_expf(v);
#else
        return etl::detail::gcem::exp(v);
#endif
    }
#if __has_builtin(__builtin_expf)
    return __builtin_expf(v);
#else
    return etl::detail::gcem::exp(v);
#endif
}

/// Computes e (Euler's number, 2.7182...) raised to the given power v
/// \details https://en.cppreference.com/w/cpp/numeric/math/exp
/// \ingroup cmath
[[nodiscard]] constexpr auto expf(float v) noexcept -> float { return etl::exp(v); }

/// Computes e (Euler's number, 2.7182...) raised to the given power v
/// \details https://en.cppreference.com/w/cpp/numeric/math/exp
/// \ingroup cmath
[[nodiscard]] constexpr auto exp(double v) noexcept -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_exp)
        return __builtin_exp(v);
#else
        return etl::detail::gcem::exp(v);
#endif
    }
#if __has_builtin(__builtin_exp)
    return __builtin_exp(v);
#else
    return etl::detail::gcem::exp(v);
#endif
}

/// Computes e (Euler's number, 2.7182...) raised to the given power v
/// \details https://en.cppreference.com/w/cpp/numeric/math/exp
/// \ingroup cmath
[[nodiscard]] constexpr auto exp(long double v) noexcept -> long double { return etl::detail::gcem::exp(v); }

/// Computes e (Euler's number, 2.7182...) raised to the given power v
/// \details https://en.cppreference.com/w/cpp/numeric/math/exp
/// \ingroup cmath
[[nodiscard]] constexpr auto expl(long double v) noexcept -> long double { return etl::exp(v); }

/// Computes e (Euler's number, 2.7182...) raised to the given power v
/// \details https://en.cppreference.com/w/cpp/numeric/math/exp
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto exp(T v) noexcept -> double
{
    return etl::exp(static_cast<double>(v));
}

} // namespace etl

#endif // TETL_CMATH_EXP_HPP
