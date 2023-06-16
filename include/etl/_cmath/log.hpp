// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_LOG_HPP
#define TETL_CMATH_LOG_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(float v) noexcept -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_logf)
        return __builtin_logf(v);
#else
        return etl::detail::gcem::log(v);
#endif
    }
#if __has_builtin(__builtin_logf)
    return __builtin_logf(v);
#else
    return etl::detail::gcem::log(v);
#endif
}

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto logf(float v) noexcept -> float { return etl::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(double v) noexcept -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_log)
        return __builtin_log(v);
#else
        return etl::detail::gcem::log(v);
#endif
    }
#if __has_builtin(__builtin_log)
    return __builtin_log(v);
#else
    return etl::detail::gcem::log(v);
#endif
}

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(long double v) noexcept -> long double { return etl::detail::gcem::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto logl(long double v) noexcept -> long double { return etl::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
template <integral T>
[[nodiscard]] constexpr auto log(T arg) noexcept -> double
{
    return etl::log(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LOG_HPP
