// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_LOG_HPP
#define TETL_CMATH_LOG_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct log {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float v) const noexcept -> Float
    {
        if (not etl::is_constant_evaluated()) {
#if __has_builtin(__builtin_logf)
            if constexpr (etl::is_same_v<Float, float>) {
                return __builtin_logf(v);
            }
#endif
#if __has_builtin(__builtin_log)
            if constexpr (etl::is_same_v<Float, double>) {
                return __builtin_log(v);
            }
#endif
#if __has_builtin(__builtin_logl)
            if constexpr (etl::is_same_v<Float, long double>) {
                return __builtin_logl(v);
            }
#endif
        }

        return etl::detail::gcem::log(v);
    }
} log;

} // namespace detail

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(float v) noexcept -> float { return etl::detail::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto logf(float v) noexcept -> float { return etl::detail::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(double v) noexcept -> double { return etl::detail::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(long double v) noexcept -> long double { return etl::detail::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto logl(long double v) noexcept -> long double { return etl::detail::log(v); }

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
template <integral T>
[[nodiscard]] constexpr auto log(T arg) noexcept -> double
{
    return etl::detail::log(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LOG_HPP
