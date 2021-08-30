/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_LOG_HPP
#define TETL_CMATH_LOG_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"

namespace etl {

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(float v) noexcept -> float
{
    return gcem::log(v);
}

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto logf(float v) noexcept -> float
{
    return gcem::log(v);
}

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(double v) noexcept -> double
{
    return gcem::log(v);
}

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto log(long double v) noexcept -> long double
{
    return gcem::log(v);
}

/// \brief Computes the natural (base e) logarithm of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log
[[nodiscard]] constexpr auto logl(long double v) noexcept -> long double
{
    return gcem::log(v);
}

} // namespace etl

#endif // TETL_CMATH_LOG_HPP