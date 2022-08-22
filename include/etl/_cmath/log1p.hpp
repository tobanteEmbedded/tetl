/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_LOG1P_HPP
#define TETL_CMATH_LOG1P_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log1p
[[nodiscard]] constexpr auto log1p(float v) noexcept -> float { return etl::detail::gcem::log1p(v); }

/// \brief Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log1p
[[nodiscard]] constexpr auto log1pf(float v) noexcept -> float { return etl::detail::gcem::log1p(v); }

/// \brief Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log1p
[[nodiscard]] constexpr auto log1p(double v) noexcept -> double { return etl::detail::gcem::log1p(v); }

/// \brief Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log1p
[[nodiscard]] constexpr auto log1p(long double v) noexcept -> long double { return etl::detail::gcem::log1p(v); }

/// \brief Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log1p
[[nodiscard]] constexpr auto log1pl(long double v) noexcept -> long double { return etl::detail::gcem::log1p(v); }

/// \brief Computes the natural (base e) logarithm of 1+arg. This function is
/// more precise than the expression etl::log(1+arg) if arg is close to zero.
///
/// https://en.cppreference.com/w/cpp/numeric/math/log1p
template <typename T>
[[nodiscard]] constexpr auto log1p(T arg) noexcept -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::log1p(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LOG1P_HPP
