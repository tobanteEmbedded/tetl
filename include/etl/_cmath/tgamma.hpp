/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_TGAMMA_HPP
#define TETL_CMATH_TGAMMA_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the gamma function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/tgamma
[[nodiscard]] constexpr auto tgamma(float arg) noexcept -> float { return etl::detail::gcem::tgamma(arg); }

/// \brief Computes the gamma function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/tgamma
[[nodiscard]] constexpr auto tgammaf(float arg) noexcept -> float { return etl::detail::gcem::tgamma(arg); }

/// \brief Computes the gamma function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/tgamma
[[nodiscard]] constexpr auto tgamma(double arg) noexcept -> double { return etl::detail::gcem::tgamma(arg); }

/// \brief Computes the gamma function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/tgamma
[[nodiscard]] constexpr auto tgamma(long double arg) noexcept -> long double { return etl::detail::gcem::tgamma(arg); }

/// \brief Computes the gamma function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/tgamma
[[nodiscard]] constexpr auto tgammal(long double arg) noexcept -> long double { return etl::detail::gcem::tgamma(arg); }

/// \brief Computes the gamma function of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/tgamma
template <typename T>
[[nodiscard]] constexpr auto tgamma(T arg) noexcept -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::tgamma(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_TGAMMA_HPP
