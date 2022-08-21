/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ATANH_HPP
#define TETL_CMATH_ATANH_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the inverse hyperbolic tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atanh
[[nodiscard]] constexpr auto atanh(float arg) noexcept -> float { return etl::detail::gcem::atanh(arg); }

/// \brief Computes the inverse hyperbolic tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atanh
[[nodiscard]] constexpr auto atanhf(float arg) noexcept -> float { return etl::detail::gcem::atanh(arg); }

/// \brief Computes the inverse hyperbolic tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atanh
[[nodiscard]] constexpr auto atanh(double arg) noexcept -> double { return etl::detail::gcem::atanh(arg); }

/// \brief Computes the inverse hyperbolic tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atanh
[[nodiscard]] constexpr auto atanh(long double arg) noexcept -> long double { return etl::detail::gcem::atanh(arg); }

/// \brief Computes the inverse hyperbolic tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atanh
[[nodiscard]] constexpr auto atanhl(long double arg) noexcept -> long double { return etl::detail::gcem::atanh(arg); }

/// \brief Computes the inverse hyperbolic tangent of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/atanh
template <typename T>
[[nodiscard]] constexpr auto atanh(T arg) noexcept -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::atanh(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ATANH_HPP
