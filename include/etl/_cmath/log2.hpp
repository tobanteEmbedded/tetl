/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_LOG2_HPP
#define TETL_CMATH_LOG2_HPP

#include "etl/_3rd_party/gcem/gcem.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2(float v) noexcept -> float { return etl::detail::gcem::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2f(float v) noexcept -> float { return etl::detail::gcem::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2(double v) noexcept -> double { return etl::detail::gcem::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2(long double v) noexcept -> long double { return etl::detail::gcem::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2l(long double v) noexcept -> long double { return etl::detail::gcem::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
template <typename T>
[[nodiscard]] constexpr auto log2(T arg) noexcept -> etl::enable_if_t<etl::is_integral_v<T>, double>
{
    return etl::detail::gcem::log2(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LOG2_HPP
