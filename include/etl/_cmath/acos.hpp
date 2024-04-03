// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ACOS_HPP
#define TETL_CMATH_ACOS_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// Computes the principal value of the arc cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acos
/// \ingroup cmath
[[nodiscard]] constexpr auto acos(float arg) noexcept -> float { return etl::detail::gcem::acos(arg); }

/// Computes the principal value of the arc cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acos
/// \ingroup cmath
[[nodiscard]] constexpr auto acosf(float arg) noexcept -> float { return etl::detail::gcem::acos(arg); }

/// Computes the principal value of the arc cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acos
/// \ingroup cmath
[[nodiscard]] constexpr auto acos(double arg) noexcept -> double { return etl::detail::gcem::acos(arg); }

/// Computes the principal value of the arc cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acos
/// \ingroup cmath
[[nodiscard]] constexpr auto acos(long double arg) noexcept -> long double { return etl::detail::gcem::acos(arg); }

/// Computes the principal value of the arc cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acos
/// \ingroup cmath
[[nodiscard]] constexpr auto acosl(long double arg) noexcept -> long double { return etl::detail::gcem::acos(arg); }

/// Computes the principal value of the arc cosine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/acos
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto acos(T arg) noexcept -> double
{
    return etl::detail::gcem::acos(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ACOS_HPP
