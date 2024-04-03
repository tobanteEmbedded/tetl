// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ATAN_HPP
#define TETL_CMATH_ATAN_HPP

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// Computes the principal value of the arc tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan
/// \ingroup cmath
[[nodiscard]] constexpr auto atan(float arg) noexcept -> float { return etl::detail::gcem::atan(arg); }

/// Computes the principal value of the arc tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan
/// \ingroup cmath
[[nodiscard]] constexpr auto atanf(float arg) noexcept -> float { return etl::detail::gcem::atan(arg); }

/// Computes the principal value of the arc tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan
/// \ingroup cmath
[[nodiscard]] constexpr auto atan(double arg) noexcept -> double { return etl::detail::gcem::atan(arg); }

/// Computes the principal value of the arc tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan
/// \ingroup cmath
[[nodiscard]] constexpr auto atan(long double arg) noexcept -> long double { return etl::detail::gcem::atan(arg); }

/// Computes the principal value of the arc tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan
/// \ingroup cmath
[[nodiscard]] constexpr auto atanl(long double arg) noexcept -> long double { return etl::detail::gcem::atan(arg); }

/// Computes the principal value of the arc tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto atan(T arg) noexcept -> double
{
    return etl::detail::gcem::atan(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ATAN_HPP
