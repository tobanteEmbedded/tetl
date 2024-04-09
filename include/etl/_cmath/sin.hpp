// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_SIN_HPP
#define TETL_CMATH_SIN_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct sin {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not etl::is_constant_evaluated()) {
#if __has_builtin(__builtin_sinf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_sinf(arg);
            }
#endif
#if __has_builtin(__builtin_sin)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_sin(arg);
            }
#endif
        }
        return etl::detail::gcem::sin(arg);
    }
} sin;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the sine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/sin
[[nodiscard]] constexpr auto sin(float arg) noexcept -> float { return etl::detail::sin(arg); }
[[nodiscard]] constexpr auto sinf(float arg) noexcept -> float { return etl::detail::sin(arg); }
[[nodiscard]] constexpr auto sin(double arg) noexcept -> double { return etl::detail::sin(arg); }
[[nodiscard]] constexpr auto sin(long double arg) noexcept -> long double { return etl::detail::sin(arg); }
[[nodiscard]] constexpr auto sinl(long double arg) noexcept -> long double { return etl::detail::sin(arg); }
[[nodiscard]] constexpr auto sin(integral auto arg) noexcept -> double { return etl::detail::sin(double(arg)); }

/// @}

} // namespace etl

#endif // TETL_CMATH_SIN_HPP
