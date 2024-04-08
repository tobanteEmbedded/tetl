// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ASINH_HPP
#define TETL_CMATH_ASINH_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct asinh {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
#if not defined(__AVR__)
        if (not etl::is_constant_evaluated()) {
    #if __has_builtin(__builtin_asinhf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_asinhf(arg);
            }
    #endif
    #if __has_builtin(__builtin_asinh)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_asinh(arg);
            }
    #endif
    #if __has_builtin(__builtin_asinhl)
            if constexpr (etl::same_as<Float, long double>) {
                return __builtin_asinhl(arg);
            }
    #endif
        }
#endif
        return etl::detail::gcem::asinh(arg);
    }
} asinh;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the inverse hyperbolic sine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/asinh
[[nodiscard]] constexpr auto asinh(float arg) noexcept -> float { return etl::detail::asinh(arg); }
[[nodiscard]] constexpr auto asinhf(float arg) noexcept -> float { return etl::detail::asinh(arg); }
[[nodiscard]] constexpr auto asinh(double arg) noexcept -> double { return etl::detail::asinh(arg); }
[[nodiscard]] constexpr auto asinh(long double arg) noexcept -> long double { return etl::detail::asinh(arg); }
[[nodiscard]] constexpr auto asinhl(long double arg) noexcept -> long double { return etl::detail::asinh(arg); }
[[nodiscard]] constexpr auto asinh(integral auto arg) noexcept -> double { return etl::detail::asinh(double(arg)); }

/// @}

} // namespace etl

#endif // TETL_CMATH_ASINH_HPP
