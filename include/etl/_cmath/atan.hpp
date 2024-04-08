// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ATAN_HPP
#define TETL_CMATH_ATAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct atan {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not etl::is_constant_evaluated()) {
#if __has_builtin(__builtin_atanf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_atanf(arg);
            }
#elif __has_builtin(__builtin_atan)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_atan(arg);
            }
#elif __has_builtin(__builtin_atanl)
            if constexpr (etl::same_as<Float, long double>) {
                return __builtin_atanl(arg);
            }
#endif
        }
        return etl::detail::gcem::atan(arg);
    }
} atan;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the principal value of the arc tangent of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/atan
[[nodiscard]] constexpr auto atan(float arg) noexcept -> float { return etl::detail::atan(arg); }

[[nodiscard]] constexpr auto atanf(float arg) noexcept -> float { return etl::detail::atan(arg); }

[[nodiscard]] constexpr auto atan(double arg) noexcept -> double { return etl::detail::atan(arg); }

[[nodiscard]] constexpr auto atan(long double arg) noexcept -> long double { return etl::detail::atan(arg); }

[[nodiscard]] constexpr auto atanl(long double arg) noexcept -> long double { return etl::detail::atan(arg); }

template <integral T>
[[nodiscard]] constexpr auto atan(T arg) noexcept -> double
{
    return etl::detail::atan(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ATAN_HPP
