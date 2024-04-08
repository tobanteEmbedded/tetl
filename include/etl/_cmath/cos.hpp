// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_COS_HPP
#define TETL_CMATH_COS_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct cos {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not etl::is_constant_evaluated()) {
#if __has_builtin(__builtin_cosf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_cosf(arg);
            }
#endif
#if __has_builtin(__builtin_cos)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_cos(arg);
            }
#endif
#if __has_builtin(__builtin_cosl)
            if constexpr (etl::same_as<Float, long double>) {
                return __builtin_cosl(arg);
            }
#endif
        }
        return etl::detail::gcem::cos(arg);
    }
} cos;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the cosine of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/cos
[[nodiscard]] constexpr auto cos(float arg) noexcept -> float { return etl::detail::cos(arg); }
[[nodiscard]] constexpr auto cosf(float arg) noexcept -> float { return etl::detail::cos(arg); }
[[nodiscard]] constexpr auto cos(double arg) noexcept -> double { return etl::detail::cos(arg); }
[[nodiscard]] constexpr auto cos(long double arg) noexcept -> long double { return etl::detail::cos(arg); }
[[nodiscard]] constexpr auto cosl(long double arg) noexcept -> long double { return etl::detail::cos(arg); }
[[nodiscard]] constexpr auto cos(integral auto arg) noexcept -> double { return etl::detail::cos(double(arg)); }

/// @}

} // namespace etl

#endif // TETL_CMATH_COS_HPP
