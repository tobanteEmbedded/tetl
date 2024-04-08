// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ACOS_HPP
#define TETL_CMATH_ACOS_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct acos {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not etl::is_constant_evaluated()) {
#if __has_builtin(__builtin_acosf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_acosf(arg);
            }
#elif __has_builtin(__builtin_acos)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_acos(arg);
            }
#elif __has_builtin(__builtin_acosl)
            if constexpr (etl::same_as<Float, long double>) {
                return __builtin_acosl(arg);
            }
#endif
        }
        return etl::detail::gcem::acos(arg);
    }
} acos;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the principal value of the arc cosine of arg.
///
/// https://en.cppreference.com/w/cpp/numeric/math/acos
[[nodiscard]] constexpr auto acos(float arg) noexcept -> float { return etl::detail::acos(arg); }

[[nodiscard]] constexpr auto acosf(float arg) noexcept -> float { return etl::detail::acos(arg); }

[[nodiscard]] constexpr auto acos(double arg) noexcept -> double { return etl::detail::acos(arg); }

[[nodiscard]] constexpr auto acos(long double arg) noexcept -> long double { return etl::detail::acos(arg); }

[[nodiscard]] constexpr auto acosl(long double arg) noexcept -> long double { return etl::detail::acos(arg); }

template <integral T>
[[nodiscard]] constexpr auto acos(T arg) noexcept -> double
{
    return etl::detail::acos(static_cast<double>(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_ACOS_HPP
