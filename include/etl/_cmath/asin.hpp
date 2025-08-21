// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ASIN_HPP
#define TETL_CMATH_ASIN_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct asin {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_asinf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_asinf(arg);
            }
#endif
#if __has_builtin(__builtin_asin)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_asin(arg);
            }
#endif
        }
        return etl::detail::gcem::asin(arg);
    }
} asin;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the principal value of the arc sine of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/asin
[[nodiscard]] constexpr auto asin(float arg) noexcept -> float { return etl::detail::asin(arg); }
[[nodiscard]] constexpr auto asinf(float arg) noexcept -> float { return etl::detail::asin(arg); }
[[nodiscard]] constexpr auto asin(double arg) noexcept -> double { return etl::detail::asin(arg); }
[[nodiscard]] constexpr auto asin(long double arg) noexcept -> long double { return etl::detail::asin(arg); }
[[nodiscard]] constexpr auto asinl(long double arg) noexcept -> long double { return etl::detail::asin(arg); }
[[nodiscard]] constexpr auto asin(integral auto arg) noexcept -> double { return etl::detail::asin(double(arg)); }

/// @}

} // namespace etl

#endif // TETL_CMATH_ASIN_HPP
