// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_TAN_HPP
#define TETL_CMATH_TAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct tan {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_tanf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_tanf(arg);
            }
#endif
#if __has_builtin(__builtin_tan)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_tan(arg);
            }
#endif
        }
        return etl::detail::gcem::tan(arg);
    }
} tan;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes the tangent of arg (measured in radians).
/// \details https://en.cppreference.com/w/cpp/numeric/math/tan
[[nodiscard]] constexpr auto tan(float arg) noexcept -> float
{
    return etl::detail::tan(arg);
}
[[nodiscard]] constexpr auto tanf(float arg) noexcept -> float
{
    return etl::detail::tan(arg);
}
[[nodiscard]] constexpr auto tan(double arg) noexcept -> double
{
    return etl::detail::tan(arg);
}
[[nodiscard]] constexpr auto tan(long double arg) noexcept -> long double
{
    return etl::detail::tan(arg);
}
[[nodiscard]] constexpr auto tanl(long double arg) noexcept -> long double
{
    return etl::detail::tan(arg);
}
[[nodiscard]] constexpr auto tan(integral auto arg) noexcept -> double
{
    return etl::detail::tan(double(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_TAN_HPP
