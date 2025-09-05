// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_EXP_HPP
#define TETL_CMATH_EXP_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct exp {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_expf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_expf(arg);
            }
#endif
#if __has_builtin(__builtin_exp)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_exp(arg);
            }
#endif
        }
        return etl::detail::gcem::exp(arg);
    }
} exp;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes e (Euler's number, 2.7182...) raised to the given power arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/exp
[[nodiscard]] constexpr auto exp(float arg) noexcept -> float
{
    return etl::detail::exp(arg);
}
[[nodiscard]] constexpr auto expf(float arg) noexcept -> float
{
    return etl::detail::exp(arg);
}
[[nodiscard]] constexpr auto exp(double arg) noexcept -> double
{
    return etl::detail::exp(arg);
}
[[nodiscard]] constexpr auto exp(long double arg) noexcept -> long double
{
    return etl::detail::exp(arg);
}
[[nodiscard]] constexpr auto expl(long double arg) noexcept -> long double
{
    return etl::detail::exp(arg);
}
[[nodiscard]] constexpr auto exp(integral auto arg) noexcept -> double
{
    return etl::detail::exp(double(arg));
}

/// @}

} // namespace etl

#endif // TETL_CMATH_EXP_HPP
