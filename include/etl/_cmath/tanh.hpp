// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_TANH_HPP
#define TETL_CMATH_TANH_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct tanh {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const noexcept -> Float
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_tanhf)
            if constexpr (etl::same_as<Float, float>) {
                return __builtin_tanhf(arg);
            }
#endif
#if __has_builtin(__builtin_tanh)
            if constexpr (etl::same_as<Float, double>) {
                return __builtin_tanh(arg);
            }
#endif
        }
        return etl::detail::gcem::tanh(arg);
    }
} tanh;

} // namespace detail

/// \ingroup cmath
/// @{

/// Computes e (Euler's number, 2.7182...) raised to the given power arg
/// \details https://en.cppreference.com/w/cpp/numeric/math/tanh
[[nodiscard]] constexpr auto tanh(float arg) noexcept -> float { return etl::detail::tanh(arg); }
[[nodiscard]] constexpr auto tanhf(float arg) noexcept -> float { return etl::detail::tanh(arg); }
[[nodiscard]] constexpr auto tanh(double arg) noexcept -> double { return etl::detail::tanh(arg); }
[[nodiscard]] constexpr auto tanh(long double arg) noexcept -> long double { return etl::detail::tanh(arg); }
[[nodiscard]] constexpr auto tanhl(long double arg) noexcept -> long double { return etl::detail::tanh(arg); }
[[nodiscard]] constexpr auto tanh(integral auto arg) noexcept -> double { return etl::detail::tanh(double(arg)); }

/// @}

} // namespace etl

#endif // TETL_CMATH_TANH_HPP
