// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_FMA_HPP
#define TETL_CMATH_FMA_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/is_constant_evaluated.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

namespace detail {

inline constexpr struct fma {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float x, Float y, Float z) const noexcept -> Float
    {
        if (not etl::is_constant_evaluated()) {
#if __has_builtin(__builtin_fmaf)
            if constexpr (etl::is_same_v<Float, float>) {
                return __builtin_fmaf(x, y, z);
            }
#endif
#if __has_builtin(__builtin_fma)
            if constexpr (etl::is_same_v<Float, double>) {
                return __builtin_fma(x, y, z);
            }
#endif
#if __has_builtin(__builtin_fmal)
            if constexpr (etl::is_same_v<Float, long double>) {
                return __builtin_fmal(x, y, z);
            }
#endif
        }

        return (x * y) + z;
    }
} fma;

} // namespace detail

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(float x, float y, float z) noexcept -> float { return etl::detail::fma(x, y, z); }

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fmaf(float x, float y, float z) noexcept -> float { return etl::detail::fma(x, y, z); }

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(double x, double y, double z) noexcept -> double { return etl::detail::fma(x, y, z); }

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fma(long double x, long double y, long double z) noexcept -> long double
{
    return etl::detail::fma(x, y, z);
}

/// \brief Computes (x*y) + z as if to infinite precision and rounded only once
/// to fit the result type.
///
/// https://en.cppreference.com/w/cpp/numeric/math/fma
[[nodiscard]] constexpr auto fmal(long double x, long double y, long double z) noexcept -> long double
{
    return etl::detail::fma(x, y, z);
}

} // namespace etl

#endif // TETL_CMATH_FMA_HPP
