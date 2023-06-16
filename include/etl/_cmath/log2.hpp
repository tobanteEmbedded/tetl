// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_LOG2_HPP
#define TETL_CMATH_LOG2_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2(float v) noexcept -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_log2f)
        return __builtin_log2f(v);
#else
        return etl::detail::gcem::log2(v);
#endif
    }
#if __has_builtin(__builtin_log2f)
    return __builtin_log2f(v);
#else
    return etl::detail::gcem::log2(v);
#endif
}

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2f(float v) noexcept -> float { return etl::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2(double v) noexcept -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_log2)
        return __builtin_log2(v);
#else
        return etl::detail::gcem::log2(v);
#endif
    }
#if __has_builtin(__builtin_log2)
    return __builtin_log2(v);
#else
    return etl::detail::gcem::log2(v);
#endif
}

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2(long double v) noexcept -> long double { return etl::detail::gcem::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
[[nodiscard]] constexpr auto log2l(long double v) noexcept -> long double { return etl::log2(v); }

/// \brief Computes the binary (base-2) logarithm of arg.
/// https://en.cppreference.com/w/cpp/numeric/math/log2
template <integral T>
[[nodiscard]] constexpr auto log2(T arg) noexcept -> double
{
    return etl::log2(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LOG2_HPP
