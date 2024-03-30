// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_LOG10_HPP
#define TETL_CMATH_LOG10_HPP

#include <etl/_config/all.hpp>

#include <etl/_3rd_party/gcem/gcem.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// \brief Computes the binary (base-10) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log10
/// \ingroup cmath
[[nodiscard]] constexpr auto log10(float arg) noexcept -> float
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_log10f)
        return __builtin_log10f(arg);
#else
        return etl::detail::gcem::log(arg) / static_cast<float>(GCEM_LOG_10);
#endif
    }
#if __has_builtin(__builtin_log10f)
    return __builtin_log10f(arg);
#else
    return etl::detail::gcem::log(arg) / static_cast<float>(GCEM_LOG_10);
#endif
}

/// \brief Computes the binary (base-10) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log10
/// \ingroup cmath
[[nodiscard]] constexpr auto log10f(float arg) noexcept -> float { return etl::log10(arg); }

/// \brief Computes the binary (base-10) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log10
/// \ingroup cmath
[[nodiscard]] constexpr auto log10(double arg) noexcept -> double
{
    if (is_constant_evaluated()) {
#if __has_constexpr_builtin(__builtin_log10)
        return __builtin_log10(arg);
#else
        return etl::detail::gcem::log(arg) / static_cast<double>(GCEM_LOG_10);
#endif
    }
#if __has_builtin(__builtin_log10)
    return __builtin_log10(arg);
#else
    return etl::detail::gcem::log(arg) / static_cast<double>(GCEM_LOG_10);
#endif
}

/// \brief Computes the binary (base-10) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log10
/// \ingroup cmath
[[nodiscard]] constexpr auto log10(long double arg) noexcept -> long double
{
    return etl::detail::gcem::log(arg) / static_cast<long double>(GCEM_LOG_10);
}

/// \brief Computes the binary (base-10) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log10
/// \ingroup cmath
[[nodiscard]] constexpr auto log10l(long double arg) noexcept -> long double { return etl::log10(arg); }

/// \brief Computes the binary (base-10) logarithm of arg.
/// \details https://en.cppreference.com/w/cpp/numeric/math/log10
/// \ingroup cmath
template <integral T>
[[nodiscard]] constexpr auto log10(T arg) noexcept -> double
{
    return etl::log10(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_LOG10_HPP
