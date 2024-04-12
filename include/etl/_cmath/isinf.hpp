// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ISINF_HPP
#define TETL_CMATH_ISINF_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/integral.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

inline constexpr struct isinf {
    template <typename Float>
    [[nodiscard]] constexpr auto operator()(Float arg) const -> bool
    {
#if __has_builtin(__builtin_isinf)
        return __builtin_isinf(arg) != 0;
#else
        return arg == etl::numeric_limits<Float>::infinity();
#endif
    }
} isinf;

} // namespace detail

/// Determines if the given floating point number arg is a positive or negative infinity.
/// \details https://en.cppreference.com/w/cpp/numeric/math/isinf
/// \ingroup cmath
[[nodiscard]] constexpr auto isinf(float arg) -> bool { return etl::detail::isinf(arg); }

/// \ingroup cmath
[[nodiscard]] constexpr auto isinf(double arg) -> bool { return etl::detail::isinf(arg); }

/// \ingroup cmath
[[nodiscard]] constexpr auto isinf(long double arg) -> bool { return etl::detail::isinf(arg); }

/// \ingroup cmath
template <etl::integral Int>
[[nodiscard]] constexpr auto isinf(Int arg) -> bool
{
    return etl::detail::isinf(static_cast<double>(arg));
}

} // namespace etl

#endif // TETL_CMATH_ISINF_HPP
