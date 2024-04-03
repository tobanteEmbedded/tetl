// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_ISFINITE_HPP
#define TETL_CMATH_ISFINITE_HPP

#include <etl/_cmath/isinf.hpp>
#include <etl/_cmath/isnan.hpp>

namespace etl {

/// Determines if the given floating point number arg has finite value
/// i.e. it is normal, subnormal or zero, but not infinite or NaN.
/// \details https://en.cppreference.com/w/cpp/numeric/math/isfinite
/// \ingroup cmath
[[nodiscard]] constexpr auto isfinite(float arg) -> bool { return not etl::isnan(arg) and not etl::isinf(arg); }

/// \ingroup cmath
[[nodiscard]] constexpr auto isfinite(double arg) -> bool { return not etl::isnan(arg) and not etl::isinf(arg); }

/// \ingroup cmath
[[nodiscard]] constexpr auto isfinite(long double arg) -> bool { return not etl::isnan(arg) and not etl::isinf(arg); }

} // namespace etl

#endif // TETL_CMATH_ISFINITE_HPP
