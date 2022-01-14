/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_ISFINITE_HPP
#define TETL_CMATH_ISFINITE_HPP

#include "etl/_cmath/isinf.hpp"
#include "etl/_cmath/isnan.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Determines if the given floating point number arg has finite value
/// i.e. it is normal, subnormal or zero, but not infinite or NaN.
/// https://en.cppreference.com/w/cpp/numeric/math/isfinite
[[nodiscard]] constexpr auto isfinite(float arg) -> bool { return !etl::isnan(arg) && !etl::isinf(arg); }

[[nodiscard]] constexpr auto isfinite(double arg) -> bool { return !etl::isnan(arg) && !etl::isinf(arg); }

[[nodiscard]] constexpr auto isfinite(long double arg) -> bool { return !etl::isnan(arg) && !etl::isinf(arg); }

} // namespace etl

#endif // TETL_CMATH_ISFINITE_HPP