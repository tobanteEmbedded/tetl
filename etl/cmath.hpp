/*
Copyright (c) 2019-2021, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CMATH_HPP
#define TAETL_CMATH_HPP

#include "etl/type_traits.hpp"

#include "etl/detail/sfinae.hpp"

#ifdef _MSC_VER
#include <math.h>
#else
#ifndef NAN
#define NAN TAETL_BUILTIN_NAN
#endif

#ifndef INFINITY
#define INFINITY TAETL_BUILTIN_INFINITY
#endif
#endif

namespace etl
{
/**
 * @brief Most efficient floating-point type at least as wide as float.
 */
using float_t = float;

/**
 * @brief Most efficient floating-point type at least as wide as double.
 */
using double_t = double;

/**
 * @brief Determines if the given floating point number arg is a positive or
 * negative infinity.
 *
 * @return true if arg is infinite, false otherwise
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isinf
 */
[[nodiscard]] constexpr auto isinf(float arg) -> bool
{
  return arg == INFINITY;
}

/**
 * @brief Determines if the given floating point number arg is a positive or
 * negative infinity.
 *
 * @return true if arg is infinite, false otherwise
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isinf
 */
[[nodiscard]] constexpr auto isinf(double arg) -> bool
{
  return arg == INFINITY;
}

/**
 * @brief Determines if the given floating point number arg is a positive or
 * negative infinity.
 *
 * @return true if arg is infinite, false otherwise
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isinf
 */
[[nodiscard]] constexpr auto isinf(long double arg) -> bool
{
  return arg == INFINITY;
}

/**
 * @brief A set of overloads or a function template accepting the arg argument
 * of any integral type. Equivalent to cast to double.
 *
 * @return true if arg is infinite, false otherwise
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isinf
 */
template <typename IntegralType,
          TAETL_REQUIRES_(etl::is_integral_v<IntegralType>)>
[[nodiscard]] constexpr auto isinf(IntegralType arg) -> bool
{
  return isinf(static_cast<double>(arg));
}

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isnan
 */
[[nodiscard]] constexpr auto isnan(float arg) -> bool { return arg != arg; }

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isnan
 */
[[nodiscard]] constexpr auto isnan(double arg) -> bool { return arg != arg; }

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isnan
 */
[[nodiscard]] constexpr auto isnan(long double arg) -> bool
{
  return arg != arg;
}

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isnan
 */
template <typename IntegralType,
          TAETL_REQUIRES_(etl::is_integral_v<IntegralType>)>
[[nodiscard]] constexpr auto isnan(IntegralType arg) -> bool
{
  return isnan(static_cast<double>(arg));
}

/**
 * @brief Determines if the given floating point number arg has finite value
 * i.e. it is normal, subnormal or zero, but not infinite or NaN.
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isfinite
 */
[[nodiscard]] constexpr auto isfinite(float arg) -> bool
{
  return !etl::isnan(arg) && !etl::isinf(arg);
}

/**
 * @brief Determines if the given floating point number arg has finite value
 * i.e. it is normal, subnormal or zero, but not infinite or NaN.
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isfinite
 */
[[nodiscard]] constexpr auto isfinite(double arg) -> bool
{
  return !etl::isnan(arg) && !etl::isinf(arg);
}

/**
 * @brief Determines if the given floating point number arg has finite value
 * i.e. it is normal, subnormal or zero, but not infinite or NaN.
 *
 * @details https://en.cppreference.com/w/cpp/numeric/math/isfinite
 */
[[nodiscard]] constexpr auto isfinite(long double arg) -> bool
{
  return !etl::isnan(arg) && !etl::isinf(arg);
}

namespace detail
{
template <typename Float>
[[nodiscard]] constexpr auto lerp_impl(Float a, Float b, Float t) noexcept
  -> ::etl::enable_if_t<::etl::is_floating_point_v<Float>, Float>
{
  if ((a <= 0 && b >= 0) || (a >= 0 && b <= 0)) { return t * b + (1 - t) * a; }

  if (t == 1) { return b; }

  auto const x = a + t * (b - a);
  if ((t > 1) == (b > a)) { return b < x ? x : b; }
  return x < b ? x : b;
}
}  // namespace detail

/**
 * @brief Computes a+t(b−a), i.e. the linear interpolation between a and b for
 * the parameter t (or extrapolation, when t is outside the range [0,1]).
 *
 * https://en.cppreference.com/w/cpp/numeric/lerp
 */
[[nodiscard]] constexpr auto lerp(float a, float b, float t) noexcept -> float
{
  return detail::lerp_impl<float>(a, b, t);
}

/**
 * @brief Computes a+t(b−a), i.e. the linear interpolation between a and b for
 * the parameter t (or extrapolation, when t is outside the range [0,1]).
 *
 * https://en.cppreference.com/w/cpp/numeric/lerp
 */
[[nodiscard]] constexpr auto lerp(double a, double b, double t) noexcept
  -> double
{
  return detail::lerp_impl<double>(a, b, t);
}

/**
 * @brief Computes a+t(b−a), i.e. the linear interpolation between a and b for
 * the parameter t (or extrapolation, when t is outside the range [0,1]).
 *
 * https://en.cppreference.com/w/cpp/numeric/lerp
 */
[[nodiscard]] constexpr auto lerp(long double a, long double b,
                                  long double t) noexcept -> long double
{
  return detail::lerp_impl<long double>(a, b, t);
}

}  // namespace etl

#endif  // TAETL_CMATH_HPP
