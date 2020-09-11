/*
Copyright (c) 2019-2020, Tobias Hienzsch
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

#include <math.h>

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
 * @return true if arg is infinite, false otherwise
 */
[[nodiscard]] constexpr auto isinf(float arg) -> bool { return arg == INFINITY; }

/**
 * @brief Determines if the given floating point number arg is a positive or
 * negative infinity.
 * @return true if arg is infinite, false otherwise
 */
[[nodiscard]] constexpr auto isinf(double arg) -> bool { return arg == INFINITY; }

/**
 * @brief Determines if the given floating point number arg is a positive or
 * negative infinity.
 * @return true if arg is infinite, false otherwise
 */
[[nodiscard]] constexpr auto isinf(long double arg) -> bool { return arg == INFINITY; }

/**
 * @brief A set of overloads or a function template accepting the arg argument
 * of any integral type. Equivalent to cast to double.
 * @return true if arg is infinite, false otherwise
 */
template <typename IntegralType>
[[nodiscard]] constexpr auto isinf(IntegralType arg)
    -> etl::enable_if_t<etl::is_integral_v<IntegralType>, bool>
{
    return isinf(static_cast<double>(arg));
}

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 */
[[nodiscard]] constexpr auto isnan(float arg) -> bool { return arg != arg; }

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 */
[[nodiscard]] constexpr auto isnan(double arg) -> bool { return arg != arg; }

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 */
[[nodiscard]] constexpr auto isnan(long double arg) -> bool { return arg != arg; }

/**
 * @brief Determines if the given floating point number arg is a not-a-number
 * (NaN) value.
 */
template <typename IntegralType>
[[nodiscard]] constexpr auto isnan(IntegralType arg)
    -> etl::enable_if_t<etl::is_integral_v<IntegralType>, bool>
{
    return isnan(static_cast<double>(arg));
}

/**
 * @brief Determines if the given floating point number arg has finite value
 * i.e. it is normal, subnormal or zero, but not infinite or NaN.
 */
[[nodiscard]] constexpr auto isfinite(float arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

/**
 * @brief Determines if the given floating point number arg has finite value
 * i.e. it is normal, subnormal or zero, but not infinite or NaN.
 */
[[nodiscard]] constexpr auto isfinite(double arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

/**
 * @brief Determines if the given floating point number arg has finite value
 * i.e. it is normal, subnormal or zero, but not infinite or NaN.
 */
[[nodiscard]] constexpr auto isfinite(long double arg) -> bool
{
    return !etl::isnan(arg) && !etl::isinf(arg);
}

}  // namespace etl

#endif  // TAETL_CMATH_HPP
