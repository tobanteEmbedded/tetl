/*################################################################################
  ##
  ##   Copyright (C) 2016-2020 Keith O'Hara
  ##
  ##   This file is part of the GCE-Math C++ library.
  ##
  ##   Licensed under the Apache License, Version 2.0 (the "License");
  ##   you may not use this file except in compliance with the License.
  ##   You may obtain a copy of the License at
  ##
  ##       http://www.apache.org/licenses/LICENSE-2.0
  ##
  ##   Unless required by applicable law or agreed to in writing, software
  ##   distributed under the License is distributed on an "AS IS" BASIS,
  ##   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ##   See the License for the specific language governing permissions and
  ##   limitations under the License.
  ##
  ################################################################################*/

#ifndef GCEM_gcd_HPP
#define GCEM_gcd_HPP

namespace internal {

template <typename T>
constexpr auto gcd_recur(const T a, const T b) noexcept -> T
{
    return (b == T(0) ? a : gcd_recur(b, a % b));
}

template <typename T,
    typename etl::enable_if<etl::is_integral<T>::value>::type* = nullptr>
constexpr auto gcd_int_check(const T a, const T b) noexcept -> T
{
    return gcd_recur(a, b);
}

template <typename T,
    typename etl::enable_if<!etl::is_integral<T>::value>::type* = nullptr>
constexpr auto gcd_int_check(const T a, const T b) noexcept -> T
{
    return gcd_recur(static_cast<ullint_t>(a), static_cast<ullint_t>(b));
}

template <typename T1, typename T2, typename TC = common_t<T1, T2>>
constexpr auto gcd_type_check(const T1 a, const T2 b) noexcept -> TC
{
    return gcd_int_check(static_cast<TC>(abs(a)), static_cast<TC>(abs(b)));
}

} // namespace internal

/**
 * Compile-time greatest common divisor (GCD) function
 *
 * @param a integral-valued input.
 * @param b integral-valued input.
 * @return the greatest common divisor between integers \c a and \c b using a
 * Euclidean algorithm.
 */

template <typename T1, typename T2>
constexpr auto gcd(const T1 a, const T2 b) noexcept -> common_t<T1, T2>
{
    return internal::gcd_type_check(a, b);
}

#endif
