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

/*
 * compile-time two-argument arctangent function
 */

#ifndef GCEM_atan2_HPP
#define GCEM_atan2_HPP

namespace internal {

template <typename T>
constexpr auto atan2_compute(T const y, T const x) noexcept -> T
{
    return static_cast<T>( // NaN check
        any_nan(y, x) ? etl::numeric_limits<T>::quiet_NaN() :
                      //
            etl::numeric_limits<T>::epsilon() > abs(x) ? //
            etl::numeric_limits<T>::epsilon() > abs(y) ? neg_zero(y)   ? neg_zero(x) ? -T(etl::numbers::pi) : -T(0)
                                                           : neg_zero(x) ? T(etl::numbers::pi)
                                                                       : T(0)
            : y > T(0) ? T(GCEM_HALF_PI)
                                                       : -T(GCEM_HALF_PI)
                                                       :
                                                       //
            x < T(0) ? y < T(0) ? atan(y / x) - T(etl::numbers::pi) : atan(y / x) + T(etl::numbers::pi) :
                     //
                atan(y / x));
}

template <typename T1, typename T2, typename TC = common_return_t<T1, T2>>
constexpr auto atan2_type_check(const T1 y, const T2 x) noexcept -> TC
{
    return atan2_compute(static_cast<TC>(x), static_cast<TC>(y));
}

} // namespace internal

/**
 * Compile-time two-argument arctangent function
 *
 * @param y a real-valued input.
 * @param x a real-valued input.
 * @return \f[ \text{atan2}(y,x) = \begin{cases} \text{atan}(y/x) & \text{ if }
 * x > 0 \\ \text{atan}(y/x) + \pi & \text{ if } x < 0 \text{ and } y \geq 0
 * \\ \text{atan}(y/x) - \pi & \text{ if } x < 0 \text{ and } y < 0 \\ + \pi/2 &
 * \text{ if } x = 0 \text{ and } y > 0 \\ - \pi/2 & \text{ if } x = 0 \text{
 * and } y < 0 \end{cases} \f] The function is undefined at the origin, however
 * the following conventions are used. \f[ \text{atan2}(y,x) = \begin{cases} +0
 * & \text{ if } x = +0 \text{ and } y = +0 \\ -0 & \text{ if } x = +0 \text{
 * and } y = -0 \\ +\pi & \text{ if } x = -0 \text{ and } y = +0 \\ - \pi &
 * \text{ if } x = -0 \text{ and } y = -0 \end{cases} \f]
 */

template <typename T1, typename T2>
constexpr auto atan2(const T1 y, const T2 x) noexcept -> common_return_t<T1, T2>
{
    return internal::atan2_type_check(x, y);
}

#endif
