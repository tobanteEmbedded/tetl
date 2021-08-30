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
 * compile-time arccosine function
 */

#ifndef GCEM_acos_HPP
#define GCEM_acos_HPP

namespace internal {

template <typename T>
constexpr auto acos_compute(const T x) noexcept -> T
{
    return ( // only defined on [-1,1]
        abs(x) > T(1) ? etl::numeric_limits<T>::quiet_NaN() :
                      // indistinguishable from one or zero
            etl::numeric_limits<T>::epsilon() > abs(x - T(1)) ? T(0)
        : etl::numeric_limits<T>::epsilon() > abs(x)          ? T(GCEM_HALF_PI)
                                                              :
                                                     // else
            atan(sqrt(T(1) - x * x) / x));
}

template <typename T>
constexpr auto acos_check(const T x) noexcept -> T
{
    return ( // NaN check
        is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                  //
            x > T(0) ? // if
            acos_compute(x)
                     :
                     // else
            T(GCEM_PI) - acos_compute(-x));
}

} // namespace internal

/**
 * Compile-time arccosine function
 *
 * @param x a real-valued input, where \f$ x \in [-1,1] \f$.
 * @return the inverse cosine function using \f[ \text{acos}(x) = \text{atan}
 * \left( \frac{\sqrt{1-x^2}}{x} \right) \f]
 */

template <typename T>
constexpr auto acos(const T x) noexcept -> return_t<T>
{
    return internal::acos_check(static_cast<return_t<T>>(x));
}

#endif
