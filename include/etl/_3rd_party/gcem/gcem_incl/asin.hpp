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
 * compile-time arcsine function
 */

#ifndef GCEM_asin_HPP
#define GCEM_asin_HPP

namespace internal {

template <typename T>
constexpr auto asin_compute(T const x) noexcept -> T
{
    return ( // only defined on [-1,1]
        x > T(1) ? etl::numeric_limits<T>::quiet_NaN() :
                 // indistinguishable from one or zero
            etl::numeric_limits<T>::epsilon() > abs(x - T(1)) ? T(GCEM_HALF_PI)
        : etl::numeric_limits<T>::epsilon() > abs(x)          ? T(0)
                                                              :
                                                     // else
            atan(x / sqrt(T(1) - x * x)));
}

template <typename T>
constexpr auto asin_check(T const x) noexcept -> T
{
    return ( // NaN check
        is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                  //
            x < T(0) ? -asin_compute(-x)
                     : asin_compute(x));
}

} // namespace internal

/**
 * Compile-time arcsine function
 *
 * @param x a real-valued input, where \f$ x \in [-1,1] \f$.
 * @return the inverse sine function using \f[ \text{asin}(x) = \text{atan}
 * \left( \frac{x}{\sqrt{1-x^2}} \right) \f]
 */

template <typename T>
constexpr auto asin(T const x) noexcept -> return_t<T>
{
    return internal::asin_check(static_cast<return_t<T>>(x));
}

#endif
