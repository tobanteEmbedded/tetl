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
 * compile-time inverse hyperbolic tangent function
 */

#ifndef GCEM_atanh_HPP
#define GCEM_atanh_HPP

namespace internal {

template <typename T>
constexpr auto atanh_compute(const T x) noexcept -> T
{
    return (log((T(1) + x) / (T(1) - x)) / T(2));
}

template <typename T>
constexpr auto atanh_check(const T x) noexcept -> T
{
    return ( // NaN check
        is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                  // function is defined for |x| < 1
            T(1) < abs(x)                                     ? etl::numeric_limits<T>::quiet_NaN()
        : etl::numeric_limits<T>::epsilon() > (T(1) - abs(x)) ? sgn(x) * etl::numeric_limits<T>::infinity()
                                                              :
                                                              // indistinguishable from zero
            etl::numeric_limits<T>::epsilon() > abs(x) ? T(0)
                                                       :
                                                       // else
            atanh_compute(x));
}

} // namespace internal

/**
 * Compile-time inverse hyperbolic tangent function
 *
 * @param x a real-valued input.
 * @return the inverse hyperbolic tangent function using \f[ \text{atanh}(x) =
 * \frac{1}{2} \ln \left( \frac{1+x}{1-x} \right) \f]
 */

template <typename T>
constexpr auto atanh(const T x) noexcept -> return_t<T>
{
    return internal::atanh_check(static_cast<return_t<T>>(x));
}

#endif
