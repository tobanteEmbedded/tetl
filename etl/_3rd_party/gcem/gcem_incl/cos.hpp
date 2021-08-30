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
 * compile-time cosine function using tan(x/2)
 */

#ifndef GCEM_cos_HPP
#define GCEM_cos_HPP

namespace internal {

template <typename T>
constexpr auto cos_compute(const T x) noexcept -> T
{
    return (T(1) - x * x) / (T(1) + x * x);
}

template <typename T>
constexpr auto cos_check(const T x) noexcept -> T
{
    return ( // NaN check
        is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                  // indistinguishable from 0
            etl::numeric_limits<T>::epsilon() > abs(x)
            ? T(1)
            :
            // special cases: pi/2 and pi
            etl::numeric_limits<T>::epsilon() > abs(x - T(GCEM_HALF_PI)) ? T(0)
        : etl::numeric_limits<T>::epsilon() > abs(x + T(GCEM_HALF_PI))   ? T(0)
        : etl::numeric_limits<T>::epsilon() > abs(x - T(etl::numbers::pi))
            ? -T(1)
        : etl::numeric_limits<T>::epsilon() > abs(x + T(etl::numbers::pi))
            ? -T(1)
            :
            // else
            cos_compute(tan(x / T(2))));
}

} // namespace internal

/**
 * Compile-time cosine function
 *
 * @param x a real-valued input.
 * @return the cosine function using \f[ \cos(x) =
 * \frac{1-\tan^2(x/2)}{1+\tan^2(x/2)} \f]
 */

template <typename T>
constexpr auto cos(const T x) noexcept -> return_t<T>
{
    return internal::cos_check(static_cast<return_t<T>>(x));
}

#endif
