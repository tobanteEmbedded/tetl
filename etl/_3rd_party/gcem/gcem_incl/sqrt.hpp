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
 * compile-time square-root function
 */

#ifndef GCEM_sqrt_HPP
#define GCEM_sqrt_HPP

namespace internal {

template <typename T>
constexpr auto sqrt_recur(const T x, const T xn, const int count) noexcept -> T
{
    return (abs(xn - x / xn) / (T(1) + xn) < etl::numeric_limits<T>::epsilon()
                ? // if
                xn
                : count < GCEM_SQRT_MAX_ITER ? // else
                      sqrt_recur(x, T(0.5) * (xn + x / xn), count + 1)
                                             : xn);
}

template <typename T>
constexpr auto sqrt_check(const T x, const T mVal) noexcept -> T
{
    return (is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                      //
                x < T(0) ? etl::numeric_limits<T>::quiet_NaN()
                         :
                         //
                is_posinf(x) ? x
                             :
                             // indistinguishable from zero or one
                etl::numeric_limits<T>::epsilon() > abs(x)      ? T(0)
            : etl::numeric_limits<T>::epsilon() > abs(T(1) - x) ? x
                                                                :
                                                                // else
                x > T(4) ? sqrt_check(x / T(4), T(2) * mVal)
                         : mVal * sqrt_recur(x, x / T(2), 0));
}

} // namespace internal

/**
 * Compile-time square-root function
 *
 * @param x a real-valued input.
 * @return Computes \f$ \sqrt{x} \f$ using a Newton-Raphson approach.
 */

template <typename T>
constexpr auto sqrt(const T x) noexcept -> return_t<T>
{
    return internal::sqrt_check(static_cast<return_t<T>>(x), return_t<T>(1));
}

#endif
