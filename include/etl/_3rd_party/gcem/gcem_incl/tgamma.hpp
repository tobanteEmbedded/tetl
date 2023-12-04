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
 * the ('true') gamma function
 */

#ifndef GCEM_tgamma_HPP
#define GCEM_tgamma_HPP

namespace internal {

template <typename T>
constexpr auto tgamma_check(T const x) noexcept -> T
{
    return ( // NaN check
        is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                  // indistinguishable from one or zero
            etl::numeric_limits<T>::epsilon() > abs(x - T(1)) ? T(1)
        : etl::numeric_limits<T>::epsilon() > abs(x)          ? etl::numeric_limits<T>::infinity()
                                                              :
                                                     // negative numbers
            x < T(0) ? // check for integer
            etl::numeric_limits<T>::epsilon() > abs(x - find_whole(x)) ? etl::numeric_limits<T>::quiet_NaN() :
                                                                       // else
                tgamma_check(x + T(1)) / x
                     :

                     // else
            exp(lgamma(x)));
}

} // namespace internal

/**
 * Compile-time gamma function
 *
 * @param x a real-valued input.
 * @return computes the `true' gamma function
 * \f[ \Gamma(x) = \int_0^\infty y^{x-1} \exp(-y) dy \f]
 * using a polynomial form:
 * \f[ \Gamma(x+1) \approx (x+g+0.5)^{x+0.5} \exp(-x-g-0.5) \sqrt{2 \pi} \left[
 * c_0 + \frac{c_1}{x+1} + \frac{c_2}{x+2} + \cdots + \frac{c_n}{x+n} \right]
 * \f] where the value \f$ g \f$ and the coefficients \f$ (c_0, c_1, \ldots,
 * c_n) \f$ are taken from Paul Godfrey, whose note can be found here:
 * http://my.fit.edu/~gabdo/gamma.txt
 */

template <typename T>
constexpr auto tgamma(T const x) noexcept -> return_t<T>
{
    return internal::tgamma_check(static_cast<return_t<T>>(x));
}

#endif
