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
 * compile-time binary logarithm function
 */

#ifndef GCEM_log2_HPP
#define GCEM_log2_HPP

namespace internal {

template <typename T>
constexpr auto log2_check(const T x) noexcept -> T
{
    return (is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                      // x < 0
                x < T(0) ? etl::numeric_limits<T>::quiet_NaN()
                         :
                         // x ~= 0
                etl::numeric_limits<T>::epsilon() > x ? -etl::numeric_limits<T>::infinity()
                                                      :
                                                      // indistinguishable from 1
                etl::numeric_limits<T>::epsilon() > abs(x - T(1)) ? T(0)
                                                                  :
                                                                  //
                x == etl::numeric_limits<T>::infinity() ? etl::numeric_limits<T>::infinity()
                                                        :
                                                        // else: log_2(x) = ln(x) / ln(2)
                T(log(x) / GCEM_LOG_2));
}

} // namespace internal

/**
 * Compile-time binary logarithm function
 *
 * @param x a real-valued input.
 * @return \f$ \log_2(x) \f$ using \f[ \log_{2}(x) = \frac{\log_e(x)}{\log_e(2)}
 * \f]
 */

template <typename T>
constexpr auto log2(const T x) noexcept -> return_t<T>
{
    return internal::log2_check(static_cast<return_t<T>>(x));
}

#endif
