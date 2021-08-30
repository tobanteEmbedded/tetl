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

#ifndef GCEM_round_HPP
#define GCEM_round_HPP

namespace internal {

template <typename T>
constexpr auto round_int(const T x) noexcept -> T
{
    return static_cast<T>(find_whole(x));
}

template <typename T>
constexpr auto round_check(const T x) noexcept -> T
{
    return ( // NaN check
        is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                  // +/- infinite
            !is_finite(x) ? x
                          :
                          // signed-zero cases
            etl::numeric_limits<T>::epsilon() > abs(x) ? x
                                                       :
                                                       // else
            sgn(x) * round_int(abs(x)));
}

} // namespace internal

/**
 * Compile-time round function
 *
 * @param x a real-valued input.
 * @return computes the rounding value of the input.
 */

template <typename T>
constexpr auto round(const T x) noexcept -> return_t<T>
{
    return internal::round_check(static_cast<return_t<T>>(x));
}

#endif
