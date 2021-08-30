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

#ifndef GCEM_fmod_HPP
#define GCEM_fmod_HPP

namespace internal {

template <typename T>
constexpr auto fmod_check(const T x, const T y) noexcept -> T
{
    return ( // NaN check
        any_nan(x, y) ? etl::numeric_limits<T>::quiet_NaN() :
                      // +/- infinite
            !all_finite(x, y) ? etl::numeric_limits<T>::quiet_NaN()
                              :
                              // else
            x - trunc(x / y) * y);
}

template <typename T1, typename T2, typename TC = common_return_t<T1, T2>>
constexpr auto fmod_type_check(const T1 x, const T2 y) noexcept -> TC
{
    return fmod_check(static_cast<TC>(x), static_cast<TC>(y));
}

} // namespace internal

/**
 * Compile-time remainder of division function
 * @param x a real-valued input.
 * @param y a real-valued input.
 * @return computes the floating-point remainder of \f$ x / y \f$ (rounded
 * towards zero) using \f[ \text{fmod}(x,y) = x - \text{trunc}(x/y) \times y \f]
 */

template <typename T1, typename T2>
constexpr auto fmod(const T1 x, const T2 y) noexcept -> common_return_t<T1, T2>
{
    return internal::fmod_type_check(x, y);
}

#endif
