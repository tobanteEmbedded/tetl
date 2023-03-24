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

#ifndef GCEM_lcm_HPP
#define GCEM_lcm_HPP

namespace internal {

template <typename T>
constexpr auto lcm_compute(const T a, const T b) noexcept -> T
{
    return abs(a * (b / gcd(a, b)));
}

template <typename T1, typename T2, typename TC = common_t<T1, T2>>
constexpr auto lcm_type_check(const T1 a, const T2 b) noexcept -> TC
{
    return lcm_compute(static_cast<TC>(a), static_cast<TC>(b));
}

} // namespace internal

/**
 * Compile-time least common multiple (LCM) function
 *
 * @param a integral-valued input.
 * @param b integral-valued input.
 * @return the least common multiple between integers \c a and \c b using the
 * representation \f[ \text{lcm}(a,b) = \dfrac{| a b |}{\text{gcd}(a,b)} \f]
 * where \f$ \text{gcd}(a,b) \f$ denotes the greatest common divisor between \f$
 * a \f$ and \f$ b \f$.
 */

template <typename T1, typename T2>
constexpr auto lcm(const T1 a, const T2 b) noexcept -> common_t<T1, T2>
{
    return internal::lcm_type_check(a, b);
}

#endif