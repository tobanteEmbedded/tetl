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
 * compile-time power function
 */

#ifndef GCEM_pow_integral_HPP
#define GCEM_pow_integral_HPP

namespace internal {

template <typename T1, typename T2>
constexpr auto pow_integral_compute(T1 base, T2 expTerm) noexcept -> T1;

// integral-valued powers using method described in
// https://en.wikipedia.org/wiki/Exponentiation_by_squaring

template <typename T1, typename T2>
constexpr auto pow_integral_compute_recur(const T1 base, const T1 val, const T2 expTerm) noexcept -> T1
{
    return (
        expTerm > T2(1) ? (is_odd(expTerm) ? pow_integral_compute_recur(base * base, val * base, expTerm / 2)
                                           : pow_integral_compute_recur(base * base, val, expTerm / 2))
                        : (expTerm == T2(1) ? val * base : val)
    );
}

template <typename T1, typename T2, typename etl::enable_if<etl::is_signed<T2>::value>::type* = nullptr>
constexpr auto pow_integral_sgn_check(const T1 base, const T2 expTerm) noexcept -> T1
{
    return (
        expTerm < T2(0) ? //
            T1(1) / pow_integral_compute(base, -expTerm)
                        :
                        //
            pow_integral_compute_recur(base, T1(1), expTerm)
    );
}

template <typename T1, typename T2, typename etl::enable_if<!etl::is_signed<T2>::value>::type* = nullptr>
constexpr auto pow_integral_sgn_check(const T1 base, const T2 expTerm) noexcept -> T1
{
    return (pow_integral_compute_recur(base, T1(1), expTerm));
}

template <typename T1, typename T2>
constexpr auto pow_integral_compute(const T1 base, const T2 expTerm) noexcept -> T1
{
    return (
        expTerm == T2(3)   ? base * base * base
        : expTerm == T2(2) ? base * base
        : expTerm == T2(1) ? base
        : expTerm == T2(0) ? T1(1)
                           :
                           // check for overflow
            expTerm == etl::numeric_limits<T2>::min() ? T1(0)
        : expTerm == etl::numeric_limits<T2>::max()   ? etl::numeric_limits<T1>::infinity()
                                                      :
                                                    // else
            pow_integral_sgn_check(base, expTerm)
    );
}

template <typename T1, typename T2, typename etl::enable_if<etl::is_integral<T2>::value>::type* = nullptr>
constexpr auto pow_integral_type_check(const T1 base, const T2 expTerm) noexcept -> T1
{
    return pow_integral_compute(base, expTerm);
}

template <typename T1, typename T2, typename etl::enable_if<!etl::is_integral<T2>::value>::type* = nullptr>
constexpr auto pow_integral_type_check(const T1 base, const T2 expTerm) noexcept -> T1
{
    // return etl::numeric_limits<return_t<T1>>::quiet_NaN();
    return pow_integral_compute(base, static_cast<llint_t>(expTerm));
}

//
// main function

template <typename T1, typename T2>
constexpr auto pow_integral(const T1 base, const T2 expTerm) noexcept -> T1
{
    return internal::pow_integral_type_check(base, expTerm);
}

} // namespace internal

#endif
