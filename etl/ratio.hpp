/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_RATIO_HPP
#define TAETL_RATIO_HPP

#include "definitions.hpp"
#include "numeric.hpp"
#include "type_traits.hpp"

namespace etl
{
namespace detail
{
template <typename T>
[[nodiscard]] constexpr auto sign(T val)
{
    if (val < 0) { return T(-1); }
    return T(1);
}
}  // namespace detail
/**
 * @brief The class template provides compile-time rational
 * arithmetic support. Each instantiation of this template exactly represents
 * any finite rational number as long as its numerator Num and denominator Denom
 * are representable as compile-time constants of type intmax_t.
 */
template <intmax_t Num, intmax_t Denom = 1>
struct ratio
{
    static constexpr intmax_t num
        = detail::sign(Num) * detail::sign(Denom) * abs(Num) / gcd(Num, Denom);
    static constexpr intmax_t den = abs(Denom) / gcd(Num, Denom);

    using type = ratio<num, den>;
};

/**
 * @brief The alias template etl::ratio_add denotes the result of adding two
 * exact rational fractions represented by the etl::ratio specializations R1
 * and R2.
 *
 * @details The result is a etl::ratio specialization etl::ratio<U, V>, such
 * that given Num == R1::num * R2::den + R2::num * R1::den and
 * Denom == R1::den * R2::den (computed without arithmetic overflow), U is
 * etl::ratio<Num, Denom>::num and V is etl::ratio<Num, Denom>::den.
 *
 * @todo Check overflow.
 */
template <class R1, class R2>
using ratio_add
    = ratio<R1::num * R2::den + R2::num * R1::den, R1::den * R2::den>;

/**
 * @brief The alias template etl::ratio_subtract denotes the result of
 * subtracting two exact rational fractions represented by the etl::ratio
 * specializations R1 and R2.
 *
 * @details The result is a etl::ratio specialization etl::ratio<U, V>, such
 * that given Num == R1::num * R2::den - R2::num * R1::den
 * and Denom == R1::den * R2::den (computed without arithmetic overflow), U is
 * etl::ratio<Num, Denom>::num and V is etl::ratio<Num, Denom>::den.
 *
 * @todo Check overflow.
 */
template <class R1, class R2>
using ratio_subtract
    = ratio<R1::num * R2::den - R2::num * R1::den, R1::den * R2::den>;

/**
 * @brief The alias template etl::ratio_multiply denotes the result of
 * multiplying two exact rational fractions represented by the etl::ratio
 * specializations R1 and R2.
 *
 * @details The result is a etl::ratio specialization etl::ratio<U, V>, such
 * that given Num == R1::num * R2::num and Denom == R1::den * R2::den (computed
 * without arithmetic overflow), U is etl::ratio<Num, Denom>::num and V is
 * etl::ratio<Num, Denom>::den.
 *
 * @todo Check overflow.
 */
template <class R1, class R2>
using ratio_multiply = ratio<R1::num * R2::num, R1::den * R2::den>;

/**
 * @brief The alias template etl::ratio_divide denotes the result of dividing
 * two exact rational fractions represented by the etl::ratio specializations R1
 * and R2.
 *
 * @details The result is a etl::ratio specialization etl::ratio<U, V>, such
 * that given Num == R1::num * R2::den and Denom == R1::den * R2::num (computed
 * without arithmetic overflow), U is etl::ratio<Num, Denom>::num and V is
 * etl::ratio<Num, Denom>::den.
 *
 * @todo Check overflow.
 */
template <class R1, class R2>
using ratio_divide = ratio<R1::num * R2::den, R1::den * R2::num>;

/**
 * @brief Compares two ratio objects for equality at compile-time. If the ratios
 * R1 and R2 are equal, provides the member constant value equal true.
 * Otherwise, value is false.
 */
template <class R1, class R2>
struct ratio_equal
    : public etl::integral_constant<bool,
                                    R1::num == R2::num && R1::den == R2::den>
{
};

template <class R1, class R2>
inline constexpr bool ratio_equal_v = ratio_equal<R1, R2>::value;

/**
 * @brief Compares two ratio objects for equality at compile-time. If the ratios
 * R1 and R2 are not equal, provides the member constant value equal true.
 * Otherwise, value is false.
 */
template <class R1, class R2>
struct ratio_not_equal
    : etl::integral_constant<bool, !etl::ratio_equal_v<R1, R2>>
{
};

template <class R1, class R2>
inline constexpr bool ratio_not_equal_v = ratio_not_equal<R1, R2>::value;

/**
 * @brief Compares two ratio objects for equality at compile-time. If the ratio
 * R1 is less than the ratio R2, provides the member constant value equal true.
 * Otherwise, value is false.
 */
template <class R1, class R2>
struct ratio_less
    : public etl::integral_constant<bool,
                                    (R1::num * R2::den < R2::num * R1::den)>
{
};

template <class R1, class R2>
inline constexpr bool ratio_less_v = ratio_less<R1, R2>::value;

/**
 * @brief Compares two ratio objects for equality at compile-time. If the ratio
 * R1 is less than or equal to the ratio R2, provides the member constant value
 * equal true. Otherwise, value is false.
 */
template <class R1, class R2>
struct ratio_less_equal
    : public etl::integral_constant<bool,
                                    (R1::num * R2::den <= R2::num * R1::den)>
{
};

template <class R1, class R2>
inline constexpr bool ratio_less_equal_v = ratio_less_equal<R1, R2>::value;

/**
 * @brief Compares two ratio objects for equality at compile-time
 */
template <class R1, class R2>
struct ratio_greater;
/**
 * @brief Compares two ratio objects for equality at compile-time
 */
template <class R1, class R2>
struct ratio_greater_equal;

using atto  = ratio<1, 1'000'000'000'000'000'000>;
using femto = ratio<1, 1'000'000'000'000'000>;
using pico  = ratio<1, 1'000'000'000'000>;
using nano  = ratio<1, 1'000'000'000>;
using micro = ratio<1, 1'000'000>;
using milli = ratio<1, 1'000>;
using centi = ratio<1, 100>;
using deci  = ratio<1, 10>;
using deca  = ratio<10, 1>;
using hecto = ratio<100, 1>;
using kilo  = ratio<1'000, 1>;
using mega  = ratio<1'000'000, 1>;
using giga  = ratio<1'000'000'000, 1>;
using tera  = ratio<1'000'000'000'000, 1>;
using peta  = ratio<1'000'000'000'000'000, 1>;
using exa   = ratio<1'000'000'000'000'000'000, 1>;

}  // namespace etl

#endif  // TAETL_RATIO_HPP