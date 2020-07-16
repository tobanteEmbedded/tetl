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

// TAETL
#include "definitions.hpp"
#include "numeric.hpp"

namespace taetl
{
namespace internal
{
template <typename T>
[[nodiscard]] constexpr auto sign(T val)
{
    if (val < 0) { return T(-1); }
    return T(1);
}
}  // namespace internal
/**
 * @brief The class template provides compile-time rational
 * arithmetic support. Each instantiation of this template exactly represents
 * any finite rational number as long as its numerator Num and denominator Denom
 * are representable as compile-time constants of type intmax_t.
 */
template <intmax_t Num, intmax_t Denom = 1>
struct ratio
{
    static constexpr intmax_t num = internal::sign(Num) * internal::sign(Denom)
                                    * abs(Num) / gcd(Num, Denom);
    static constexpr intmax_t den = abs(Denom) / gcd(Num, Denom);

    using type = ratio<num, den>;
};

using atto  = ratio<1, 1000000000000000000>;
using femto = ratio<1, 1000000000000000>;
using pico  = ratio<1, 1000000000000>;
using nano  = ratio<1, 1000000000>;
using micro = ratio<1, 1000000>;
using milli = ratio<1, 1000>;
using centi = ratio<1, 100>;
using deci  = ratio<1, 10>;
using deca  = ratio<10, 1>;
using hecto = ratio<100, 1>;
using kilo  = ratio<1000, 1>;
using mega  = ratio<1000000, 1>;
using giga  = ratio<1000000000, 1>;
using tera  = ratio<1000000000000, 1>;
using peta  = ratio<1000000000000000, 1>;
using exa   = ratio<1000000000000000000, 1>;

}  // namespace taetl

#endif  // TAETL_RATIO_HPP