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

namespace taetl
{
/**
 * @brief The class template provides compile-time rational
 * arithmetic support. Each instantiation of this template exactly represents
 * any finite rational number as long as its numerator Num and denominator Denom
 * are representable as compile-time constants of type taetl::intmax_t.
 */
template <taetl::intmax_t Num, taetl::intmax_t Denom = 1>
class ratio
{
};

using atto  = taetl::ratio<1, 1000000000000000000>;
using femto = taetl::ratio<1, 1000000000000000>;
using pico  = taetl::ratio<1, 1000000000000>;
using nano  = taetl::ratio<1, 1000000000>;
using micro = taetl::ratio<1, 1000000>;
using milli = taetl::ratio<1, 1000>;
using centi = taetl::ratio<1, 100>;
using deci  = taetl::ratio<1, 10>;
using deca  = taetl::ratio<10, 1>;
using hecto = taetl::ratio<100, 1>;
using kilo  = taetl::ratio<1000, 1>;
using mega  = taetl::ratio<1000000, 1>;
using giga  = taetl::ratio<1000000000, 1>;
using tera  = taetl::ratio<1000000000000, 1>;
using peta  = taetl::ratio<1000000000000000, 1>;
using exa   = taetl::ratio<1000000000000000000, 1>;

}  // namespace taetl

#endif  // TAETL_RATIO_HPP