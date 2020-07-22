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

#ifndef TAETL_LIMITS_HPP
#define TAETL_LIMITS_HPP

#include "definitions.hpp"

namespace etl
{
enum float_round_style
{
    round_indeterminate       = -1,
    round_toward_zero         = 0,
    round_to_nearest          = 1,
    round_toward_infinity     = 2,
    round_toward_neg_infinity = 3
};

template <class T>
struct numeric_limits
{
    static constexpr bool is_specialized           = false;
    static constexpr bool is_signed                = false;
    static constexpr bool is_integer               = false;
    static constexpr bool is_exact                 = false;
    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false;
    static constexpr bool has_signaling_NaN        = false;
    static constexpr bool has_denorm               = false;
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_round_style round_style = round_toward_zero;
    static constexpr bool is_iec559                = false;
    static constexpr bool is_bounded               = false;
    static constexpr bool is_modulo                = false;
    static constexpr int digits                    = 0;
    static constexpr int digits10                  = 0;
    static constexpr int max_digits10              = 0;
    static constexpr int radix                     = 0;
    static constexpr int min_exponent              = 0;
    static constexpr int min_exponent10            = 0;
    static constexpr int max_exponent              = 0;
    static constexpr int max_exponent10            = 0;
    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
};
}  // namespace etl

#endif  // TAETL_LIMITS_HPP
