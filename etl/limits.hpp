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

#include <float.h>
#include <math.h>

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

enum float_denorm_style
{
    denorm_indeterminate = -1,
    denorm_absent        = 0,
    denorm_present       = 1
};

template <class T>
class numeric_limits
{
public:
    static constexpr bool is_specialized = false;

    static constexpr auto min() noexcept { return T {}; }
    static constexpr auto max() noexcept { return T {}; }
    static constexpr auto lowest() noexcept { return T {}; }

    static constexpr int digits       = 0;
    static constexpr int digits10     = 0;
    static constexpr int max_digits10 = 0;

    static constexpr bool is_signed  = false;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact   = false;
    static constexpr int radix       = 0;
    static constexpr auto epsilon() noexcept { return T {}; }
    static constexpr auto round_error() noexcept { return T {}; }

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false;
    static constexpr bool has_signaling_NaN        = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;
    static constexpr bool has_denorm_loss          = false;
    static constexpr auto infinity() noexcept { return T {}; }
    static constexpr auto quiet_NaN() noexcept { return T {}; }
    static constexpr auto signaling_NaN() noexcept { return T {}; }
    static constexpr auto denorm_min() noexcept { return T {}; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = false;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<bool>
{
public:
    static constexpr bool is_specialized = true;

    static constexpr auto min() noexcept { return false; }
    static constexpr auto max() noexcept { return true; }
    static constexpr auto lowest() noexcept { return false; }

    static constexpr int digits       = 1;
    static constexpr int digits10     = 0;
    static constexpr int max_digits10 = 0;

    static constexpr bool is_signed  = false;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> bool { return false; }
    static constexpr auto round_error() noexcept -> bool { return false; }

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false;
    static constexpr bool has_signaling_NaN        = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;
    static constexpr bool has_denorm_loss          = false;
    static constexpr auto infinity() noexcept -> bool { return false; }
    static constexpr auto quiet_NaN() noexcept -> bool { return false; }
    static constexpr auto signaling_NaN() noexcept -> bool { return false; }
    static constexpr auto denorm_min() noexcept -> bool { return false; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<float>
{
public:
    static constexpr bool is_specialized = true;

    static constexpr auto min() noexcept { return FLT_MIN; }
    static constexpr auto max() noexcept { return FLT_MAX; }
    static constexpr auto lowest() noexcept { return -FLT_MAX; }

    static constexpr int digits       = FLT_MANT_DIG;
    static constexpr int digits10     = FLT_DIG;
    static constexpr int max_digits10 = DECIMAL_DIG;

    static constexpr bool is_signed  = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact   = false;
    static constexpr int radix       = FLT_RADIX;
    static constexpr auto epsilon() noexcept -> float { return FLT_EPSILON; }
    static constexpr auto round_error() noexcept -> float { return 0.5F; }

    static constexpr int min_exponent   = FLT_MIN_EXP;
    static constexpr int min_exponent10 = FLT_MIN_10_EXP;
    static constexpr int max_exponent   = FLT_MAX_EXP;
    static constexpr int max_exponent10 = FLT_MAX_10_EXP;

    static constexpr bool has_infinity             = true;
    static constexpr bool has_quiet_NaN            = true;
    static constexpr bool has_signaling_NaN        = true;
    static constexpr float_denorm_style has_denorm = denorm_present;
    static constexpr bool has_denorm_loss          = false;
    // static constexpr auto infinity() noexcept -> float { return HUGE_VALF; }
    static constexpr auto quiet_NaN() noexcept -> float { return NAN; }
    static constexpr auto signaling_NaN() noexcept -> float { return NAN; }
    static constexpr auto denorm_min() noexcept -> float { return 0.0F; }

    static constexpr bool is_iec559  = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<double>
{
public:
    static constexpr bool is_specialized = true;

    static constexpr auto min() noexcept { return DBL_MIN; }
    static constexpr auto max() noexcept { return DBL_MAX; }
    static constexpr auto lowest() noexcept { return -DBL_MAX; }

    static constexpr int digits       = DBL_MANT_DIG;
    static constexpr int digits10     = DBL_DIG;
    static constexpr int max_digits10 = DECIMAL_DIG;

    static constexpr bool is_signed  = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact   = false;
    static constexpr int radix       = FLT_RADIX;
    static constexpr auto epsilon() noexcept -> double { return DBL_EPSILON; }
    static constexpr auto round_error() noexcept -> double { return 0.5; }

    static constexpr int min_exponent   = DBL_MIN_EXP;
    static constexpr int min_exponent10 = DBL_MIN_10_EXP;
    static constexpr int max_exponent   = DBL_MAX_EXP;
    static constexpr int max_exponent10 = DBL_MAX_10_EXP;

    static constexpr bool has_infinity             = true;
    static constexpr bool has_quiet_NaN            = true;
    static constexpr bool has_signaling_NaN        = true;
    static constexpr float_denorm_style has_denorm = denorm_present;
    static constexpr bool has_denorm_loss          = false;
    // static constexpr auto infinity() noexcept -> double { return HUGE_VAL; }
    static constexpr auto quiet_NaN() noexcept -> double { return NAN; }
    static constexpr auto signaling_NaN() noexcept -> double { return NAN; }
    static constexpr auto denorm_min() noexcept -> double { return 0.0; }

    static constexpr bool is_iec559  = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

}  // namespace etl

#endif  // TAETL_LIMITS_HPP
