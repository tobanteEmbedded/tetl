// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_LIMITS_HPP
#define TETL_LIMITS_HPP

#include "etl/version.hpp"

#ifdef _MSC_VER
#include <float.h>
#include <limits.h>
#include <math.h>
#else
#include "etl/cfloat.hpp"
#include "etl/climits.hpp"
#include "etl/cmath.hpp"
#endif

#include "etl/cstdint.hpp"

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

template <typename T>
class numeric_limits
{
  public:
  static constexpr bool is_specialized = false;

  static constexpr auto min() noexcept { return T(); }
  static constexpr auto max() noexcept { return T(); }
  static constexpr auto lowest() noexcept { return T(); }

  static constexpr int digits       = 0;
  static constexpr int digits10     = 0;
  static constexpr int max_digits10 = 0;

  static constexpr bool is_signed  = false;
  static constexpr bool is_integer = false;
  static constexpr bool is_exact   = false;
  static constexpr int radix       = 0;
  static constexpr auto epsilon() noexcept { return T(); }
  static constexpr auto round_error() noexcept { return T(); }

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept { return T(); }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept { return T(); }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept { return T(); }
  static constexpr auto denorm_min() noexcept { return T(); }

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

  static constexpr auto min() noexcept -> bool { return false; }
  static constexpr auto max() noexcept -> bool { return true; }
  static constexpr auto lowest() noexcept -> bool { return false; }

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

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> bool { return false; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> bool { return false; }
  // NOLINTNEXTLINE(readability-identifier-naming)
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
class numeric_limits<char>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto min() noexcept -> char { return CHAR_MIN; }
  static constexpr auto max() noexcept -> char { return CHAR_MAX; }
  static constexpr auto lowest() noexcept -> char { return CHAR_MIN; }

  static constexpr bool is_signed  = CHAR_MIN < 0;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept { return char {}; }
  static constexpr auto round_error() noexcept { return char {}; }

  static constexpr int digits = CHAR_BIT - (int)is_signed;
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept { return char {}; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept { return char {}; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept { return char {}; }
  static constexpr auto denorm_min() noexcept { return char {}; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = is_signed;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<signed char>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto min() noexcept -> signed char { return SCHAR_MIN; }
  static constexpr auto max() noexcept -> signed char { return SCHAR_MAX; }
  static constexpr auto lowest() noexcept -> signed char { return SCHAR_MIN; }

  static constexpr bool is_signed  = SCHAR_MIN < 0;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept -> signed char { return {}; }
  static constexpr auto round_error() noexcept -> signed char { return {}; }

  static constexpr int digits = CHAR_BIT - 1;
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> signed char { return {}; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> signed char { return {}; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept -> signed char { return {}; }
  static constexpr auto denorm_min() noexcept -> signed char { return {}; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = false;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<unsigned char>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> unsigned char { return 0; }
  static constexpr auto min() noexcept -> unsigned char { return 0; }
  static constexpr auto max() noexcept -> unsigned char { return UCHAR_MAX; }

  static constexpr bool is_signed  = false;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept -> unsigned char { return {}; }
  static constexpr auto round_error() noexcept -> unsigned char { return {}; }

  static constexpr int digits = CHAR_BIT;
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> unsigned char { return 0; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> unsigned char { return 0; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept -> unsigned char { return 0; }
  static constexpr auto denorm_min() noexcept -> unsigned char { return 0; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = true;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<short>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> short { return SHRT_MIN; }
  static constexpr auto min() noexcept -> short { return SHRT_MIN; }
  static constexpr auto max() noexcept -> short { return SHRT_MAX; }

  static constexpr bool is_signed  = true;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept { return short {}; }
  static constexpr auto round_error() noexcept { return short {}; }

  static constexpr int digits = CHAR_BIT * sizeof(short) - 1;
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept { return short {}; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept { return short {}; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept { return short {}; }
  static constexpr auto denorm_min() noexcept { return short {}; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = false;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<unsigned short>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> unsigned short { return 0; }
  static constexpr auto min() noexcept -> unsigned short { return 0; }
  static constexpr auto max() noexcept -> unsigned short { return USHRT_MAX; }

  static constexpr bool is_signed  = false;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept -> unsigned short { return {}; }
  static constexpr auto round_error() noexcept -> unsigned short { return {}; }

  static constexpr int digits = CHAR_BIT * sizeof(short);
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> unsigned short { return 0; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> unsigned short { return 0; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept -> unsigned short { return 0; }
  static constexpr auto denorm_min() noexcept -> unsigned short { return 0; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = true;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<int>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> int { return INT_MIN; }
  static constexpr auto min() noexcept -> int { return INT_MIN; }
  static constexpr auto max() noexcept -> int { return INT_MAX; }

  static constexpr bool is_signed  = true;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept { return int {}; }
  static constexpr auto round_error() noexcept { return int {}; }

  static constexpr int digits = CHAR_BIT * sizeof(int) - 1;
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept { return int {}; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept { return int {}; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept { return int {}; }
  static constexpr auto denorm_min() noexcept { return int {}; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = false;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<unsigned int>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> unsigned int { return 0; }
  static constexpr auto min() noexcept -> unsigned int { return 0; }
  static constexpr auto max() noexcept -> unsigned int { return UINT_MAX; }

  static constexpr bool is_signed  = false;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept -> unsigned int { return {}; }
  static constexpr auto round_error() noexcept -> unsigned int { return {}; }

  static constexpr int digits = CHAR_BIT * sizeof(int);
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> unsigned int { return 0; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> unsigned int { return 0; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept -> unsigned int { return 0; }
  static constexpr auto denorm_min() noexcept -> unsigned int { return 0; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = true;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<long>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> long { return LONG_MIN; }
  static constexpr auto min() noexcept -> long { return LONG_MIN; }
  static constexpr auto max() noexcept -> long { return LONG_MAX; }

  static constexpr bool is_signed  = true;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept { return long {}; }
  static constexpr auto round_error() noexcept { return long {}; }

  static constexpr int digits = CHAR_BIT * sizeof(long) - 1;
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept { return long {}; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept { return long {}; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept { return long {}; }
  static constexpr auto denorm_min() noexcept { return long {}; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = false;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

template <>
class numeric_limits<unsigned long>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> unsigned long { return 0; }
  static constexpr auto min() noexcept -> unsigned long { return 0; }
  static constexpr auto max() noexcept -> unsigned long { return ULONG_MAX; }

  static constexpr bool is_signed  = false;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept -> unsigned long { return {}; }
  static constexpr auto round_error() noexcept -> unsigned long { return {}; }

  static constexpr int digits = CHAR_BIT * sizeof(unsigned long);
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> unsigned long { return 0; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> unsigned long { return 0; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept -> unsigned long { return 0; }
  static constexpr auto denorm_min() noexcept -> unsigned long { return 0; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = true;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};

#if defined(LLONG_MIN) && defined(LLONG_MAX)
template <>
class numeric_limits<long long>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> long long { return LLONG_MIN; }
  static constexpr auto min() noexcept -> long long { return LLONG_MIN; }
  static constexpr auto max() noexcept -> long long { return LLONG_MAX; }

  static constexpr bool is_signed  = true;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept -> long long { return 0; }
  static constexpr auto round_error() noexcept -> long long { return 0; }

  static constexpr int digits = CHAR_BIT * sizeof(long long) - 1;
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> long long { return 0; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> long long { return 0; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept -> long long { return 0; }
  static constexpr auto denorm_min() noexcept -> long long { return 0; }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = false;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};
#endif

#if defined(ULLONG_MAX)
template <>
class numeric_limits<unsigned long long>
{
  public:
  static constexpr bool is_specialized = true;

  static constexpr auto lowest() noexcept -> unsigned long long { return 0; }
  static constexpr auto min() noexcept -> unsigned long long { return 0; }
  static constexpr auto max() noexcept -> unsigned long long
  {
    return ULLONG_MAX;
  }

  static constexpr bool is_signed  = false;
  static constexpr bool is_integer = true;
  static constexpr bool is_exact   = true;
  static constexpr int radix       = 2;
  static constexpr auto epsilon() noexcept -> unsigned long long { return {}; }
  static constexpr auto round_error() noexcept -> unsigned long long
  {
    return {};
  }

  static constexpr int digits = CHAR_BIT * sizeof(unsigned long long);
  // static constexpr int digits10     = digits * etl::log10(2);
  static constexpr int max_digits10 = 0;

  static constexpr int min_exponent   = 0;
  static constexpr int min_exponent10 = 0;
  static constexpr int max_exponent   = 0;
  static constexpr int max_exponent10 = 0;

  static constexpr bool has_infinity = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = false;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = false;
  static constexpr float_denorm_style has_denorm = denorm_absent;
  static constexpr bool has_denorm_loss          = false;
  static constexpr auto infinity() noexcept -> unsigned long long { return 0; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> unsigned long long { return 0; }
  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto signaling_NaN() noexcept -> unsigned long long
  {
    return 0;
  }
  static constexpr auto denorm_min() noexcept -> unsigned long long
  {
    return 0;
  }

  static constexpr bool is_iec559  = false;
  static constexpr bool is_bounded = true;
  static constexpr bool is_modulo  = true;

  static constexpr bool traps                    = true;
  static constexpr bool tinyness_before          = false;
  static constexpr float_round_style round_style = round_toward_zero;
};
#endif

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

  static constexpr bool has_infinity = true;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = true;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = true;
  static constexpr float_denorm_style has_denorm = denorm_present;
  static constexpr bool has_denorm_loss          = false;
  // static constexpr auto infinity() noexcept -> float { return HUGE_VALF; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> float { return NAN; }
  // NOLINTNEXTLINE(readability-identifier-naming)
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

  static constexpr bool has_infinity = true;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_quiet_NaN = true;

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr bool has_signaling_NaN        = true;
  static constexpr float_denorm_style has_denorm = denorm_present;
  static constexpr bool has_denorm_loss          = false;
  // static constexpr auto infinity() noexcept -> double { return HUGE_VAL; }

  // NOLINTNEXTLINE(readability-identifier-naming)
  static constexpr auto quiet_NaN() noexcept -> double { return NAN; }
  // NOLINTNEXTLINE(readability-identifier-naming)
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

#endif  // TETL_LIMITS_HPP
