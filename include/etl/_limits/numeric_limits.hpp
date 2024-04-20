// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LIMITS_NUMERIC_LIMITS_HPP
#define TETL_LIMITS_NUMERIC_LIMITS_HPP

#include <etl/_config/all.hpp>

#include <etl/_cfloat/defines.hpp>
#include <etl/_climits/defines.hpp>
#include <etl/_cmath/typedefs.hpp>
#include <etl/_limits/float_denorm_style.hpp>
#include <etl/_limits/float_round_style.hpp>

namespace etl {

template <typename T>
struct numeric_limits {
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
    static constexpr auto epsilon() noexcept -> T { return T(); }
    static constexpr auto round_error() noexcept -> T { return T(); }

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> T { return T(); }
    static constexpr auto quiet_NaN() noexcept -> T { return T(); }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> T { return T(); } // NOLINT
    static constexpr auto denorm_min() noexcept -> T { return T(); }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = false;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<bool> {
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

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> bool { return false; }
    static constexpr auto quiet_NaN() noexcept -> bool { return false; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> bool { return false; } // NOLINT
    static constexpr auto denorm_min() noexcept -> bool { return false; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<char> {
    static constexpr bool is_specialized = true;

    static constexpr auto min() noexcept -> char { return CHAR_MIN; }
    static constexpr auto max() noexcept -> char { return CHAR_MAX; }
    static constexpr auto lowest() noexcept -> char { return CHAR_MIN; }

    static constexpr bool is_signed  = CHAR_MIN < 0;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> char { return char{}; }
    static constexpr auto round_error() noexcept -> char { return char{}; }

    static constexpr int digits       = static_cast<int>(CHAR_BIT * sizeof(char) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> char { return char{}; }
    static constexpr auto quiet_NaN() noexcept -> char { return char{}; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> char { return char{}; } // NOLINT
    static constexpr auto denorm_min() noexcept -> char { return char{}; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = is_signed;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<signed char> {
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

    static constexpr int digits   = static_cast<int>(CHAR_BIT * sizeof(signed char) - static_cast<unsigned>(is_signed));
    static constexpr int digits10 = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> signed char { return {}; }
    static constexpr auto quiet_NaN() noexcept -> signed char { return {}; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> signed char { return {}; } // NOLINT
    static constexpr auto denorm_min() noexcept -> signed char { return {}; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<unsigned char> {
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

    static constexpr int digits = static_cast<int>(CHAR_BIT * sizeof(unsigned char) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> unsigned char { return 0; }
    static constexpr auto quiet_NaN() noexcept -> unsigned char { return 0; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> unsigned char { return 0; } // NOLINT
    static constexpr auto denorm_min() noexcept -> unsigned char { return 0; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = true;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<char8_t> {
    static constexpr bool is_specialized = true;

    static constexpr auto min() noexcept -> char8_t { return 0; }
    static constexpr auto max() noexcept -> char8_t { return UCHAR_MAX; }
    static constexpr auto lowest() noexcept -> char8_t { return min(); }

    static constexpr bool is_signed  = CHAR_MIN < 0;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> char8_t { return char8_t{}; }
    static constexpr auto round_error() noexcept -> char8_t { return char8_t{}; }

    static constexpr int digits       = 8;
    static constexpr int digits10     = 2;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> char8_t { return char8_t{}; }
    static constexpr auto quiet_NaN() noexcept -> char8_t { return char8_t{}; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> char8_t { return char8_t{}; } // NOLINT
    static constexpr auto denorm_min() noexcept -> char8_t { return char8_t{}; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = true;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<short> {
    static constexpr bool is_specialized = true;

    static constexpr auto lowest() noexcept -> short { return SHRT_MIN; }
    static constexpr auto min() noexcept -> short { return SHRT_MIN; }
    static constexpr auto max() noexcept -> short { return SHRT_MAX; }

    static constexpr bool is_signed  = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> short { return short{}; }
    static constexpr auto round_error() noexcept -> short { return short{}; }

    static constexpr int digits       = static_cast<int>(CHAR_BIT * sizeof(short) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> short { return short{}; }
    static constexpr auto quiet_NaN() noexcept -> short { return short{}; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> short { return short{}; } // NOLINT
    static constexpr auto denorm_min() noexcept -> short { return short{}; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<unsigned short> {
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

    static constexpr int digits
        = static_cast<int>(CHAR_BIT * sizeof(unsigned short) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> unsigned short { return 0; }
    static constexpr auto quiet_NaN() noexcept -> unsigned short { return 0; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> unsigned short { return 0; } // NOLINT
    static constexpr auto denorm_min() noexcept -> unsigned short { return 0; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = true;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<int> {
    static constexpr bool is_specialized = true;

    static constexpr auto lowest() noexcept -> int { return INT_MIN; }
    static constexpr auto min() noexcept -> int { return INT_MIN; }
    static constexpr auto max() noexcept -> int { return INT_MAX; }

    static constexpr bool is_signed  = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> int { return int{}; }
    static constexpr auto round_error() noexcept -> int { return int{}; }

    static constexpr int digits       = static_cast<int>(CHAR_BIT * sizeof(int) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_absent;

    static constexpr auto infinity() noexcept -> int { return int{}; }
    static constexpr auto quiet_NaN() noexcept -> int { return int{}; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> int { return int{}; } // NOLINT
    static constexpr auto denorm_min() noexcept -> int { return int{}; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<unsigned int> {
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

    static constexpr int digits = static_cast<int>(CHAR_BIT * sizeof(unsigned int) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr float_denorm_style has_denorm = denorm_absent;
    static constexpr bool has_denorm_loss          = false;

    static constexpr auto infinity() noexcept -> unsigned int { return 0; }
    static constexpr auto quiet_NaN() noexcept -> unsigned int { return 0; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> unsigned int { return 0; } // NOLINT
    static constexpr auto denorm_min() noexcept -> unsigned int { return 0; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = true;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<long> {
    static constexpr bool is_specialized = true;

    static constexpr auto lowest() noexcept -> long { return LONG_MIN; }
    static constexpr auto min() noexcept -> long { return LONG_MIN; }
    static constexpr auto max() noexcept -> long { return LONG_MAX; }

    static constexpr bool is_signed  = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> long { return long{}; }
    static constexpr auto round_error() noexcept -> long { return long{}; }

    static constexpr int digits       = static_cast<int>(CHAR_BIT * sizeof(long) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr float_denorm_style has_denorm = denorm_absent;
    static constexpr bool has_denorm_loss          = false;

    static constexpr auto infinity() noexcept -> long { return long{}; }
    static constexpr auto quiet_NaN() noexcept -> long { return long{}; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> long { return long{}; } // NOLINT
    static constexpr auto denorm_min() noexcept -> long { return long{}; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<unsigned long> {
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

    static constexpr int digits = static_cast<int>(CHAR_BIT * sizeof(unsigned long) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr float_denorm_style has_denorm = denorm_absent;
    static constexpr bool has_denorm_loss          = false;

    static constexpr auto infinity() noexcept -> unsigned long { return 0; }
    static constexpr auto quiet_NaN() noexcept -> unsigned long { return 0; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> unsigned long { return 0; } // NOLINT
    static constexpr auto denorm_min() noexcept -> unsigned long { return 0; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = true;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<long long> {
    static constexpr bool is_specialized = true;

    static constexpr auto lowest() noexcept -> long long
    {
#if defined(LLONG_MIN)
        return LLONG_MIN;
#else
        return -__LONG_LONG_MAX__ - 1;
#endif
    }

    static constexpr auto min() noexcept -> long long { return lowest(); }

    static constexpr auto max() noexcept -> long long
    {
#if defined(LLONG_MAX)
        return LLONG_MAX;
#else
        return __LONG_LONG_MAX__;
#endif
    }

    static constexpr bool is_signed  = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> long long { return 0; }
    static constexpr auto round_error() noexcept -> long long { return 0; }

    static constexpr int digits   = static_cast<int>(CHAR_BIT * sizeof(long long) - static_cast<unsigned>(is_signed));
    static constexpr int digits10 = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr float_denorm_style has_denorm = denorm_absent;
    static constexpr bool has_denorm_loss          = false;

    static constexpr auto infinity() noexcept -> long long { return 0; }
    static constexpr auto quiet_NaN() noexcept -> long long { return 0; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> long long { return 0; } // NOLINT
    static constexpr auto denorm_min() noexcept -> long long { return 0; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<unsigned long long> {
    static constexpr bool is_specialized = true;

    static constexpr auto lowest() noexcept -> unsigned long long { return 0; }
    static constexpr auto min() noexcept -> unsigned long long { return 0; }
    static constexpr auto max() noexcept -> unsigned long long { return static_cast<unsigned long long>(-1); }

    static constexpr bool is_signed  = false;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact   = true;
    static constexpr int radix       = 2;
    static constexpr auto epsilon() noexcept -> unsigned long long { return {}; }
    static constexpr auto round_error() noexcept -> unsigned long long { return {}; }

    static constexpr int digits
        = static_cast<int>(CHAR_BIT * sizeof(unsigned long long) - static_cast<unsigned>(is_signed));
    static constexpr int digits10     = digits * 3 / 10;
    static constexpr int max_digits10 = 0;

    static constexpr int min_exponent   = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent   = 0;
    static constexpr int max_exponent10 = 0;

    static constexpr bool has_infinity             = false;
    static constexpr bool has_quiet_NaN            = false; // NOLINT
    static constexpr bool has_signaling_NaN        = false; // NOLINT
    static constexpr float_denorm_style has_denorm = denorm_absent;
    static constexpr bool has_denorm_loss          = false;

    static constexpr auto infinity() noexcept -> unsigned long long { return 0; }
    static constexpr auto quiet_NaN() noexcept -> unsigned long long { return 0; }     // NOLINT
    static constexpr auto signaling_NaN() noexcept -> unsigned long long { return 0; } // NOLINT
    static constexpr auto denorm_min() noexcept -> unsigned long long { return 0; }

    static constexpr bool is_iec559  = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = true;

    static constexpr bool traps                    = true;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<float> {
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
    static constexpr bool has_quiet_NaN            = true; // NOLINT
    static constexpr bool has_signaling_NaN        = true; // NOLINT
    static constexpr float_denorm_style has_denorm = denorm_present;
    static constexpr bool has_denorm_loss          = false;

    static constexpr auto infinity() noexcept -> float { return TETL_BUILTIN_HUGE_VALF; }
    static constexpr auto quiet_NaN() noexcept -> float { return TETL_BUILTIN_NANF(""); }      // NOLINT
    static constexpr auto signaling_NaN() noexcept -> float { return TETL_BUILTIN_NANSF(""); } // NOLINT
    static constexpr auto denorm_min() noexcept -> float { return 0.0F; }

    static constexpr bool is_iec559  = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<double> {
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
    static constexpr bool has_quiet_NaN            = true; // NOLINT
    static constexpr bool has_signaling_NaN        = true; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_present;

    static constexpr auto infinity() noexcept -> double { return TETL_BUILTIN_HUGE_VAL; }
    static constexpr auto quiet_NaN() noexcept -> double { return TETL_BUILTIN_NAN(""); }      // NOLINT
    static constexpr auto signaling_NaN() noexcept -> double { return TETL_BUILTIN_NANS(""); } // NOLINT
    static constexpr auto denorm_min() noexcept -> double { return 0.0; }

    static constexpr bool is_iec559  = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <>
struct numeric_limits<long double> {
    static constexpr bool is_specialized = true;

    static constexpr auto min() noexcept { return LDBL_MIN; }
    static constexpr auto max() noexcept { return LDBL_MAX; }
    static constexpr auto lowest() noexcept { return -LDBL_MAX; }

    static constexpr int digits       = LDBL_MANT_DIG;
    static constexpr int digits10     = LDBL_DIG;
    static constexpr int max_digits10 = 2 + LDBL_MANT_DIG * 301L / 1000;

    static constexpr bool is_signed  = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact   = false;
    static constexpr int radix       = FLT_RADIX;
    static constexpr auto epsilon() noexcept -> long double { return LDBL_EPSILON; }
    static constexpr auto round_error() noexcept -> long double { return 0.5L; }

    static constexpr int min_exponent   = LDBL_MIN_EXP;
    static constexpr int min_exponent10 = LDBL_MIN_10_EXP;
    static constexpr int max_exponent   = LDBL_MAX_EXP;
    static constexpr int max_exponent10 = LDBL_MAX_10_EXP;

    static constexpr bool has_infinity             = true;
    static constexpr bool has_quiet_NaN            = true; // NOLINT
    static constexpr bool has_signaling_NaN        = true; // NOLINT
    static constexpr bool has_denorm_loss          = false;
    static constexpr float_denorm_style has_denorm = denorm_present;

    static constexpr auto infinity() noexcept -> long double { return TETL_BUILTIN_HUGE_VALL; }
    static constexpr auto quiet_NaN() noexcept -> long double { return TETL_BUILTIN_NANL(""); }      // NOLINT
    static constexpr auto signaling_NaN() noexcept -> long double { return TETL_BUILTIN_NANSL(""); } // NOLINT
    static constexpr auto denorm_min() noexcept -> long double { return 0.0L; }

    static constexpr bool is_iec559  = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo  = false;

    static constexpr bool traps                    = false;
    static constexpr bool tinyness_before          = false;
    static constexpr float_round_style round_style = round_toward_zero;
};

template <typename T>
struct numeric_limits<T const> : numeric_limits<T> { };
template <typename T>
struct numeric_limits<T volatile> : numeric_limits<T> { };
template <typename T>
struct numeric_limits<T const volatile> : numeric_limits<T> { };

} // namespace etl

#endif // TETL_LIMITS_NUMERIC_LIMITS_HPP
