// SPDX-License-Identifier: BSL-1.0

#include <etl/limits.hpp>

#include "testing/testing.hpp"

[[nodiscard]] constexpr auto test_default() -> bool
{
    struct S {
        int i = 42;
    };

    CHECK(etl::numeric_limits<S>::is_specialized == false);
    CHECK(etl::numeric_limits<S>::is_signed == false);
    CHECK(etl::numeric_limits<S>::is_integer == false);
    CHECK(etl::numeric_limits<S>::is_bounded == false);

    CHECK(etl::numeric_limits<S>::min().i == 42);
    CHECK(etl::numeric_limits<S>::max().i == 42);
    CHECK(etl::numeric_limits<S>::lowest().i == 42);
    CHECK(etl::numeric_limits<S>::epsilon().i == 42);
    CHECK(etl::numeric_limits<S>::round_error().i == 42);
    CHECK(etl::numeric_limits<S>::infinity().i == 42);
    CHECK(etl::numeric_limits<S>::quiet_NaN().i == 42);
    CHECK(etl::numeric_limits<S>::signaling_NaN().i == 42);
    CHECK(etl::numeric_limits<S>::denorm_min().i == 42);

    return true;
}

[[nodiscard]] constexpr auto test_bool() -> bool
{
    CHECK(etl::numeric_limits<bool>::is_specialized == true);
    CHECK(etl::numeric_limits<bool>::is_signed == false);
    CHECK(etl::numeric_limits<bool>::is_integer == true);
    CHECK(etl::numeric_limits<bool>::is_bounded == true);

    CHECK(etl::numeric_limits<bool>::min() == false);
    CHECK(etl::numeric_limits<bool>::max() == true);
    CHECK(etl::numeric_limits<bool>::lowest() == false);
    CHECK(etl::numeric_limits<bool>::epsilon() == false);
    CHECK(etl::numeric_limits<bool>::round_error() == false);
    CHECK(etl::numeric_limits<bool>::infinity() == false);
    CHECK(etl::numeric_limits<bool>::quiet_NaN() == false);
    CHECK(etl::numeric_limits<bool>::signaling_NaN() == false);
    CHECK(etl::numeric_limits<bool>::denorm_min() == false);
    return true;
}

template <typename T>
[[nodiscard]] constexpr auto test_signed() -> bool
{
    CHECK(etl::numeric_limits<T>::is_specialized == true);
    CHECK(etl::numeric_limits<T>::is_signed == true);
    CHECK(etl::numeric_limits<T>::is_integer == true);
    CHECK(etl::numeric_limits<T>::is_bounded == true);
    CHECK(etl::numeric_limits<T>::lowest() == etl::numeric_limits<T>::min());
    CHECK(etl::numeric_limits<T>::max() > etl::numeric_limits<T>::min());
    CHECK(etl::numeric_limits<T>::epsilon() == T{});
    CHECK(etl::numeric_limits<T>::round_error() == T{});
    CHECK(etl::numeric_limits<T>::infinity() == T{});
    CHECK(etl::numeric_limits<T>::quiet_NaN() == T{});
    CHECK(etl::numeric_limits<T>::signaling_NaN() == T{});
    CHECK(etl::numeric_limits<T>::denorm_min() == T{});

    using lc = etl::numeric_limits<T const>;
    CHECK(lc::is_specialized == true);
    CHECK(lc::is_signed == true);
    CHECK(lc::is_integer == true);
    CHECK(lc::is_bounded == true);
    CHECK(lc::lowest() == lc::min());
    CHECK(lc::max() > lc::min());
    CHECK(lc::epsilon() == T{});
    CHECK(lc::round_error() == T{});
    CHECK(lc::infinity() == T{});
    CHECK(lc::quiet_NaN() == T{});
    CHECK(lc::signaling_NaN() == T{});
    CHECK(lc::denorm_min() == T{});

    using lv = etl::numeric_limits<T volatile>;
    CHECK(lv::is_specialized == true);
    CHECK(lv::is_signed == true);
    CHECK(lv::is_integer == true);
    CHECK(lv::is_bounded == true);
    CHECK(lv::lowest() == lv::min());
    CHECK(lv::max() > lv::min());
    CHECK(lv::epsilon() == T{});
    CHECK(lv::round_error() == T{});
    CHECK(lv::infinity() == T{});
    CHECK(lv::quiet_NaN() == T{});
    CHECK(lv::signaling_NaN() == T{});
    CHECK(lv::denorm_min() == T{});

    using lcv = etl::numeric_limits<T const volatile>;
    CHECK(lcv::is_specialized == true);
    CHECK(lcv::is_signed == true);
    CHECK(lcv::is_integer == true);
    CHECK(lcv::is_bounded == true);
    CHECK(lcv::lowest() == lcv::min());
    CHECK(lcv::max() > lcv::min());
    CHECK(lcv::epsilon() == T{});
    CHECK(lcv::round_error() == T{});
    CHECK(lcv::infinity() == T{});
    CHECK(lcv::quiet_NaN() == T{});
    CHECK(lcv::signaling_NaN() == T{});
    CHECK(lcv::denorm_min() == T{});
    return true;
}

template <typename T>
[[nodiscard]] constexpr auto test_unsigned() -> bool
{
    CHECK(etl::numeric_limits<T>::is_specialized == true);
    CHECK(etl::numeric_limits<T>::is_signed == false);
    CHECK(etl::numeric_limits<T>::is_integer == true);
    CHECK(etl::numeric_limits<T>::is_bounded == true);

    CHECK(etl::numeric_limits<T>::lowest() == etl::numeric_limits<T>::min());
    CHECK(etl::numeric_limits<T>::max() > etl::numeric_limits<T>::min());
    CHECK(etl::numeric_limits<T>::epsilon() == T{});
    CHECK(etl::numeric_limits<T>::round_error() == T{});
    CHECK(etl::numeric_limits<T>::infinity() == T{});
    CHECK(etl::numeric_limits<T>::quiet_NaN() == T{});
    CHECK(etl::numeric_limits<T>::signaling_NaN() == T{});
    CHECK(etl::numeric_limits<T>::denorm_min() == T{});
    return true;
}

[[nodiscard]] constexpr auto test_float_round_style() -> bool
{
    CHECK(etl::float_round_style::round_indeterminate == -1);
    CHECK(etl::float_round_style::round_toward_zero == 0);
    CHECK(etl::float_round_style::round_to_nearest == 1);
    CHECK(etl::float_round_style::round_toward_infinity == 2);
    CHECK(etl::float_round_style::round_toward_neg_infinity == 3);
    return true;
}

[[nodiscard]] constexpr auto test_float() -> bool
{
    CHECK(etl::numeric_limits<float>::is_specialized == true);
    CHECK(etl::numeric_limits<float>::is_signed == true);
    CHECK(etl::numeric_limits<float>::is_integer == false);
    CHECK(etl::numeric_limits<float>::is_bounded == true);

    CHECK(etl::numeric_limits<float>::min() == FLT_MIN);
    CHECK(etl::numeric_limits<float>::max() == FLT_MAX);
    CHECK(etl::numeric_limits<float>::lowest() == -FLT_MAX);
    CHECK(etl::numeric_limits<float>::epsilon() == FLT_EPSILON);
    CHECK(etl::numeric_limits<float>::round_error() == 0.5F);
    // CHECK(etl::numeric_limits<float>::infinity() == HUGE_VALF);

    return true;
}

[[nodiscard]] constexpr auto test_double() -> bool
{
    CHECK(etl::numeric_limits<double>::is_specialized == true);
    CHECK(etl::numeric_limits<double>::is_signed == true);
    CHECK(etl::numeric_limits<double>::is_integer == false);
    CHECK(etl::numeric_limits<double>::is_bounded == true);

    CHECK(etl::numeric_limits<double>::min() == DBL_MIN);
    CHECK(etl::numeric_limits<double>::max() == DBL_MAX);
    CHECK(etl::numeric_limits<double>::lowest() == -DBL_MAX);
    CHECK(etl::numeric_limits<double>::epsilon() == DBL_EPSILON);
    CHECK(etl::numeric_limits<double>::round_error() == 0.5);
    // CHECK(etl::numeric_limits<double>::infinity() == HUGE_VAL);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_bool());

    STATIC_CHECK(test_signed<signed char>());
    STATIC_CHECK(test_signed<signed short>());
    STATIC_CHECK(test_signed<signed int>());
    STATIC_CHECK(test_signed<signed long>());

    STATIC_CHECK(test_unsigned<unsigned char>());
    STATIC_CHECK(test_unsigned<unsigned short>());
    STATIC_CHECK(test_unsigned<unsigned int>());
    STATIC_CHECK(test_unsigned<unsigned long>());

    STATIC_CHECK(test_float_round_style());

    STATIC_CHECK(test_float());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    STATIC_CHECK(test_signed<signed long long>());
    STATIC_CHECK(test_unsigned<unsigned long long>());
    STATIC_CHECK(test_double());
#endif

    return 0;
}
