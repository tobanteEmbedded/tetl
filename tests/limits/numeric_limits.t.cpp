// SPDX-License-Identifier: BSL-1.0

#include <etl/limits.hpp>

#include "testing/testing.hpp"

[[nodiscard]] constexpr auto test_default() -> bool
{
    struct S {
        int i = 42;
    };

    assert(etl::numeric_limits<S>::is_specialized == false);
    assert(etl::numeric_limits<S>::is_signed == false);
    assert(etl::numeric_limits<S>::is_integer == false);
    assert(etl::numeric_limits<S>::is_bounded == false);

    assert(etl::numeric_limits<S>::min().i == 42);
    assert(etl::numeric_limits<S>::max().i == 42);
    assert(etl::numeric_limits<S>::lowest().i == 42);
    assert(etl::numeric_limits<S>::epsilon().i == 42);
    assert(etl::numeric_limits<S>::round_error().i == 42);
    assert(etl::numeric_limits<S>::infinity().i == 42);
    assert(etl::numeric_limits<S>::quiet_NaN().i == 42);
    assert(etl::numeric_limits<S>::signaling_NaN().i == 42);
    assert(etl::numeric_limits<S>::denorm_min().i == 42);

    return true;
}

[[nodiscard]] constexpr auto test_bool() -> bool
{
    assert(etl::numeric_limits<bool>::is_specialized == true);
    assert(etl::numeric_limits<bool>::is_signed == false);
    assert(etl::numeric_limits<bool>::is_integer == true);
    assert(etl::numeric_limits<bool>::is_bounded == true);

    assert(etl::numeric_limits<bool>::min() == false);
    assert(etl::numeric_limits<bool>::max() == true);
    assert(etl::numeric_limits<bool>::lowest() == false);
    assert(etl::numeric_limits<bool>::epsilon() == false);
    assert(etl::numeric_limits<bool>::round_error() == false);
    assert(etl::numeric_limits<bool>::infinity() == false);
    assert(etl::numeric_limits<bool>::quiet_NaN() == false);
    assert(etl::numeric_limits<bool>::signaling_NaN() == false);
    assert(etl::numeric_limits<bool>::denorm_min() == false);
    return true;
}

template <typename T>
[[nodiscard]] constexpr auto test_signed() -> bool
{
    assert(etl::numeric_limits<T>::is_specialized == true);
    assert(etl::numeric_limits<T>::is_signed == true);
    assert(etl::numeric_limits<T>::is_integer == true);
    assert(etl::numeric_limits<T>::is_bounded == true);
    assert(etl::numeric_limits<T>::lowest() == etl::numeric_limits<T>::min());
    assert(etl::numeric_limits<T>::max() > etl::numeric_limits<T>::min());
    assert(etl::numeric_limits<T>::epsilon() == T{});
    assert(etl::numeric_limits<T>::round_error() == T{});
    assert(etl::numeric_limits<T>::infinity() == T{});
    assert(etl::numeric_limits<T>::quiet_NaN() == T{});
    assert(etl::numeric_limits<T>::signaling_NaN() == T{});
    assert(etl::numeric_limits<T>::denorm_min() == T{});

    using lc = etl::numeric_limits<T const>;
    assert(lc::is_specialized == true);
    assert(lc::is_signed == true);
    assert(lc::is_integer == true);
    assert(lc::is_bounded == true);
    assert(lc::lowest() == lc::min());
    assert(lc::max() > lc::min());
    assert(lc::epsilon() == T{});
    assert(lc::round_error() == T{});
    assert(lc::infinity() == T{});
    assert(lc::quiet_NaN() == T{});
    assert(lc::signaling_NaN() == T{});
    assert(lc::denorm_min() == T{});

    using lv = etl::numeric_limits<T volatile>;
    assert(lv::is_specialized == true);
    assert(lv::is_signed == true);
    assert(lv::is_integer == true);
    assert(lv::is_bounded == true);
    assert(lv::lowest() == lv::min());
    assert(lv::max() > lv::min());
    assert(lv::epsilon() == T{});
    assert(lv::round_error() == T{});
    assert(lv::infinity() == T{});
    assert(lv::quiet_NaN() == T{});
    assert(lv::signaling_NaN() == T{});
    assert(lv::denorm_min() == T{});

    using lcv = etl::numeric_limits<T const volatile>;
    assert(lcv::is_specialized == true);
    assert(lcv::is_signed == true);
    assert(lcv::is_integer == true);
    assert(lcv::is_bounded == true);
    assert(lcv::lowest() == lcv::min());
    assert(lcv::max() > lcv::min());
    assert(lcv::epsilon() == T{});
    assert(lcv::round_error() == T{});
    assert(lcv::infinity() == T{});
    assert(lcv::quiet_NaN() == T{});
    assert(lcv::signaling_NaN() == T{});
    assert(lcv::denorm_min() == T{});
    return true;
}

template <typename T>
[[nodiscard]] constexpr auto test_unsigned() -> bool
{
    assert(etl::numeric_limits<T>::is_specialized == true);
    assert(etl::numeric_limits<T>::is_signed == false);
    assert(etl::numeric_limits<T>::is_integer == true);
    assert(etl::numeric_limits<T>::is_bounded == true);

    assert(etl::numeric_limits<T>::lowest() == etl::numeric_limits<T>::min());
    assert(etl::numeric_limits<T>::max() > etl::numeric_limits<T>::min());
    assert(etl::numeric_limits<T>::epsilon() == T{});
    assert(etl::numeric_limits<T>::round_error() == T{});
    assert(etl::numeric_limits<T>::infinity() == T{});
    assert(etl::numeric_limits<T>::quiet_NaN() == T{});
    assert(etl::numeric_limits<T>::signaling_NaN() == T{});
    assert(etl::numeric_limits<T>::denorm_min() == T{});
    return true;
}

[[nodiscard]] constexpr auto test_float_round_style() -> bool
{
    assert(etl::float_round_style::round_indeterminate == -1);
    assert(etl::float_round_style::round_toward_zero == 0);
    assert(etl::float_round_style::round_to_nearest == 1);
    assert(etl::float_round_style::round_toward_infinity == 2);
    assert(etl::float_round_style::round_toward_neg_infinity == 3);
    return true;
}

[[nodiscard]] constexpr auto test_float() -> bool
{
    assert(etl::numeric_limits<float>::is_specialized == true);
    assert(etl::numeric_limits<float>::is_signed == true);
    assert(etl::numeric_limits<float>::is_integer == false);
    assert(etl::numeric_limits<float>::is_bounded == true);

    assert(etl::numeric_limits<float>::min() == FLT_MIN);
    assert(etl::numeric_limits<float>::max() == FLT_MAX);
    assert(etl::numeric_limits<float>::lowest() == -FLT_MAX);
    assert(etl::numeric_limits<float>::epsilon() == FLT_EPSILON);
    assert(etl::numeric_limits<float>::round_error() == 0.5F);
    // assert(etl::numeric_limits<float>::infinity() == HUGE_VALF);

    return true;
}

[[nodiscard]] constexpr auto test_double() -> bool
{
    assert(etl::numeric_limits<double>::is_specialized == true);
    assert(etl::numeric_limits<double>::is_signed == true);
    assert(etl::numeric_limits<double>::is_integer == false);
    assert(etl::numeric_limits<double>::is_bounded == true);

    assert(etl::numeric_limits<double>::min() == DBL_MIN);
    assert(etl::numeric_limits<double>::max() == DBL_MAX);
    assert(etl::numeric_limits<double>::lowest() == -DBL_MAX);
    assert(etl::numeric_limits<double>::epsilon() == DBL_EPSILON);
    assert(etl::numeric_limits<double>::round_error() == 0.5);
    // assert(etl::numeric_limits<double>::infinity() == HUGE_VAL);

    return true;
}

auto main() -> int
{
    assert(test_bool());
    static_assert(test_bool());

    assert(test_signed<signed char>());
    static_assert(test_signed<signed char>());
    assert(test_signed<signed short>());
    static_assert(test_signed<signed short>());
    assert(test_signed<signed int>());
    static_assert(test_signed<signed int>());
    assert(test_signed<signed long>());
    static_assert(test_signed<signed long>());

    assert(test_unsigned<unsigned char>());
    static_assert(test_unsigned<unsigned char>());
    assert(test_unsigned<unsigned short>());
    static_assert(test_unsigned<unsigned short>());
    assert(test_unsigned<unsigned int>());
    static_assert(test_unsigned<unsigned int>());
    assert(test_unsigned<unsigned long>());
    static_assert(test_unsigned<unsigned long>());

    assert(test_float_round_style());
    static_assert(test_float_round_style());

    assert(test_float());
    static_assert(test_float());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    assert(test_signed<signed long long>());
    static_assert(test_signed<signed long long>());
    assert(test_unsigned<unsigned long long>());
    static_assert(test_unsigned<unsigned long long>());
    assert(test_double());
    static_assert(test_double());
#endif

    return 0;
}
