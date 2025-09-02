// SPDX-License-Identifier: BSL-1.0

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/limits.hpp>
    #include <etl/numeric.hpp>
#endif

template <typename Int>
static constexpr auto test_integer() -> bool
{
    if constexpr (etl::is_signed_v<Int>) {
        CHECK(etl::midpoint<Int>(-3, -4) == -3);
        CHECK(etl::midpoint<Int>(-4, -3) == -4);
        CHECK(etl::midpoint<Int>(-3, -4) == -3);
        CHECK(etl::midpoint<Int>(-4, -3) == -4);
    }

    CHECK(etl::midpoint(Int(0), Int(2)) == Int(1));
    CHECK(etl::midpoint(Int(0), Int(4)) == Int(2));
    CHECK(etl::midpoint(Int(0), Int(8)) == Int(4));

    auto const large = etl::numeric_limits<Int>::max();
    CHECK(etl::midpoint(large, large) == large);
    CHECK(etl::midpoint(Int(large - Int(2)), large) == large - Int(1));
    CHECK(etl::midpoint(large, Int(large - Int(2))) == large - Int(1));

    return true;
}

template <typename Float>
static constexpr auto test_float() -> bool
{
    constexpr auto min     = etl::numeric_limits<Float>::min();
    constexpr auto max     = etl::numeric_limits<Float>::max();
    constexpr auto halfMax = max / Float(2.0);

    CHECK(etl::midpoint(Float(0), Float(0)) == Float(0));
    CHECK(etl::midpoint(Float(1), Float(1)) == Float(1));

    CHECK(etl::midpoint(min, min) == min);
    CHECK(etl::midpoint(max, max) == max);

    CHECK_APPROX(etl::midpoint(Float(0), min), min / Float(2));
    CHECK_APPROX(etl::midpoint(min, Float(0)), min / Float(2));
    CHECK_APPROX(etl::midpoint(Float(0), min), min / Float(2));

    CHECK_APPROX(etl::midpoint(Float(0), max), max / Float(2));
    CHECK_APPROX(etl::midpoint(max, Float(0)), max / Float(2));
    CHECK_APPROX(etl::midpoint(Float(0), max), max / Float(2));

    CHECK(etl::midpoint(max, max * Float(0.5)) == max * Float(0.75));
    CHECK(etl::midpoint(min, min * Float(3)) == min * Float(2));
    CHECK(etl::midpoint(min * Float(3), min) == min * Float(2));

    {
        auto const x = halfMax + Float(4.0);
        auto const y = halfMax + Float(8.0);
        CHECK(etl::midpoint(x, y) == halfMax + Float(6.0));
    }

    {
        auto const x = -halfMax + Float(4.0);
        auto const y = -halfMax + Float(8.0);
        CHECK(etl::midpoint(x, y) == -halfMax + Float(6.0));
    }

    {
        auto const a = Float(-3.0);
        auto const b = Float(-4.0);
        CHECK(etl::midpoint(a, b) == Float(-3.5));
        CHECK(etl::midpoint(b, a) == Float(-3.5));
        CHECK(etl::midpoint(a, b) == Float(-3.5));
        CHECK(etl::midpoint(b, a) == Float(-3.5));
    }

    return true;
}

template <typename T>
static constexpr auto test_pointer() -> bool
{
    {
        T data[] = {T(1), T(2), T(3), T(4)};
        CHECK(*etl::midpoint(&data[0], &data[2]) == 2);
        CHECK(*etl::midpoint(&data[2], &data[0]) == 2);
        CHECK(*etl::midpoint(&data[0], &data[2]) == 2);
        CHECK(*etl::midpoint(&data[2], &data[0]) == 2);
    }

    {
        T data[] = {T(1), T(2), T(3), T(4), T(5)};
        CHECK(*etl::midpoint(&data[0], &data[3]) == T(2));
        CHECK(*etl::midpoint(&data[0], &data[3]) == T(2));

        CHECK(*etl::midpoint(&data[3], &data[0]) == T(3));
        CHECK(*etl::midpoint(&data[3], &data[0]) == T(3));
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test_pointer<char>());
    CHECK(test_pointer<short>());
    CHECK(test_pointer<int>());
    CHECK(test_pointer<long>());
    CHECK(test_pointer<float>());
    CHECK(test_pointer<double>());

    CHECK(test_integer<unsigned char>());
    CHECK(test_integer<unsigned short>());
    CHECK(test_integer<unsigned int>());
    CHECK(test_integer<unsigned long>());
    CHECK(test_integer<signed char>());
    CHECK(test_integer<signed short>());
    CHECK(test_integer<signed int>());
    CHECK(test_integer<signed long>());

    CHECK(test_float<float>());
    CHECK(test_float<double>());

#if not(defined(_MSC_VER) and not defined(__clang__))
    CHECK(test_float<long double>());
#endif

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
