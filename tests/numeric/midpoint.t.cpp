// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/limits.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename Int>
constexpr auto test_integer() -> bool
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
constexpr auto test_float() -> bool
{

    {
        auto const a = Float(-3.0);
        auto const b = Float(-4.0);
        CHECK(etl::midpoint(a, b) == Float(-3.5));
        CHECK(etl::midpoint(b, a) == Float(-3.5));
        CHECK(etl::midpoint(a, b) == Float(-3.5));
        CHECK(etl::midpoint(b, a) == Float(-3.5));
    }

    {
        auto const small = etl::numeric_limits<Float>::min();
        CHECK(etl::midpoint(small, small) == small);
    }

    {
        auto const large = etl::numeric_limits<Float>::max();
        CHECK(etl::midpoint(large, large) == large);
    }

    {
        auto const large = etl::numeric_limits<Float>::max();
        CHECK(etl::midpoint(large, large * Float(0.5)) == large * Float(0.75));
    }

    {
        auto const small = etl::numeric_limits<Float>::min();
        CHECK(etl::midpoint(small, small * Float(3)) == small * Float(2));
        CHECK(etl::midpoint(small * Float(3), small) == small * Float(2));
    }

    {
        auto const halfMax = etl::numeric_limits<Float>::max() / Float(2.0);
        auto const x       = halfMax + Float(4.0);
        auto const y       = halfMax + Float(8.0);
        CHECK(etl::midpoint(x, y) == halfMax + Float(6.0));
    }

    {
        auto const halfMax = etl::numeric_limits<Float>::max() / Float(2.0);
        auto const x       = -halfMax + Float(4.0);
        auto const y       = -halfMax + Float(8.0);
        CHECK(etl::midpoint(x, y) == -halfMax + Float(6.0));
    }

    return true;
}

template <typename T>
constexpr auto test_pointer() -> bool
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

constexpr auto test_all() -> bool
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
    CHECK(test_float<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
