// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/limits.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test_integer() -> bool
{
    if constexpr (etl::is_signed_v<T>) {
        CHECK(etl::midpoint<T>(-3, -4) == -3);
        CHECK(etl::midpoint<T>(-4, -3) == -4);
        CHECK(etl::midpoint<T>(-3, -4) == -3);
        CHECK(etl::midpoint<T>(-4, -3) == -4);
    }

    CHECK(etl::midpoint(T(0), T(2)) == T(1));
    CHECK(etl::midpoint(T(0), T(4)) == T(2));
    CHECK(etl::midpoint(T(0), T(8)) == T(4));
    return true;
}

template <typename T>
constexpr auto test_floats() -> bool
{

    {
        auto const a = T(-3.0);
        auto const b = T(-4.0);
        CHECK(etl::midpoint(a, b) == T(-3.5));
        CHECK(etl::midpoint(b, a) == T(-3.5));
        CHECK(etl::midpoint(a, b) == T(-3.5));
        CHECK(etl::midpoint(b, a) == T(-3.5));
    }

    {
        auto const small = etl::numeric_limits<T>::min();
        CHECK(etl::midpoint(small, small) == small);
    }

    {
        auto const halfMax = etl::numeric_limits<T>::max() / T(2.0);
        auto const x       = halfMax + T(4.0);
        auto const y       = halfMax + T(8.0);
        CHECK(etl::midpoint(x, y) == halfMax + T(6.0));
    }

    {
        auto const halfMax = etl::numeric_limits<T>::max() / T(2.0);
        auto const x       = -halfMax + T(4.0);
        auto const y       = -halfMax + T(8.0);
        CHECK(etl::midpoint(x, y) == -halfMax + T(6.0));
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
    CHECK(test_integer<unsigned char>());
    CHECK(test_integer<unsigned short>());
    CHECK(test_integer<unsigned int>());
    CHECK(test_integer<unsigned long>());
    CHECK(test_integer<signed char>());
    CHECK(test_integer<signed short>());
    CHECK(test_integer<signed int>());
    CHECK(test_integer<signed long>());

    CHECK(test_floats<float>());
    CHECK(test_floats<double>());

    CHECK(test_pointer<char>());
    CHECK(test_pointer<short>());
    CHECK(test_pointer<int>());
    CHECK(test_pointer<long>());
    CHECK(test_pointer<float>());
    CHECK(test_pointer<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
