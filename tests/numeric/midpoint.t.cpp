// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/limits.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test_integer() -> bool
{
    if constexpr (etl::is_signed_v<T>) {
        assert(etl::midpoint<T>(-3, -4) == -3);
        assert(etl::midpoint<T>(-4, -3) == -4);
        assert(etl::midpoint<T>(-3, -4) == -3);
        assert(etl::midpoint<T>(-4, -3) == -4);
    }

    assert(etl::midpoint(T(0), T(2)) == T(1));
    assert(etl::midpoint(T(0), T(4)) == T(2));
    assert(etl::midpoint(T(0), T(8)) == T(4));
    return true;
}

template <typename T>
constexpr auto test_floats() -> bool
{

    {
        auto const a = T(-3.0);
        auto const b = T(-4.0);
        assert(etl::midpoint(a, b) == T(-3.5));
        assert(etl::midpoint(b, a) == T(-3.5));
        assert(etl::midpoint(a, b) == T(-3.5));
        assert(etl::midpoint(b, a) == T(-3.5));
    }

    {
        auto const small = etl::numeric_limits<T>::min();
        assert(etl::midpoint(small, small) == small);
    }

    {
        auto const halfMax = etl::numeric_limits<T>::max() / T(2.0);
        auto const x       = halfMax + T(4.0);
        auto const y       = halfMax + T(8.0);
        assert(etl::midpoint(x, y) == halfMax + T(6.0));
    }

    {
        auto const halfMax = etl::numeric_limits<T>::max() / T(2.0);
        auto const x       = -halfMax + T(4.0);
        auto const y       = -halfMax + T(8.0);
        assert(etl::midpoint(x, y) == -halfMax + T(6.0));
    }

    return true;
}

template <typename T>
constexpr auto test_pointer() -> bool
{
    {
        T data[] = {T(1), T(2), T(3), T(4)};
        assert(*etl::midpoint(&data[0], &data[2]) == 2);
        assert(*etl::midpoint(&data[2], &data[0]) == 2);
        assert(*etl::midpoint(&data[0], &data[2]) == 2);
        assert(*etl::midpoint(&data[2], &data[0]) == 2);
    }

    {
        T data[] = {T(1), T(2), T(3), T(4), T(5)};
        assert(*etl::midpoint(&data[0], &data[3]) == T(2));
        assert(*etl::midpoint(&data[0], &data[3]) == T(2));

        assert(*etl::midpoint(&data[3], &data[0]) == T(3));
        assert(*etl::midpoint(&data[3], &data[0]) == T(3));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_integer<unsigned char>());
    assert(test_integer<unsigned short>());
    assert(test_integer<unsigned int>());
    assert(test_integer<unsigned long>());
    assert(test_integer<signed char>());
    assert(test_integer<signed short>());
    assert(test_integer<signed int>());
    assert(test_integer<signed long>());

    assert(test_floats<float>());
    assert(test_floats<double>());

    assert(test_pointer<char>());
    assert(test_pointer<short>());
    assert(test_pointer<int>());
    assert(test_pointer<long>());
    assert(test_pointer<float>());
    assert(test_pointer<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
