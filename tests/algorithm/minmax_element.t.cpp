// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstddef.hpp>
#include <etl/functional.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto const in  = etl::static_vector<T, 1>{};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(out.first == in.end());
        CHECK(out.second == in.end());
    }

    {
        auto const in  = etl::array{T(1)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(1));
        CHECK(*out.second == T(1));
    }

    {
        auto const in  = etl::array{T(1), T(2)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(1));
        CHECK(*out.second == T(2));
    }

    {
        auto const in  = etl::array{T(1), T(2), T(3)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(1));
        CHECK(*out.second == T(3));
    }

    {
        auto const in  = etl::array{T(1), T(2), T(3)};
        auto const out = etl::minmax_element(in.begin(), in.end(), etl::greater{});
        CHECK(*out.first == T(3));
        CHECK(*out.second == T(1));
    }

    {
        auto const in  = etl::array{T(1), T(3), T(3)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(1));
        CHECK(*out.second == T(3));
    }

    {
        auto const in  = etl::array{T(1), T(2), T(3), T(4), T(5), T(6)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(1));
        CHECK(*out.second == T(6));
    }

    {
        auto const in  = etl::array{T(1), T(4), T(5), T(3), T(2)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(1));
        CHECK(*out.second == T(5));
    }

    {
        auto const in  = etl::array{T(100), T(99), T(0)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(0));
        CHECK(*out.second == T(100));
    }

    {
        auto const in  = etl::array{T(99), T(88), T(77), T(2), T(22), T(1), T(111), T(0), T(112), T(110)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        CHECK(*out.first == T(0));
        CHECK(*out.second == T(112));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
