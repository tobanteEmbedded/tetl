// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // RHS == empty
    {
        auto const v1 = etl::array{T(1), T(2), T(3), T(4), T(5)};
        auto const v2 = etl::static_vector<T, 1>{};

        auto dest = etl::array<T, 5>{};
        etl::set_union(v1.begin(), v1.end(), v2.begin(), v2.end(), dest.begin());
        CHECK(dest == v1);
    }

    // RHS contains lower values
    {
        auto const v1 = etl::array{T(1), T(2), T(3), T(4), T(5)};
        auto const v2 = etl::array{T(0), T(0), T(1)};

        auto dest = etl::array<T, 7>{};
        etl::set_union(v1.begin(), v1.end(), v2.begin(), v2.end(), dest.begin());
        CHECK(dest == etl::array{T(0), T(0), T(1), T(2), T(3), T(4), T(5)});
    }

    // cppreference.com example #1
    {
        auto const v1 = etl::array{T(1), T(2), T(3), T(4), T(5)};
        auto const v2 = etl::array{T(3), T(4), T(5), T(6), T(7)};

        auto dest = etl::array<T, 7>{};
        etl::set_union(v1.begin(), v1.end(), v2.begin(), v2.end(), dest.begin());
        CHECK(dest == etl::array{T(1), T(2), T(3), T(4), T(5), T(6), T(7)});
    }

    // cppreference.com example #1
    {
        auto const v1 = etl::array{T(1), T(2), T(3), T(4), T(5), T(5), T(5)};
        auto const v2 = etl::array{T(3), T(4), T(5), T(6), T(7)};

        auto dest = etl::array<T, 9>{};
        etl::set_union(v1.begin(), v1.end(), v2.begin(), v2.end(), dest.begin());
        CHECK(dest == etl::array{T(1), T(2), T(3), T(4), T(5), T(5), T(5), T(6), T(7)});
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
