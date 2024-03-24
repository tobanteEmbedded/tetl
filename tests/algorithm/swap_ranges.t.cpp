// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto a        = etl::array{T(1), T(2)};
        decltype(a) b = {};

        etl::swap_ranges(begin(a), end(a), begin(b));
        CHECK(a[0] == T(0));
        CHECK(a[1] == T(0));
        CHECK(b[0] == T(1));
        CHECK(b[1] == T(2));
    }

    {
        auto data = etl::array{T(1), T(2)};
        etl::iter_swap(begin(data), begin(data) + 1);
        CHECK(data[0] == T(2));
        CHECK(data[1] == T(1));
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
