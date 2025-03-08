// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    // first1,last1,first2
    {
        auto lhs    = etl::array{T(0), T(1), T(2)};
        auto rhs    = etl::array{T(0), T(1), T(3)};
        auto result = etl::mismatch(begin(lhs), end(lhs), begin(rhs));
        CHECK(*result.first == T(2));
        CHECK(*result.second == T(3));
    }

    // first1,last1,first2,last2
    {
        auto lhs    = etl::array{T(0), T(1), T(2)};
        auto rhs    = etl::array{T(0), T(1), T(4)};
        auto result = etl::mismatch(begin(lhs), end(lhs), begin(rhs), end(rhs));
        CHECK(*result.first == T(2));
        CHECK(*result.second == T(4));
    }
    return true;
}

static constexpr auto test_all() -> bool
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
