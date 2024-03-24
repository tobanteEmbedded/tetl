// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // empty range
    {
        auto const vec = etl::static_vector<T, 4>{};
        CHECK(etl::lower_bound(begin(vec), end(vec), T(0)) == end(vec));
        CHECK(etl::lower_bound(begin(vec), end(vec), T(0), etl::greater{}) == end(vec));
    }

    // single element
    {
        auto v = etl::static_vector<T, 4>{};
        v.push_back(T(0));
        CHECK(etl::lower_bound(begin(v), end(v), T(0)) == begin(v));
        CHECK(etl::lower_bound(begin(v), end(v), T(1)) == end(v));
        CHECK(etl::lower_bound(begin(v), end(v), T(0), etl::greater{}) == begin(v));
        CHECK(etl::lower_bound(begin(v), end(v), T(1), etl::greater{}) == begin(v));

        // reset
        v.clear();
        v.push_back(T(1));
        CHECK(etl::lower_bound(begin(v), end(v), T(0)) == begin(v));
        CHECK(etl::lower_bound(begin(v), end(v), T(1)) == begin(v));
        CHECK(etl::lower_bound(begin(v), end(v), T(0), etl::greater{}) == end(v));
        CHECK(etl::lower_bound(begin(v), end(v), T(1), etl::greater{}) == begin(v));
    }

    // multiple elements
    {
        auto const a = etl::array{T(0), T(1), T(2), T(3)};
        CHECK(etl::lower_bound(begin(a), end(a), T(0)) == begin(a));
        CHECK(etl::lower_bound(begin(a), end(a), T(1)) == begin(a) + 1);
        CHECK(etl::lower_bound(begin(a), end(a), T(4)) == end(a));
        CHECK(etl::lower_bound(begin(a), end(a), T(0), etl::greater{}) == end(a));
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
