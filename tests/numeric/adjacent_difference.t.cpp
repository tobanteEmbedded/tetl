// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // empty
    {
        auto a = etl::static_vector<T, 1>{};
        CHECK(a.begin() == a.end());
        CHECK(etl::adjacent_difference(a.begin(), a.end(), a.begin()) == a.begin());
    }

    // "cppreference.com example"
    {
        etl::array a{T(2), T(4), T(6)};
        CHECK(etl::adjacent_difference(a.begin(), a.end(), a.begin()) == a.end());
        CHECK(a == etl::array{T(2), T(2), T(2)});
    }

    // "cppreference.com example"
    {
        etl::array a{T(2), T(4), T(6)};
        CHECK(etl::adjacent_difference(forward_iter(a.begin()), forward_iter(a.end()), a.begin()) == a.end());
        CHECK(a == etl::array{T(2), T(2), T(2)});
    }

    // "cppreference.com example fibonacci"
    {
        etl::array<T, 4> a{T(1)};
        etl::adjacent_difference(a.begin(), etl::prev(a.end()), etl::next(a.begin()), etl::plus<T>());
        CHECK(a == etl::array{T(1), T(1), T(2), T(3)});
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());

    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());

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
