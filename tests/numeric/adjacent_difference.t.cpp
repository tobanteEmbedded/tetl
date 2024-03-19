// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // "cppreference.com example"
    {
        etl::array a{T(2), T(4), T(6)};
        etl::adjacent_difference(a.begin(), a.end(), a.begin());
        CHECK(a[0] == 2);
        CHECK(a[1] == 2);
        CHECK(a[2] == 2);
    }

    // "cppreference.com example fibonacci"
    {
        etl::array<T, 4> a{T(1)};
        etl::adjacent_difference(a.begin(), etl::prev(a.end()), etl::next(a.begin()), etl::plus<T>{});
        CHECK(a[0] == 1);
        CHECK(a[1] == 1);
        CHECK(a[2] == 2);
        CHECK(a[3] == 3);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
