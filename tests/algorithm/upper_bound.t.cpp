// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto greater = etl::greater<>();

    // empty range
    {
        auto const d = etl::static_vector<T, 4>{};
        CHECK(etl::upper_bound(begin(d), end(d), T(0)) == end(d));
        CHECK(etl::upper_bound(begin(d), end(d), T(0), greater) == end(d));
    }

    // single element
    {
        auto d = etl::static_vector<T, 4>{};
        d.push_back(T(0));
        CHECK(etl::upper_bound(begin(d), end(d), T(0)) == end(d));
        CHECK(etl::upper_bound(begin(d), end(d), T(1)) == end(d));
        CHECK(etl::upper_bound(begin(d), end(d), T(1), greater) == begin(d));
    }

    // multiple elements
    {
        auto const d = etl::array{T(0), T(1), T(2), T(3)};
        CHECK(etl::upper_bound(begin(d), end(d), T(0)) == begin(d) + 1);
        CHECK(etl::upper_bound(begin(d), end(d), T(1)) == begin(d) + 2);
        CHECK(etl::upper_bound(begin(d), end(d), T(5)) == end(d));
    }
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
