// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::lower_bound;
    auto greater = etl::greater<>();

    // empty range
    {
        auto const vec = etl::static_vector<T, 4>{};
        CHECK(lower_bound(begin(vec), end(vec), T(0)) == end(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(0), greater) == end(vec));
    }

    // single element
    {
        auto v = etl::static_vector<T, 4>{};
        v.push_back(T(0));
        CHECK(lower_bound(begin(v), end(v), T(0)) == begin(v));
        CHECK(lower_bound(begin(v), end(v), T(1)) == end(v));
        CHECK(lower_bound(begin(v), end(v), T(0), greater) == begin(v));
        CHECK(lower_bound(begin(v), end(v), T(1), greater) == begin(v));

        // reset
        v.clear();
        v.push_back(T(1));
        CHECK(lower_bound(begin(v), end(v), T(0)) == begin(v));
        CHECK(lower_bound(begin(v), end(v), T(1)) == begin(v));
        CHECK(lower_bound(begin(v), end(v), T(0), greater) == end(v));
        CHECK(lower_bound(begin(v), end(v), T(1), greater) == begin(v));
    }

    // multiple elements
    {
        auto const a = etl::array{T(0), T(1), T(2), T(3)};
        CHECK(lower_bound(begin(a), end(a), T(0)) == begin(a));
        CHECK(lower_bound(begin(a), end(a), T(1)) == begin(a) + 1);
        CHECK(lower_bound(begin(a), end(a), T(4)) == end(a));
        CHECK(lower_bound(begin(a), end(a), T(0), greater) == end(a));
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
