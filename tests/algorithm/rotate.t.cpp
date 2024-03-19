// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto data = etl::array{T(1), T(2), T(3), T(4)};
        CHECK(data[0] == 1);
        etl::rotate(begin(data), begin(data) + 1, end(data));
        CHECK(data[0] == 2);
    }

    // empty range
    {
        etl::static_vector<T, 5> s{};
        etl::static_vector<T, 5> d{};
        auto* pivot = etl::find(begin(s), end(s), T(3));

        etl::rotate_copy(s.begin(), pivot, s.end(), etl::back_inserter(d));
        CHECK(d.empty());
        CHECK(d.size() == s.size());
    }

    // cppreference example
    {
        auto s      = etl::array{T(1), T(2), T(3), T(4), T(5)};
        auto* pivot = etl::find(begin(s), end(s), T(3));

        // From 1, 2, 3, 4, 5 to 3, 4, 5, 1, 2
        etl::static_vector<T, 5> d{};
        etl::rotate_copy(s.begin(), pivot, s.end(), etl::back_inserter(d));
        CHECK(d.size() == s.size());
        CHECK(d[0] == T(3));
        CHECK(d[1] == T(4));
        CHECK(d[2] == T(5));
        CHECK(d[3] == T(1));
        CHECK(d[4] == T(2));
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
