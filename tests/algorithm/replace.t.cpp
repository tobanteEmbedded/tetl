// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // empty range
    {
        auto data = etl::static_vector<T, 4>{};
        etl::replace(begin(data), end(data), T(0), T(1));
        CHECK(data.empty());
    }

    // range
    {
        auto data = etl::array{T(1), T(2), T(2), T(3)};
        etl::replace(begin(data), end(data), T(2), T(1));
        CHECK(etl::count(begin(data), end(data), T(2)) == 0);
        CHECK(etl::count(begin(data), end(data), T(1)) == 3);
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
