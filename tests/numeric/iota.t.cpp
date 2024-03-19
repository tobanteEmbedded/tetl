// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // from 0
    {
        auto data = etl::array<T, 4>{};
        etl::iota(begin(data), end(data), T{0});
        CHECK(data[0] == 0);
        CHECK(data[1] == 1);
        CHECK(data[2] == 2);
        CHECK(data[3] == 3);
    }

    // from 42
    {
        auto data = etl::array<T, 4>{};
        etl::iota(begin(data), end(data), T{42});
        CHECK(data[0] == 42);
        CHECK(data[1] == 43);
        CHECK(data[2] == 44);
        CHECK(data[3] == 45);
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
