// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::lcm(T{10}, T{5}) == T{10});
    CHECK(etl::lcm(T{4}, T{6}) == T{12});
    CHECK(etl::lcm(T{6}, T{4}) == T{12});
    CHECK(etl::lcm(T{30}, T{120}) == T{120});
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
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
