// SPDX-License-Identifier: BSL-1.0

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    CHECK(sizeof(etl::int8_t) == 1);
    CHECK(sizeof(etl::int16_t) == 2);
    CHECK(sizeof(etl::int32_t) == 4);
    CHECK(sizeof(etl::int64_t) == 8);
    CHECK(sizeof(etl::uint8_t) == 1);
    CHECK(sizeof(etl::uint16_t) == 2);
    CHECK(sizeof(etl::uint32_t) == 4);
    CHECK(sizeof(etl::uint64_t) == 8);
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
