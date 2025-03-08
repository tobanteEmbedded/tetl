// SPDX-License-Identifier: BSL-1.0

#include <etl/experimental/net/byte_order.hpp> // for hton, ntoh, net

#include <etl/cstdint.hpp> // for int8_t, uint16_t, uin...

#include "testing/testing.hpp"

static constexpr auto test_all() -> bool
{
    using namespace etl::experimental::net;

    CHECK(ntoh(hton(etl::int8_t{0})) == 0);
    CHECK(ntoh(hton(etl::int8_t{1})) == 1);
    CHECK(ntoh(hton(etl::int8_t{42})) == 42);

    CHECK(ntoh(hton(etl::uint8_t{0})) == 0);
    CHECK(ntoh(hton(etl::uint8_t{1})) == 1);
    CHECK(ntoh(hton(etl::uint8_t{42})) == 42);

    CHECK(ntoh(hton(etl::uint16_t{0})) == 0);
    CHECK(ntoh(hton(etl::uint16_t{1})) == 1);
    CHECK(ntoh(hton(etl::uint16_t{42})) == 42);

    CHECK(ntoh(hton(etl::uint32_t{0})) == 0);
    CHECK(ntoh(hton(etl::uint32_t{1})) == 1);
    CHECK(ntoh(hton(etl::uint32_t{42})) == 42);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
