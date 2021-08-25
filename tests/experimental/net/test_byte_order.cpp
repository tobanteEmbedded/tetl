/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "catch2/catch_template_test_macros.hpp"

#include "etl/cstdint.hpp"                     // for int8_t, uint16_t, uin...
#include "etl/experimental/net/byte_order.hpp" // for hton, ntoh, net

TEST_CASE("experimental/net: ntoh/hton etl::int8_t", "[experimental][net]")
{
    using namespace etl::experimental::net;
    REQUIRE(ntoh(hton(etl::int8_t { 0 })) == 0);
    REQUIRE(ntoh(hton(etl::int8_t { 1 })) == 1);
    REQUIRE(ntoh(hton(etl::int8_t { 42 })) == 42);
}

TEST_CASE("experimental/net: ntoh/hton etl::uint8_t", "[experimental][net]")
{
    using namespace etl::experimental::net;
    REQUIRE(ntoh(hton(etl::uint8_t { 0 })) == 0);
    REQUIRE(ntoh(hton(etl::uint8_t { 1 })) == 1);
    REQUIRE(ntoh(hton(etl::uint8_t { 42 })) == 42);
}

TEST_CASE("experimental/net: ntoh/hton etl::uint16_t", "[experimental][net]")
{
    using namespace etl::experimental::net;
    REQUIRE(ntoh(hton(etl::uint16_t { 0 })) == 0);
    REQUIRE(ntoh(hton(etl::uint16_t { 1 })) == 1);
    REQUIRE(ntoh(hton(etl::uint16_t { 42 })) == 42);
}

TEST_CASE("experimental/net: ntoh/hton etl::uint32_t", "[experimental][net]")
{
    using namespace etl::experimental::net;
    REQUIRE(ntoh(hton(etl::uint32_t { 0 })) == 0);
    REQUIRE(ntoh(hton(etl::uint32_t { 1 })) == 1);
    REQUIRE(ntoh(hton(etl::uint32_t { 42 })) == 42);
}