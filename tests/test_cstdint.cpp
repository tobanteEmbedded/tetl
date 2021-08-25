/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdint.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("cstdint: int8_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::int8_t) == sizeof(int8_t));
}

TEST_CASE("cstdint: int16_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::int16_t) == sizeof(int16_t));
}

TEST_CASE("cstdint: int32_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::int32_t) == sizeof(int32_t));
}

TEST_CASE("cstdint: int64_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::int64_t) == sizeof(int64_t));
}

TEST_CASE("cstdint: uint8_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::uint8_t) == sizeof(uint8_t));
}

TEST_CASE("cstdint: uint16_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::uint16_t) == sizeof(uint16_t));
}

TEST_CASE("cstdint: uint32_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::uint32_t) == sizeof(uint32_t));
}

TEST_CASE("cstdint: uint64_t", "[cstdint]")
{
    REQUIRE(sizeof(etl::uint64_t) == sizeof(uint64_t));
}
