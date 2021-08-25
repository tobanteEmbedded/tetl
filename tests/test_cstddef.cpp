/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstddef.hpp"

#include "etl/cstdint.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("cstddef: size_t", "[cstddef]")
{
    REQUIRE(sizeof(etl::size_t) == sizeof(size_t));
}

TEMPLATE_TEST_CASE("cstddef/byte: to_integer", "[cstdef][byte]", etl::uint8_t,
    etl::uint16_t, etl::uint32_t, etl::uint64_t)
{
    auto const b = etl::byte { 42 };
    REQUIRE(etl::to_integer<TestType>(b) == TestType { 42 });
}

TEMPLATE_TEST_CASE("cstddef/byte: operator <<=", "[cstdef][byte]", etl::uint8_t,
    etl::uint16_t, etl::uint32_t, etl::uint64_t)
{
    {
        auto b = etl::byte { 1 };
        b <<= 1;
        REQUIRE(etl::to_integer<TestType>(b) == TestType { 2 });
    }
    {
        auto b = etl::byte { 1 };
        b <<= 2;
        REQUIRE(etl::to_integer<TestType>(b) == TestType { 4 });
    }
    {
        auto b = etl::byte { 1 };
        b <<= 3;
        REQUIRE(etl::to_integer<TestType>(b) == TestType { 8 });
    }
}

TEMPLATE_TEST_CASE("cstddef/byte: operator >>=", "[cstdef][byte]", etl::uint8_t,
    etl::uint16_t, etl::uint32_t, etl::uint64_t)
{
    auto b = etl::byte { 2 };
    b >>= 1;
    REQUIRE(etl::to_integer<TestType>(b) == TestType { 1 });
}

TEST_CASE("cstddef/byte: operator <<", "[cstdef][byte]")
{
    auto b = etl::byte { 1 };
    REQUIRE(etl::to_integer<int>(b << 1) == 2);
    REQUIRE(etl::to_integer<int>(b << 2) == 4);
    REQUIRE(etl::to_integer<int>(b << 3) == 8);
}

TEST_CASE("cstddef/byte: operator >>", "[cstdef][byte]")
{
    auto b = etl::byte { 8 };
    REQUIRE(etl::to_integer<int>(b >> 0) == 8);
    REQUIRE(etl::to_integer<int>(b >> 1) == 4);
    REQUIRE(etl::to_integer<int>(b >> 2) == 2);
    REQUIRE(etl::to_integer<int>(b >> 3) == 1);
}

TEST_CASE("cstddef/byte: operator |", "[cstdef][byte]")
{
    REQUIRE(etl::to_integer<int>(etl::byte { 1 } | etl::byte { 0 }) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte { 1 } | etl::byte { 1 }) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte { 2 } | etl::byte { 1 }) == 3);
}

TEST_CASE("cstddef/byte: operator |=", "[cstdef][byte]")
{
    auto b1 = etl::byte { 1 };
    b1 |= etl::byte { 0 };
    REQUIRE(etl::to_integer<int>(b1) == 1);
}

TEST_CASE("cstddef/byte: operator &", "[cstdef][byte]")
{
    REQUIRE(etl::to_integer<int>(etl::byte { 1 } & etl::byte { 0 }) == 0);
    REQUIRE(etl::to_integer<int>(etl::byte { 1 } & etl::byte { 1 }) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte { 2 } & etl::byte { 1 }) == 0);
}

TEST_CASE("cstddef/byte: operator &=", "[cstdef][byte]")
{
    auto b1 = etl::byte { 1 };
    b1 &= etl::byte { 1 };
    REQUIRE(etl::to_integer<int>(b1) == 1);
}

TEST_CASE("cstddef/byte: operator ^", "[cstdef][byte]")
{
    REQUIRE(etl::to_integer<int>(etl::byte { 1 } ^ etl::byte { 0 }) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte { 1 } ^ etl::byte { 1 }) == 0);
    REQUIRE(etl::to_integer<int>(etl::byte { 2 } ^ etl::byte { 1 }) == 3);
}

TEST_CASE("cstddef/byte: operator ^=", "[cstdef][byte]")
{
    auto b1 = etl::byte { 2 };
    b1 ^= etl::byte { 1 };
    REQUIRE(etl::to_integer<int>(b1) == 3);
}