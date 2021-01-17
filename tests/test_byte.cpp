/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#include "catch2/catch.hpp"

#include "etl/byte.hpp"

TEMPLATE_TEST_CASE("byte: to_integer", "[byte]", etl::uint8_t, etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)
{
    auto const b = etl::byte {42};
    REQUIRE(etl::to_integer<TestType>(b) == TestType {42});
}

TEMPLATE_TEST_CASE("byte: operator <<=", "[byte]", etl::uint8_t, etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)
{
    {
        auto b = etl::byte {1};
        b <<= 1;
        REQUIRE(etl::to_integer<TestType>(b) == TestType {2});
    }
    {
        auto b = etl::byte {1};
        b <<= 2;
        REQUIRE(etl::to_integer<TestType>(b) == TestType {4});
    }
    {
        auto b = etl::byte {1};
        b <<= 3;
        REQUIRE(etl::to_integer<TestType>(b) == TestType {8});
    }
}

TEMPLATE_TEST_CASE("byte: operator >>=", "[byte]", etl::uint8_t, etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)
{
    auto b = etl::byte {2};
    b >>= 1;
    REQUIRE(etl::to_integer<TestType>(b) == TestType {1});
}

TEST_CASE("byte: operator <<", "[byte]")
{
    auto b = etl::byte {1};
    REQUIRE(etl::to_integer<int>(b << 1) == 2);
    REQUIRE(etl::to_integer<int>(b << 2) == 4);
    REQUIRE(etl::to_integer<int>(b << 3) == 8);
}

TEST_CASE("byte: operator >>", "[byte]")
{
    auto b = etl::byte {8};
    REQUIRE(etl::to_integer<int>(b >> 0) == 8);
    REQUIRE(etl::to_integer<int>(b >> 1) == 4);
    REQUIRE(etl::to_integer<int>(b >> 2) == 2);
    REQUIRE(etl::to_integer<int>(b >> 3) == 1);
}

TEST_CASE("byte: operator |", "[byte]")
{
    REQUIRE(etl::to_integer<int>(etl::byte {1} | etl::byte {0}) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte {1} | etl::byte {1}) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte {2} | etl::byte {1}) == 3);
}

TEST_CASE("byte: operator |=", "[byte]")
{
    auto b1 = etl::byte {1};
    b1 |= etl::byte {0};
    REQUIRE(etl::to_integer<int>(b1) == 1);
}

TEST_CASE("byte: operator &", "[byte]")
{
    REQUIRE(etl::to_integer<int>(etl::byte {1} & etl::byte {0}) == 0);
    REQUIRE(etl::to_integer<int>(etl::byte {1} & etl::byte {1}) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte {2} & etl::byte {1}) == 0);
}

TEST_CASE("byte: operator &=", "[byte]")
{
    auto b1 = etl::byte {1};
    b1 &= etl::byte {1};
    REQUIRE(etl::to_integer<int>(b1) == 1);
}

TEST_CASE("byte: operator ^", "[byte]")
{
    REQUIRE(etl::to_integer<int>(etl::byte {1} ^ etl::byte {0}) == 1);
    REQUIRE(etl::to_integer<int>(etl::byte {1} ^ etl::byte {1}) == 0);
    REQUIRE(etl::to_integer<int>(etl::byte {2} ^ etl::byte {1}) == 3);
}

TEST_CASE("byte: operator ^=", "[byte]")
{
    auto b1 = etl::byte {2};
    b1 ^= etl::byte {1};
    REQUIRE(etl::to_integer<int>(b1) == 3);
}