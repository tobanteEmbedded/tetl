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

#include "taetl/bit.hpp"

#include "catch2/catch.hpp"

TEST_CASE("bit: endian", "[bit]")
{
    REQUIRE(taetl::endian::native == taetl::endian::little);
    REQUIRE(taetl::endian::big != taetl::endian::little);
}

TEST_CASE("bit: popcount constexpr", "[bit]")
{
    STATIC_REQUIRE(taetl::popcount(uint8_t {1}) == 1);
    STATIC_REQUIRE(taetl::popcount(uint8_t {2}) == 1);
    STATIC_REQUIRE(taetl::popcount(uint8_t {3}) == 2);
    STATIC_REQUIRE(taetl::popcount(uint8_t {0xFF}) == 8);
}

TEST_CASE("bit: popcount(uint8)", "[bit]")
{
    REQUIRE(taetl::popcount(uint8_t {1}) == 1);
    REQUIRE(taetl::popcount(uint8_t {2}) == 1);
    REQUIRE(taetl::popcount(uint8_t {3}) == 2);
    REQUIRE(taetl::popcount(uint8_t {0xFF}) == 8);
}

TEST_CASE("bit: popcount(uint16)", "[bit]")
{
    REQUIRE(taetl::popcount(uint16_t {1}) == 1);
    REQUIRE(taetl::popcount(uint16_t {2}) == 1);
    REQUIRE(taetl::popcount(uint16_t {3}) == 2);
    REQUIRE(taetl::popcount(uint16_t {0xFFFF}) == 16);
}

TEST_CASE("bit: popcount(uint32)", "[bit]")
{
    REQUIRE(taetl::popcount(uint32_t {1}) == 1);
    REQUIRE(taetl::popcount(uint32_t {2}) == 1);
    REQUIRE(taetl::popcount(uint32_t {3}) == 2);
    REQUIRE(taetl::popcount(uint32_t {0xFFFFFFFF}) == 32);
}

TEST_CASE("bit: popcount(uint64)", "[bit]")
{
    REQUIRE(taetl::popcount(uint64_t {1}) == 1);
    REQUIRE(taetl::popcount(uint64_t {2}) == 1);
    REQUIRE(taetl::popcount(uint64_t {3}) == 2);
    REQUIRE(taetl::popcount(uint64_t {0xFFFFFFFFFFFFFFFF}) == 64);
}
