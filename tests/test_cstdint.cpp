/*
Copyright (c) Tobias Hienzsch. All rights reserved.

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

#include "catch2/catch_template_test_macros.hpp"

#include "etl/cstdint.hpp"

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
