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

#include "catch2/catch_template_test_macros.hpp"

#include "etl/bit.hpp"
#include "etl/limits.hpp"

TEMPLATE_TEST_CASE("bit: bit_cast 32bit", "[bit]", etl::uint32_t, etl::int32_t,
                   float)
{
  SECTION("round trip")
  {
    auto original = TestType {42};
    auto other    = etl::bit_cast<float>(original);
    REQUIRE(etl::bit_cast<TestType>(other) == original);
  }
}

TEMPLATE_TEST_CASE("bit: bit_cast 64bit", "[bit]", etl::uint64_t, etl::int64_t,
                   double)
{
  SECTION("round trip")
  {
    auto original = TestType {42};
    auto other    = etl::bit_cast<double>(original);
    REQUIRE(etl::bit_cast<TestType>(other) == original);
  }
}

TEST_CASE("bit: endian", "[bit]")
{
  REQUIRE(etl::endian::native == etl::endian::little);
  REQUIRE(etl::endian::big != etl::endian::little);
}

TEMPLATE_TEST_CASE("bit: rotl", "[bit]", etl::uint8_t)
{
  etl::uint8_t const i = 0b00011101;

  CHECK(etl::rotl(i, 0) == 0b00011101);
  CHECK(etl::rotl(i, 1) == 0b00111010);
  CHECK(etl::rotl(i, 4) == 0b11010001);
  CHECK(etl::rotl(i, 9) == 0b00111010);
  CHECK(etl::rotl(i, -1) == 0b10001110);
}

TEMPLATE_TEST_CASE("bit: rotr", "[bit]", etl::uint8_t)
{
  TestType const i = 0b00011101;

  CHECK(etl::rotr(i, 0) == 0b00011101);
  CHECK(etl::rotr(i, 1) == 0b10001110);
  CHECK(etl::rotr(i, 9) == 0b10001110);
  CHECK(etl::rotr(i, -1) == 0b00111010);
}

TEMPLATE_TEST_CASE("bit: popcount(unsigned)", "[bit]", etl::uint8_t,
                   etl::uint16_t, etl::uint32_t, etl::uint64_t)
{
  REQUIRE(etl::popcount(TestType {1}) == 1);
  REQUIRE(etl::popcount(TestType {2}) == 1);
  REQUIRE(etl::popcount(TestType {3}) == 2);
}

TEMPLATE_TEST_CASE("bit: popcount(unsigned) constexpr", "[bit]", etl::uint8_t,
                   etl::uint16_t, etl::uint32_t, etl::uint64_t)
{
  STATIC_REQUIRE(etl::popcount(TestType {1}) == 1);
  STATIC_REQUIRE(etl::popcount(TestType {2}) == 1);
  STATIC_REQUIRE(etl::popcount(TestType {3}) == 2);
}

TEST_CASE("bit: popcount(uint16)", "[bit]")
{
  REQUIRE(etl::popcount(uint16_t {0xFFFF}) == 16);
}

TEST_CASE("bit: popcount(uint32)", "[bit]")
{
  REQUIRE(etl::popcount(uint32_t {0xFFFFFFFF}) == 32);
}

TEST_CASE("bit: popcount(uint64)", "[bit]")
{
  REQUIRE(etl::popcount(uint64_t {0xFFFFFFFFFFFFFFFF}) == 64);
}

TEMPLATE_TEST_CASE("bit: has_single_bit", "[bit]", etl::uint8_t, etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)
{
  REQUIRE(etl::has_single_bit(TestType {1 << 0}));
  REQUIRE(etl::has_single_bit(TestType {1 << 1}));
  REQUIRE(etl::has_single_bit(TestType {1 << 2}));
  REQUIRE(etl::has_single_bit(TestType {1 << 3}));
  REQUIRE(etl::has_single_bit(TestType {1 << 4}));

  REQUIRE_FALSE(etl::has_single_bit(TestType {0}));
  REQUIRE_FALSE(etl::has_single_bit(TestType {3}));
  REQUIRE_FALSE(etl::has_single_bit(TestType {3 << 4}));
}

TEST_CASE("bit: bit_ceil", "[bit]")
{
  REQUIRE(etl::bit_ceil(0b00000000U) == 0b00000001U);
  REQUIRE(etl::bit_ceil(0b00000001U) == 0b00000001U);
  REQUIRE(etl::bit_ceil(0b00000010U) == 0b00000010U);
  REQUIRE(etl::bit_ceil(0b00000011U) == 0b00000100U);
  REQUIRE(etl::bit_ceil(0b00000100U) == 0b00000100U);
  REQUIRE(etl::bit_ceil(0b00000101U) == 0b00001000U);
  REQUIRE(etl::bit_ceil(0b00000110U) == 0b00001000U);
  REQUIRE(etl::bit_ceil(0b00000111U) == 0b00001000U);
  REQUIRE(etl::bit_ceil(0b00001000U) == 0b00001000U);
  REQUIRE(etl::bit_ceil(0b00001001U) == 0b00010000U);
}

TEST_CASE("bit: bit_floor", "[bit]")
{
  REQUIRE(etl::bit_floor(0b00000000UL) == 0b00000000UL);
  REQUIRE(etl::bit_floor(0b00000001UL) == 0b00000001UL);
  REQUIRE(etl::bit_floor(0b00000010UL) == 0b00000010UL);
  REQUIRE(etl::bit_floor(0b00000011UL) == 0b00000010UL);
  REQUIRE(etl::bit_floor(0b00000100UL) == 0b00000100UL);
  REQUIRE(etl::bit_floor(0b00000101UL) == 0b00000100UL);
  REQUIRE(etl::bit_floor(0b00000110UL) == 0b00000100UL);
  REQUIRE(etl::bit_floor(0b00000111UL) == 0b00000100UL);
  REQUIRE(etl::bit_floor(0b00001000UL) == 0b00001000UL);
  REQUIRE(etl::bit_floor(0b00001001UL) == 0b00001000UL);
}

TEMPLATE_TEST_CASE("bit: countl_zero", "[bit]", etl::uint8_t, etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)
{
  REQUIRE(etl::countl_zero(TestType {0})
          == etl::numeric_limits<TestType>::digits);

  REQUIRE(etl::countl_zero(etl::uint8_t {0b1111'1111}) == 0);
  REQUIRE(etl::countl_zero(etl::uint8_t {0b0111'1111}) == 1);
  REQUIRE(etl::countl_zero(etl::uint8_t {0b0011'1111}) == 2);
  REQUIRE(etl::countl_zero(etl::uint8_t {0b0001'1111}) == 3);
  REQUIRE(etl::countl_zero(etl::uint8_t {0b0000'1111}) == 4);
  REQUIRE(etl::countl_zero(etl::uint8_t {0b0000'0000}) == 8);

  REQUIRE(etl::countl_zero(etl::uint16_t {0b1000'0000'1111'1111}) == 0);
  REQUIRE(etl::countl_zero(etl::uint16_t {0b0100'0000'1111'1111}) == 1);
  REQUIRE(etl::countl_zero(etl::uint16_t {0b0010'0000'1111'1111}) == 2);
  REQUIRE(etl::countl_zero(etl::uint16_t {0b0001'0000'1111'1111}) == 3);
  REQUIRE(etl::countl_zero(etl::uint16_t {0b0000'0000'0000'0001}) == 15);
}

TEMPLATE_TEST_CASE("bit: countl_one", "[bit]", etl::uint8_t, etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)
{
  REQUIRE(etl::countl_one(TestType {etl::numeric_limits<TestType>::max()})
          == etl::numeric_limits<TestType>::digits);

  REQUIRE(etl::countl_one(etl::uint8_t {0b0000'0000}) == 0);
  REQUIRE(etl::countl_one(etl::uint8_t {0b1111'1111}) == 8);
  REQUIRE(etl::countl_one(etl::uint8_t {0b1110'1111}) == 3);

  REQUIRE(etl::countl_one(etl::uint16_t {0b1000'0000'1111'1111}) == 1);
  REQUIRE(etl::countl_one(etl::uint16_t {0b1111'0000'1111'1111}) == 4);
}

TEMPLATE_TEST_CASE("bit: bit_width", "[bit]", etl::uint8_t, etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)
{
  REQUIRE(etl::bit_width(TestType {0}) == 0);
  REQUIRE(etl::bit_width(TestType {1}) == 1);
  REQUIRE(etl::bit_width(TestType {2}) == 2);
  REQUIRE(etl::bit_width(TestType {3}) == 2);
  REQUIRE(etl::bit_width(TestType {4}) == 3);
  REQUIRE(etl::bit_width(TestType {5}) == 3);
  REQUIRE(etl::bit_width(TestType {6}) == 3);
  REQUIRE(etl::bit_width(TestType {7}) == 3);
}
