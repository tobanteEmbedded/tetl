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
#include "etl/cstdlib.hpp"
#include "etl/cstring.hpp"

#include "catch2/catch_approx.hpp"
#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("cstdlib: itoa(signed,base10)", "[cstdlib]")
{
  SECTION("0")
  {
    int val         = 0;
    char buffer[12] = {};
    auto* result    = etl::itoa(val, buffer, 10);
    REQUIRE(&buffer[0] == result);
    REQUIRE(etl::strlen(result) == 1);
    REQUIRE(etl::strcmp(result, "0") == 0);
  }

  SECTION("10")
  {
    int val         = 10;
    char buffer[12] = {};
    auto* result    = etl::itoa(val, buffer, 10);
    REQUIRE(&buffer[0] == result);
    REQUIRE(etl::strlen(result) == 2);
    REQUIRE(etl::strcmp(result, "10") == 0);
  }

  SECTION("999")
  {
    int val         = 999;
    char buffer[12] = {};
    auto* result    = etl::itoa(val, buffer, 10);
    REQUIRE(&buffer[0] == result);
    REQUIRE(etl::strlen(result) == 3);
    REQUIRE(etl::strcmp(result, "999") == 0);
  }

  SECTION("1002")
  {
    int val         = 1002;
    char buffer[12] = {};
    auto* result    = etl::itoa(val, buffer, 10);
    REQUIRE(&buffer[0] == result);
    REQUIRE(etl::strlen(result) == 4);
    REQUIRE(etl::strcmp(result, "1002") == 0);
  }

  SECTION("44444")
  {
    int val         = 44444;
    char buffer[12] = {};
    auto* result    = etl::itoa(val, buffer, 10);
    REQUIRE(&buffer[0] == result);
    REQUIRE(etl::strlen(result) == 5);
    REQUIRE(etl::strcmp(result, "44444") == 0);
  }

  SECTION("123456789")
  {
    int val         = 123456789;
    char buffer[12] = {};
    auto* result    = etl::itoa(val, buffer, 10);
    REQUIRE(&buffer[0] == result);
    REQUIRE(etl::strlen(result) == 9);
    REQUIRE(etl::strcmp(result, "123456789") == 0);
  }
}

TEST_CASE("cstdlib: atoi", "[cstdlib]")
{
  SECTION("positive")
  {
    REQUIRE(etl::atoi("0") == 0);
    REQUIRE(etl::atoi("10") == 10);
    REQUIRE(etl::atoi("100") == 100);
    REQUIRE(etl::atoi("1000") == 1000);
    REQUIRE(etl::atoi("10000") == 10000);
    REQUIRE(etl::atoi("999999") == 999999);
    REQUIRE(etl::atoi("9999999") == 9999999);
  }
}

TEST_CASE("cstdlib: atol", "[cstdlib]")
{
  SECTION("positive")
  {
    REQUIRE(etl::atol("0") == 0L);
    REQUIRE(etl::atol("10") == 10L);
    REQUIRE(etl::atol("100") == 100L);
    REQUIRE(etl::atol("1000") == 1000L);
    REQUIRE(etl::atol("10000") == 10000L);
    REQUIRE(etl::atol("999999") == 999999L);
    REQUIRE(etl::atol("9999999") == 9999999L);
  }
}

TEST_CASE("cstdlib: atoll", "[cstdlib]")
{
  SECTION("positive")
  {
    REQUIRE(etl::atoll("0") == 0LL);
    REQUIRE(etl::atoll("10") == 10LL);
    REQUIRE(etl::atoll("100") == 100LL);
    REQUIRE(etl::atoll("1000") == 1000LL);
    REQUIRE(etl::atoll("10000") == 10000LL);
    REQUIRE(etl::atoll("999999") == 999999LL);
    REQUIRE(etl::atoll("9999999") == 9999999LL);
  }
}

TEST_CASE("cstdlib: strtof", "[cstdlib]")
{
  SECTION("positive")
  {
    REQUIRE(etl::strtof("0") == Catch::Approx(0.0F));
    REQUIRE(etl::strtof("10") == Catch::Approx(10.0F));
    REQUIRE(etl::strtof("100.0") == Catch::Approx(100.0F));
    REQUIRE(etl::strtof("1000.000") == Catch::Approx(1000.0F));
    REQUIRE(etl::strtof("10000") == Catch::Approx(10000.0F));
    REQUIRE(etl::strtof("999999.0") == Catch::Approx(999999.0F));
    REQUIRE(etl::strtof("9999999") == Catch::Approx(9999999.0F));
  }
}

TEST_CASE("cstdlib: strtod", "[cstdlib]")
{
  SECTION("positive")
  {
    REQUIRE(etl::strtod("0") == Catch::Approx(0.0));
    REQUIRE(etl::strtod("10") == Catch::Approx(10.0));
    REQUIRE(etl::strtod("100.0") == Catch::Approx(100.0));
    REQUIRE(etl::strtod("1000.000") == Catch::Approx(1000.0));
    REQUIRE(etl::strtod("10000") == Catch::Approx(10000.0));
    REQUIRE(etl::strtod("999999.0") == Catch::Approx(999999.0));
    REQUIRE(etl::strtod("9999999") == Catch::Approx(9999999.0));
  }
}

TEST_CASE("cstdlib: strtold", "[cstdlib]")
{
  SECTION("positive")
  {
    REQUIRE(etl::strtold("0") == Catch::Approx(0.0));
    REQUIRE(etl::strtold("10") == Catch::Approx(10.0));
    REQUIRE(etl::strtold("100.0") == Catch::Approx(100.0));
    REQUIRE(etl::strtold("1000.000") == Catch::Approx(1000.0));
    REQUIRE(etl::strtold("10000") == Catch::Approx(10000.0));
    REQUIRE(etl::strtold("999999.0") == Catch::Approx(999999.0));
    REQUIRE(etl::strtold("9999999") == Catch::Approx(9999999.0));
  }
}

TEST_CASE("cstdlib: div", "[cstdlib]")
{
  SECTION("int")
  {
    REQUIRE(etl::div(2, 1).quot == 2);
    REQUIRE(etl::div(2, 1).rem == 0);

    REQUIRE(etl::div(1, 2).quot == 0);
    REQUIRE(etl::div(1, 2).rem == 1);
  }

  SECTION("long")
  {
    REQUIRE(etl::div(2L, 1L).quot == 2L);
    REQUIRE(etl::div(2L, 1L).rem == 0L);

    REQUIRE(etl::div(1L, 2L).quot == 0L);
    REQUIRE(etl::div(1L, 2L).rem == 1L);

    REQUIRE(etl::ldiv(2LL, 1LL).quot == 2LL);
    REQUIRE(etl::ldiv(2LL, 1LL).rem == 0LL);

    REQUIRE(etl::ldiv(1LL, 2LL).quot == 0LL);
    REQUIRE(etl::ldiv(1LL, 2LL).rem == 1LL);
  }

  SECTION("long long")
  {
    REQUIRE(etl::div(2LL, 1LL).quot == 2LL);
    REQUIRE(etl::div(2LL, 1LL).rem == 0LL);

    REQUIRE(etl::div(1LL, 2LL).quot == 0LL);
    REQUIRE(etl::div(1LL, 2LL).rem == 1LL);

    REQUIRE(etl::lldiv(2LL, 1LL).quot == 2LL);
    REQUIRE(etl::lldiv(2LL, 1LL).rem == 0LL);

    REQUIRE(etl::lldiv(1LL, 2LL).quot == 0LL);
    REQUIRE(etl::lldiv(1LL, 2LL).rem == 1LL);
  }
}