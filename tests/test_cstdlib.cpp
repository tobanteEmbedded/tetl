// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#include "etl/cstdlib.hpp"

#include "etl/algorithm.hpp"
#include "etl/cstring.hpp"
#include "etl/string_view.hpp"

#include "catch2/catch_approx.hpp"
#include "catch2/catch_template_test_macros.hpp"
#include "catch2/generators/catch_generators.hpp"

using namespace etl::string_view_literals;
using namespace Catch::Generators;

TEST_CASE("cstdlib: itoa(signed,base10)", "[cstdlib]")
{
    auto [input, expected] = GENERATE(table<int, etl::string_view>({
        { 0, "0"_sv },
        { 10, "10"_sv },
        { 99, "99"_sv },
        { 143, "143"_sv },
        { 999, "999"_sv },
        { 1111, "1111"_sv },
        { 123456789, "123456789"_sv },
    }));

    char buffer[16] = {};
    auto* result    = etl::itoa(input, buffer, 10);
    REQUIRE(&buffer[0] == result);
    REQUIRE(etl::string_view { buffer } == expected);
}

TEST_CASE("cstdlib: atoi", "[cstdlib]")
{
    auto [input, expected] = GENERATE(table<char const*, int>({
        { "0", 0 },
        { "10", 10 },
        { "99", 99 },
        { "143", 143 },
        { "999", 999 },
        { "1111", 1111 },
        { "99999", 99999 },
        { "999999", 999999 },
        { "123456789", 123456789 },
    }));

    REQUIRE(etl::atoi(input) == expected);
}

TEST_CASE("cstdlib: atol", "[cstdlib]")
{
    auto [input, expected] = GENERATE(table<char const*, long>({
        { "0", 0 },
        { "10", 10 },
        { "99", 99 },
        { "143", 143 },
        { "999", 999 },
        { "1111", 1111 },
        { "99999", 99999 },
        { "999999", 999999 },
        { "123456789", 123456789 },
    }));

    REQUIRE(etl::atol(input) == expected);
}

TEST_CASE("cstdlib: atoll", "[cstdlib]")
{
    auto [input, expected] = GENERATE(table<char const*, long long>({
        { "0", 0 },
        { "10", 10 },
        { "99", 99 },
        { "143", 143 },
        { "999", 999 },
        { "1111", 1111 },
        { "99999", 99999 },
        { "999999", 999999 },
        { "123456789", 123456789 },
    }));

    REQUIRE(etl::atoll(input) == expected);
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