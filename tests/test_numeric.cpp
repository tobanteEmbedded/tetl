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

// TAETL
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "catch2/catch.hpp"

TEST_CASE("numeric: abs", "[numeric]")
{
    REQUIRE(etl::abs(10) == 10);
    REQUIRE(etl::abs(0) == 0);
    REQUIRE(etl::abs(-10) == 10);
    REQUIRE(etl::abs(1.0) == 1.0);
    REQUIRE(etl::abs(-1.0) == 1.0);
}

TEST_CASE("numeric: accumulate", "[numeric]")
{
    etl::make::vector<double, 16> vec;
    vec.push_back(1.0);
    vec.push_back(2.0);
    vec.push_back(3.0);
    vec.push_back(4.0);

    // accumulate
    REQUIRE(etl::accumulate(vec.begin(), vec.end(), 0.0) == 10.0);

    // accumulate binary function op
    auto func = [](double a, double b) { return a + (b * 2); };
    REQUIRE(etl::accumulate(vec.begin(), vec.end(), 0.0, func) == 20.0);
}

TEST_CASE("numeric: gcd", "[numeric]")
{
    REQUIRE(etl::gcd(5, 10) == 5);
    REQUIRE(etl::gcd(10, 5) == 5);
    STATIC_REQUIRE(etl::gcd(10, 5) == 5);

    REQUIRE(etl::gcd(30, 105) == 15);
    REQUIRE(etl::gcd(105, 30) == 15);
    STATIC_REQUIRE(etl::gcd(105, 30) == 15);
}

TEST_CASE("numeric: midpoint", "[numeric]")
{
    SECTION("short")
    {
        constexpr signed short a = -3;
        constexpr signed short b = -4;
        REQUIRE(etl::midpoint(a, b) == -3);
        REQUIRE(etl::midpoint(b, a) == -4);
        STATIC_REQUIRE(etl::midpoint(a, b) == -3);
        STATIC_REQUIRE(etl::midpoint(b, a) == -4);
    }

    SECTION("char")
    {
        constexpr signed char a = -3;
        constexpr signed char b = 4;
        REQUIRE(etl::midpoint(a, b) == 0);
        REQUIRE(etl::midpoint(b, a) == 1);
        STATIC_REQUIRE(etl::midpoint(a, b) == 0);
        STATIC_REQUIRE(etl::midpoint(b, a) == 1);
    }

    SECTION("int")
    {
        constexpr signed int a = 1;
        constexpr signed int b = 4;
        REQUIRE(etl::midpoint(a, b) == 2);
        REQUIRE(etl::midpoint(b, a) == 3);
        STATIC_REQUIRE(etl::midpoint(a, b) == 2);
        STATIC_REQUIRE(etl::midpoint(b, a) == 3);
    }
}
