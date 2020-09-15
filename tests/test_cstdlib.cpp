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
#include "etl/cstdlib.hpp"
#include "etl/cstring.hpp"

#include "catch2/catch.hpp"

#include <cstring>

TEST_CASE("cstdlib: iota(signed,base10)", "[cstdlib]")
{
    SECTION("0")
    {
        int val         = 0;
        char buffer[12] = {};
        auto* result    = etl::iota(val, buffer, 10);
        REQUIRE(&buffer[0] == result);
        REQUIRE(etl::strlen(buffer) == 1);
        REQUIRE(std::strcmp(buffer, "0") == 0);
    }

    SECTION("10")
    {
        int val         = 10;
        char buffer[12] = {};
        auto* result    = etl::iota(val, buffer, 10);
        REQUIRE(&buffer[0] == result);
        REQUIRE(etl::strlen(buffer) == 2);
        REQUIRE(std::strcmp(buffer, "10") == 0);
    }

    SECTION("999")
    {
        int val         = 999;
        char buffer[12] = {};
        auto* result    = etl::iota(val, buffer, 10);
        REQUIRE(&buffer[0] == result);
        REQUIRE(etl::strlen(buffer) == 3);
        REQUIRE(std::strcmp(buffer, "999") == 0);
    }

    SECTION("1002")
    {
        int val         = 1002;
        char buffer[12] = {};
        auto* result    = etl::iota(val, buffer, 10);
        REQUIRE(&buffer[0] == result);
        REQUIRE(etl::strlen(buffer) == 4);
        REQUIRE(std::strcmp(buffer, "1002") == 0);
    }

    SECTION("44444")
    {
        int val         = 44444;
        char buffer[12] = {};
        auto* result    = etl::iota(val, buffer, 10);
        REQUIRE(&buffer[0] == result);
        REQUIRE(etl::strlen(buffer) == 5);
        REQUIRE(std::strcmp(buffer, "44444") == 0);
    }

    SECTION("123456789")
    {
        int val         = 123456789;
        char buffer[12] = {};
        auto* result    = etl::iota(val, buffer, 10);
        REQUIRE(&buffer[0] == result);
        REQUIRE(etl::strlen(buffer) == 9);
        REQUIRE(std::strcmp(buffer, "123456789") == 0);
    }
}

TEST_CASE("cstdlib: atol", "[cstdlib]")
{
    SECTION("positive")
    {
        REQUIRE(etl::atol("0") == long {0});
        REQUIRE(etl::atol("10") == long {10});
        REQUIRE(etl::atol("100") == long {100});
        REQUIRE(etl::atol("1000") == long {1000});
        REQUIRE(etl::atol("10000") == long {10000});
        REQUIRE(etl::atol("999999") == long {999999});
        REQUIRE(etl::atol("9999999") == long {9999999});
    }
}