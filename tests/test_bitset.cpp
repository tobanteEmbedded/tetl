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

#include "taetl/bitset.hpp"

#include "catch2/catch.hpp"

TEST_CASE("bitset: construct default", "[bit]")
{
    auto set = taetl::bitset<10> {};
    REQUIRE_FALSE(set.test(0));
}

TEST_CASE("bitset: set", "[bit]")
{
    WHEN("b is mutable")
    {
        auto b = taetl::bitset<10> {};
        b.set(100);
        REQUIRE(b.test(100));
    }

    WHEN("b is constexpr")
    {
        auto b = []() {
            auto b = taetl::bitset<10> {};
            b.set(100);
            return b;
        }();
        REQUIRE(b[100]);
    }
}

TEST_CASE("bitset: reset", "[bit]")
{
    WHEN("b is mutable")
    {
        auto b = taetl::bitset<10> {};
        b.set(100);
        REQUIRE(b.test(100));
        b.reset(100);
        REQUIRE_FALSE(b.test(100));
    }

    WHEN("b is constexpr")
    {
        auto b = []() {
            auto b = taetl::bitset<10> {};
            b.set(100);
            b.reset(100);
            return b;
        }();
        REQUIRE_FALSE(b[100]);
    }
}

TEST_CASE("bitset: flip", "[bit]")
{
    WHEN("b is mutable")
    {
        auto b = taetl::bitset<10> {};
        b.set(100);
        REQUIRE(b.test(100));
        b.flip(100);
        REQUIRE_FALSE(b.test(100));
    }

    WHEN("b is constexpr")
    {
        auto b = []() {
            auto b = taetl::bitset<10> {};
            b.set(100);
            REQUIRE(b.test(100));
            b.flip(100);
            return b;
        }();
        REQUIRE_FALSE(b[100]);
    }
}