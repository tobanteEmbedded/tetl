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

#include "etl/bitset.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE_SIG("bitset: construct default", "[bit]", ((size_t Num), Num), 8, 15,
                       16, 31, 32, 63, 64, 127, 128)
{
    auto set = etl::bitset<Num> {};
    REQUIRE_FALSE(set.test(0));
}

TEMPLATE_TEST_CASE_SIG("bitset: construct(unsigned long long)", "[bit]",
                       ((size_t Num), Num), 8, 15, 16, 31, 32, 63, 64, 127, 128)
{
    unsigned long long val = 0;
    auto set               = etl::bitset<Num> {val};
    REQUIRE_FALSE(set[0]);
}

TEMPLATE_TEST_CASE_SIG("bitset: set()", "[bit]", ((size_t Num), Num), 8, 15, 16, 31, 32,
                       63, 64, 127, 128)
{
    WHEN("b is mutable")
    {
        auto b = etl::bitset<Num> {};
        b.set();
        REQUIRE(b.test(1));
        REQUIRE(b[2]);
    }

    WHEN("b is constexpr")
    {
        constexpr auto b = []() {
            auto ret = etl::bitset<Num> {};
            ret.set();
            return ret;
        }();
        STATIC_REQUIRE(b[1]);
        STATIC_REQUIRE(b[2]);
    }
}

TEMPLATE_TEST_CASE_SIG("bitset: set(pos)", "[bit]", ((size_t Num), Num), 8, 15, 16, 31,
                       32, 63, 64, 127, 128)
{
    WHEN("b is mutable")
    {
        auto b = etl::bitset<Num> {};
        b.set(1);
        REQUIRE(b.test(1));
    }

    WHEN("b is constexpr")
    {
        constexpr auto b = []() {
            auto ret = etl::bitset<Num> {};
            ret.set(1);
            return ret;
        }();
        STATIC_REQUIRE(b[1]);
    }
}
