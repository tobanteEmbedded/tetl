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

#include "etl/scope_guard.hpp"

TEST_CASE("scope_guard: scope_exit", "[scope_guard]")
{
    SECTION("single")
    {
        auto counter = 0;
        {
            etl::scope_exit e {[&] { counter++; }};
        }
        REQUIRE(counter == 1);
    }

    SECTION("multiple")
    {
        auto counter = 0;
        {
            etl::scope_exit e1 {[&] { counter++; }};
            etl::scope_exit e2 {[&] { counter++; }};
            etl::scope_exit e3 {[&] { counter++; }};
        }
        REQUIRE(counter == 3);
    }

    SECTION("move")
    {
        auto counter = 0;
        {
            auto e1 = etl::scope_exit {[&] { counter++; }};
            {
                auto e2 {etl::move(e1)};
                REQUIRE(counter == 0);
            }
            REQUIRE(counter == 1);
        }
        REQUIRE(counter == 1);
    }

    SECTION("release")
    {
        auto counter = 0;
        {
            etl::scope_exit e {[&] { counter++; }};
            e.release();
        }
        REQUIRE(counter == 0);
    }
}
