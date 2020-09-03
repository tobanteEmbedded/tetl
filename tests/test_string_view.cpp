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

#include "etl/string_view.hpp"

TEST_CASE("string_view: construct default", "[string_view]")
{
    constexpr auto sv = etl::string_view {};

    REQUIRE(sv.data() == nullptr);
    STATIC_REQUIRE(sv.data() == nullptr);

    REQUIRE(sv.size() == 0);
    STATIC_REQUIRE(sv.size() == 0);

    REQUIRE(sv.length() == 0);
    STATIC_REQUIRE(sv.length() == 0);
}

TEST_CASE("string_view: construct copy", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv1 = etl::string_view {};
        auto const sv2 = sv1;

        REQUIRE(sv2.data() == nullptr);
        REQUIRE(sv2.size() == 0);
        REQUIRE(sv2.length() == 0);
    }

    WHEN("not empty")
    {
        auto const sv1 = etl::string_view {"test"};
        auto const sv2 = sv1;

        REQUIRE_FALSE(sv2.data() == nullptr);
        REQUIRE(sv2.size() == 4);
        REQUIRE(sv2.length() == 4);
    }
}