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

#include "etl/string.hpp"

TEMPLATE_TEST_CASE("string: constexpr", "[string]", etl::string<8>, etl::string<12>,
                   etl::small_string)
{
    constexpr TestType str1 {};

    STATIC_REQUIRE(str1.empty() == true);
    STATIC_REQUIRE(str1.capacity() == str1.max_size());
    STATIC_REQUIRE(str1.size() == 0);
    STATIC_REQUIRE(str1.length() == 0);

    constexpr auto str2 = []() {
        TestType str {};
        // APPEND 4 CHARACTERS
        const char* cptr = "C-string";
        str.append(cptr, 4);
        return str;
    }();

    STATIC_REQUIRE(str2.empty() == false);
    STATIC_REQUIRE(str2.capacity() == str1.max_size());
    STATIC_REQUIRE(str2.size() == 4);
    STATIC_REQUIRE(str2.length() == 4);
    STATIC_REQUIRE(str2[0] == 'C');
    STATIC_REQUIRE(str2[1] == '-');
    STATIC_REQUIRE(str2[2] == 's');
    STATIC_REQUIRE(str2[3] == 't');
    STATIC_REQUIRE(str2[4] == 0);
    STATIC_REQUIRE(str2.at(4) == 0);
}