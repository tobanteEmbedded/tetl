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
#include "taetl/ratio.hpp"
#include "taetl/warning.hpp"

#include "catch2/catch.hpp"

TEST_CASE("ratio: construct", "[ratio]")
{
    taetl::ratio<1, 1> r {};
    taetl::ignore_unused(r);
}

TEST_CASE("ratio: num/den", "[ratio]")
{
    STATIC_REQUIRE(taetl::ratio<1, 2>::type::num == 1);
    STATIC_REQUIRE(taetl::ratio<1, 2>::type::den == 2);
    STATIC_REQUIRE(taetl::ratio<3, 6>::type::num == 1);
    STATIC_REQUIRE(taetl::ratio<3, 6>::type::den == 2);
    STATIC_REQUIRE(taetl::ratio<2, 8>::type::num == 1);
    STATIC_REQUIRE(taetl::ratio<2, 8>::type::den == 4);
}

TEST_CASE("ratio: ratio_add", "[ratio]")
{
    WHEN("1/4 + 1/6 = 5/12")
    {
        using one_fourth = taetl::ratio<1, 4>;
        using one_sixth  = taetl::ratio<1, 6>;
        using sum        = taetl::ratio_add<one_fourth, one_sixth>;
        STATIC_REQUIRE(sum::num == 5);
        STATIC_REQUIRE(sum::den == 12);
    }

    WHEN("2/3 + 1/6 = 5/6")
    {
        using two_third = taetl::ratio<2, 3>;
        using one_sixth = taetl::ratio<1, 6>;
        using sum       = taetl::ratio_add<two_third, one_sixth>;
        STATIC_REQUIRE(sum::num == 5);
        STATIC_REQUIRE(sum::den == 6);
    }
}

TEST_CASE("ratio: ratio_subtract", "[ratio]")
{
    WHEN("1/4 - 1/6 = 1/12")
    {
        using one_fourth = taetl::ratio<1, 4>;
        using one_sixth  = taetl::ratio<1, 6>;
        using sum        = taetl::ratio_subtract<one_fourth, one_sixth>;
        STATIC_REQUIRE(sum::num == 1);
        STATIC_REQUIRE(sum::den == 12);
    }

    WHEN("2/3 - 1/6 = 3/6 = 1/2")
    {
        using two_third = taetl::ratio<2, 3>;
        using one_sixth = taetl::ratio<1, 6>;
        using sum       = taetl::ratio_subtract<two_third, one_sixth>;
        STATIC_REQUIRE(sum::num == 1);
        STATIC_REQUIRE(sum::den == 2);
    }
}