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

#include "etl/limits.hpp"

#include "catch2/catch.hpp"

TEST_CASE("limits: float_round_style", "[limits]")
{
    REQUIRE(etl::float_round_style::round_indeterminate == -1);
    REQUIRE(etl::float_round_style::round_toward_zero == 0);
    REQUIRE(etl::float_round_style::round_to_nearest == 1);
    REQUIRE(etl::float_round_style::round_toward_infinity == 2);
    REQUIRE(etl::float_round_style::round_toward_neg_infinity == 3);
}

TEST_CASE("limits: numeric_limits<T>", "[limits]")
{
    struct S
    {
        int i = 42;
    };
    STATIC_REQUIRE(etl::numeric_limits<S>::is_specialized == false);
    STATIC_REQUIRE(etl::numeric_limits<S>::is_signed == false);
    STATIC_REQUIRE(etl::numeric_limits<S>::is_integer == false);
    STATIC_REQUIRE(etl::numeric_limits<S>::is_bounded == false);

    STATIC_REQUIRE(etl::numeric_limits<S>::min().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::max().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::lowest().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::epsilon().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::round_error().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::infinity().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::quiet_NaN().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::signaling_NaN().i == 42);
    STATIC_REQUIRE(etl::numeric_limits<S>::denorm_min().i == 42);
}

TEST_CASE("limits: numeric_limits<bool>", "[limits]")
{
    STATIC_REQUIRE(etl::numeric_limits<bool>::is_specialized == true);
    STATIC_REQUIRE(etl::numeric_limits<bool>::is_signed == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::is_integer == true);
    STATIC_REQUIRE(etl::numeric_limits<bool>::is_bounded == true);

    STATIC_REQUIRE(etl::numeric_limits<bool>::min() == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::max() == true);
    STATIC_REQUIRE(etl::numeric_limits<bool>::lowest() == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::epsilon() == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::round_error() == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::infinity() == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::quiet_NaN() == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::signaling_NaN() == false);
    STATIC_REQUIRE(etl::numeric_limits<bool>::denorm_min() == false);
}
