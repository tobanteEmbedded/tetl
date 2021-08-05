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
#include "etl/ratio.hpp"

#include "etl/warning.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("ratio: construct", "[ratio]")
{
    etl::ratio<1, 1> r {};
    etl::ignore_unused(r);
}

TEST_CASE("ratio: num/den", "[ratio]")
{
    STATIC_REQUIRE(etl::ratio<1, 2>::type::num == 1);
    STATIC_REQUIRE(etl::ratio<1, 2>::type::den == 2);
    STATIC_REQUIRE(etl::ratio<3, 6>::type::num == 1);
    STATIC_REQUIRE(etl::ratio<3, 6>::type::den == 2);
    STATIC_REQUIRE(etl::ratio<2, 8>::type::num == 1);
    STATIC_REQUIRE(etl::ratio<2, 8>::type::den == 4);
}

TEST_CASE("ratio: ratio_add", "[ratio]")
{
    WHEN("1/4 + 1/6 = 5/12")
    {
        using one_fourth = etl::ratio<1, 4>;
        using one_sixth  = etl::ratio<1, 6>;
        using sum        = etl::ratio_add<one_fourth, one_sixth>;
        STATIC_REQUIRE(sum::num == 5);
        STATIC_REQUIRE(sum::den == 12);
    }

    WHEN("2/3 + 1/6 = 5/6")
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using sum       = etl::ratio_add<two_third, one_sixth>;
        STATIC_REQUIRE(sum::num == 5);
        STATIC_REQUIRE(sum::den == 6);
    }
}

TEST_CASE("ratio: ratio_subtract", "[ratio]")
{
    WHEN("1/4 - 1/6 = 1/12")
    {
        using one_fourth = etl::ratio<1, 4>;
        using one_sixth  = etl::ratio<1, 6>;
        using sum        = etl::ratio_subtract<one_fourth, one_sixth>;
        STATIC_REQUIRE(sum::num == 1);
        STATIC_REQUIRE(sum::den == 12);
    }

    WHEN("2/3 - 1/6 = 3/6 = 1/2")
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using sum       = etl::ratio_subtract<two_third, one_sixth>;
        STATIC_REQUIRE(sum::num == 1);
        STATIC_REQUIRE(sum::den == 2);
    }
}

TEST_CASE("ratio: ratio_multiply", "[ratio]")
{
    WHEN("1/12 * 1/2 = 1/2")
    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;
        using res         = etl::ratio_multiply<one_twelfth, one_half>;
        STATIC_REQUIRE(res::num == 1);
        STATIC_REQUIRE(res::den == 24);
    }

    WHEN("2/3 * 1/6 = 1/9")
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using res       = etl::ratio_multiply<two_third, one_sixth>;
        STATIC_REQUIRE(res::num == 1);
        STATIC_REQUIRE(res::den == 9);
    }
}

TEST_CASE("ratio: ratio_divide", "[ratio]")
{
    WHEN("1/12 / 1/6 = 1/2")
    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_sixth   = etl::ratio<1, 6>;
        using res         = etl::ratio_divide<one_twelfth, one_sixth>;
        STATIC_REQUIRE(res::num == 1);
        STATIC_REQUIRE(res::den == 2);
    }

    WHEN("2/3 / 1/6 = 4/1")
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using res       = etl::ratio_divide<two_third, one_sixth>;
        STATIC_REQUIRE(res::num == 4);
        STATIC_REQUIRE(res::den == 1);
    }
}

TEST_CASE("ratio: ratio_equal", "[ratio]")
{
    using one_twelfth = etl::ratio<1, 12>;
    using one_half    = etl::ratio<1, 2>;

    STATIC_REQUIRE(etl::ratio_equal_v<one_half, one_half>);
    STATIC_REQUIRE(etl::ratio_equal_v<one_half, etl::ratio<2, 4>>);
    STATIC_REQUIRE(etl::ratio_equal_v<one_half, etl::ratio<3, 6>>);
    STATIC_REQUIRE(etl::ratio_equal_v<one_twelfth, one_twelfth>);
    STATIC_REQUIRE(etl::ratio_equal_v<one_twelfth, etl::ratio<2, 24>>);
    STATIC_REQUIRE(etl::ratio_equal_v<one_twelfth, etl::ratio<3, 36>>);

    STATIC_REQUIRE_FALSE(etl::ratio_equal_v<one_half, one_twelfth>);
    STATIC_REQUIRE_FALSE(etl::ratio_equal_v<one_twelfth, one_half>);
    STATIC_REQUIRE_FALSE(etl::ratio_equal_v<one_twelfth, etl::ratio<2, 23>>);
    STATIC_REQUIRE_FALSE(etl::ratio_equal_v<one_twelfth, etl::ratio<3, 35>>);
}

TEST_CASE("ratio: ratio_not_equal", "[ratio]")
{
    using one_twelfth = etl::ratio<1, 12>;
    using one_half    = etl::ratio<1, 2>;

    STATIC_REQUIRE_FALSE(etl::ratio_not_equal_v<one_half, one_half>);
    STATIC_REQUIRE_FALSE(etl::ratio_not_equal_v<one_half, etl::ratio<2, 4>>);
    STATIC_REQUIRE_FALSE(etl::ratio_not_equal_v<one_half, etl::ratio<3, 6>>);
    STATIC_REQUIRE_FALSE(etl::ratio_not_equal_v<one_twelfth, one_twelfth>);
    STATIC_REQUIRE_FALSE(
        etl::ratio_not_equal_v<one_twelfth, etl::ratio<2, 24>>);
    STATIC_REQUIRE_FALSE(
        etl::ratio_not_equal_v<one_twelfth, etl::ratio<3, 36>>);

    STATIC_REQUIRE(etl::ratio_not_equal_v<one_half, one_twelfth>);
    STATIC_REQUIRE(etl::ratio_not_equal_v<one_twelfth, one_half>);
    STATIC_REQUIRE(etl::ratio_not_equal_v<one_twelfth, etl::ratio<2, 23>>);
    STATIC_REQUIRE(etl::ratio_not_equal_v<one_twelfth, etl::ratio<3, 35>>);
}

TEST_CASE("ratio: ratio_less", "[ratio]")
{
    using one_twelfth = etl::ratio<1, 12>;
    using one_half    = etl::ratio<1, 2>;

    STATIC_REQUIRE_FALSE(etl::ratio_less_v<one_half, one_half>);
    STATIC_REQUIRE_FALSE(etl::ratio_less_v<one_half, etl::ratio<2, 4>>);
    STATIC_REQUIRE_FALSE(etl::ratio_less_v<one_half, etl::ratio<3, 6>>);
    STATIC_REQUIRE_FALSE(etl::ratio_less_v<one_twelfth, one_twelfth>);
    STATIC_REQUIRE_FALSE(etl::ratio_less_v<one_twelfth, etl::ratio<2, 24>>);
    STATIC_REQUIRE_FALSE(etl::ratio_less_v<one_twelfth, etl::ratio<3, 36>>);
    STATIC_REQUIRE_FALSE(etl::ratio_less_v<one_half, one_twelfth>);

    STATIC_REQUIRE(etl::ratio_less_v<one_twelfth, one_half>);
    STATIC_REQUIRE(etl::ratio_less_v<one_twelfth, etl::ratio<2, 23>>);
    STATIC_REQUIRE(etl::ratio_less_v<one_twelfth, etl::ratio<3, 35>>);
}

TEST_CASE("ratio: ratio_less_equal", "[ratio]")
{
    using etl::ratio;
    using etl::ratio_less_equal;
    using etl::ratio_less_equal_v;
    using one_twelfth = etl::ratio<1, 12>;
    using one_half    = etl::ratio<1, 2>;

    STATIC_REQUIRE(ratio_less_equal<one_half, etl::ratio<3, 4>>::value);
    STATIC_REQUIRE(ratio_less_equal_v<one_half, one_half>);
    STATIC_REQUIRE(ratio_less_equal_v<one_half, etl::ratio<2, 4>>);
    STATIC_REQUIRE(ratio_less_equal_v<one_half, etl::ratio<3, 6>>);
    STATIC_REQUIRE(ratio_less_equal_v<one_twelfth, one_twelfth>);

    STATIC_REQUIRE(ratio_less_equal_v<etl::ratio<10, 11>, etl::ratio<11, 12>>);
    STATIC_REQUIRE(ratio_less_equal_v<one_twelfth, one_half>);
    STATIC_REQUIRE(ratio_less_equal_v<one_twelfth, etl::ratio<2, 23>>);
    STATIC_REQUIRE(ratio_less_equal_v<one_twelfth, etl::ratio<3, 35>>);

    STATIC_REQUIRE_FALSE(ratio_less_equal_v<one_half, one_twelfth>);
}

TEST_CASE("ratio: ratio_greater", "[ratio]")
{
    using etl::ratio;
    using etl::ratio_greater;
    using etl::ratio_greater_v;

    using one_twelfth = etl::ratio<1, 12>;
    using one_half    = etl::ratio<1, 2>;

    STATIC_REQUIRE_FALSE(etl::ratio_greater_v<one_half, one_half>);
    STATIC_REQUIRE_FALSE(etl::ratio_greater_v<one_half, etl::ratio<2, 4>>);
    STATIC_REQUIRE_FALSE(etl::ratio_greater_v<one_half, etl::ratio<3, 6>>);
    STATIC_REQUIRE_FALSE(etl::ratio_greater_v<one_twelfth, one_twelfth>);
    STATIC_REQUIRE_FALSE(etl::ratio_greater_v<one_twelfth, etl::ratio<2, 24>>);
    STATIC_REQUIRE_FALSE(etl::ratio_greater_v<one_twelfth, etl::ratio<3, 36>>);
    STATIC_REQUIRE_FALSE(etl::ratio_greater_v<one_twelfth, one_half>);

    STATIC_REQUIRE(etl::ratio_greater_v<one_half, one_twelfth>);
    STATIC_REQUIRE(etl::ratio_greater_v<etl::ratio<2, 23>, one_twelfth>);
    STATIC_REQUIRE(etl::ratio_greater_v<etl::ratio<3, 35>, one_twelfth>);
}

TEST_CASE("ratio: ratio_greater_equal", "[ratio]")
{
    using etl::ratio;
    using etl::ratio_greater_equal;
    using etl::ratio_greater_equal_v;

    using one_twelfth = etl::ratio<1, 12>;
    using one_half    = etl::ratio<1, 2>;

    STATIC_REQUIRE(ratio_greater_equal_v<one_half, one_half>);
    STATIC_REQUIRE(ratio_greater_equal_v<one_half, ratio<2, 4>>);
    STATIC_REQUIRE(ratio_greater_equal_v<one_half, ratio<3, 6>>);
    STATIC_REQUIRE(ratio_greater_equal_v<one_twelfth, one_twelfth>);
    STATIC_REQUIRE(ratio_greater_equal_v<one_twelfth, ratio<2, 24>>);
    STATIC_REQUIRE(ratio_greater_equal_v<one_twelfth, ratio<3, 36>>);
    STATIC_REQUIRE(ratio_greater_equal_v<one_half, one_twelfth>);
    STATIC_REQUIRE(ratio_greater_equal_v<ratio<2, 23>, one_twelfth>);
    STATIC_REQUIRE(ratio_greater_equal_v<ratio<3, 35>, one_twelfth>);

    STATIC_REQUIRE_FALSE(ratio_greater_equal_v<one_twelfth, one_half>);
}
