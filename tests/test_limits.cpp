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
#include "etl/limits.hpp"

#include "catch2/catch_template_test_macros.hpp"

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
    struct S {
        int i = 42;
    };
    STATIC_REQUIRE(etl::numeric_limits<S>::is_specialized == false);
    STATIC_REQUIRE(etl::numeric_limits<S>::is_signed == false);
    STATIC_REQUIRE(etl::numeric_limits<S>::is_integer == false);
    STATIC_REQUIRE(etl::numeric_limits<S>::is_bounded == false);

    REQUIRE(etl::numeric_limits<S>::min().i == 42);
    REQUIRE(etl::numeric_limits<S>::max().i == 42);
    REQUIRE(etl::numeric_limits<S>::lowest().i == 42);
    REQUIRE(etl::numeric_limits<S>::epsilon().i == 42);
    REQUIRE(etl::numeric_limits<S>::round_error().i == 42);
    REQUIRE(etl::numeric_limits<S>::infinity().i == 42);
    REQUIRE(etl::numeric_limits<S>::quiet_NaN().i == 42);
    REQUIRE(etl::numeric_limits<S>::signaling_NaN().i == 42);
    REQUIRE(etl::numeric_limits<S>::denorm_min().i == 42);
}

TEMPLATE_TEST_CASE("limits: numeric_limits<bool>", "[limits]", bool, bool const,
    bool volatile, bool const volatile)
{
    STATIC_REQUIRE(etl::numeric_limits<TestType>::is_specialized == true);
    STATIC_REQUIRE(etl::numeric_limits<TestType>::is_signed == false);
    STATIC_REQUIRE(etl::numeric_limits<TestType>::is_integer == true);
    STATIC_REQUIRE(etl::numeric_limits<TestType>::is_bounded == true);

    REQUIRE(etl::numeric_limits<TestType>::min() == false);
    REQUIRE(etl::numeric_limits<TestType>::max() == true);
    REQUIRE(etl::numeric_limits<TestType>::lowest() == false);
    REQUIRE(etl::numeric_limits<TestType>::epsilon() == false);
    REQUIRE(etl::numeric_limits<TestType>::round_error() == false);
    REQUIRE(etl::numeric_limits<TestType>::infinity() == false);
    REQUIRE(etl::numeric_limits<TestType>::quiet_NaN() == false);
    REQUIRE(etl::numeric_limits<TestType>::signaling_NaN() == false);
    REQUIRE(etl::numeric_limits<TestType>::denorm_min() == false);
}

TEMPLATE_TEST_CASE("limits: numeric_limits<signed T>", "[limits]", char, short,
    int, long, long long, signed char, signed short, signed int, signed long,
    signed long long)
{
    using l = etl::numeric_limits<TestType>;
    STATIC_REQUIRE(l::is_specialized == true);
    STATIC_REQUIRE(l::is_signed == true);
    STATIC_REQUIRE(l::is_integer == true);
    STATIC_REQUIRE(l::is_bounded == true);
    REQUIRE(l::lowest() == l::min());
    REQUIRE(l::max() > l::min());
    REQUIRE(l::epsilon() == TestType {});
    REQUIRE(l::round_error() == TestType {});
    REQUIRE(l::infinity() == TestType {});
    REQUIRE(l::quiet_NaN() == TestType {});
    REQUIRE(l::signaling_NaN() == TestType {});
    REQUIRE(l::denorm_min() == TestType {});

    using lc = etl::numeric_limits<TestType const>;
    STATIC_REQUIRE(lc::is_specialized == true);
    STATIC_REQUIRE(lc::is_signed == true);
    STATIC_REQUIRE(lc::is_integer == true);
    STATIC_REQUIRE(lc::is_bounded == true);
    REQUIRE(lc::lowest() == lc::min());
    REQUIRE(lc::max() > lc::min());
    REQUIRE(lc::epsilon() == TestType {});
    REQUIRE(lc::round_error() == TestType {});
    REQUIRE(lc::infinity() == TestType {});
    REQUIRE(lc::quiet_NaN() == TestType {});
    REQUIRE(lc::signaling_NaN() == TestType {});
    REQUIRE(lc::denorm_min() == TestType {});

    using lv = etl::numeric_limits<TestType volatile>;
    STATIC_REQUIRE(lv::is_specialized == true);
    STATIC_REQUIRE(lv::is_signed == true);
    STATIC_REQUIRE(lv::is_integer == true);
    STATIC_REQUIRE(lv::is_bounded == true);
    REQUIRE(lv::lowest() == lv::min());
    REQUIRE(lv::max() > lv::min());
    REQUIRE(lv::epsilon() == TestType {});
    REQUIRE(lv::round_error() == TestType {});
    REQUIRE(lv::infinity() == TestType {});
    REQUIRE(lv::quiet_NaN() == TestType {});
    REQUIRE(lv::signaling_NaN() == TestType {});
    REQUIRE(lv::denorm_min() == TestType {});

    using lcv = etl::numeric_limits<TestType const volatile>;
    STATIC_REQUIRE(lcv::is_specialized == true);
    STATIC_REQUIRE(lcv::is_signed == true);
    STATIC_REQUIRE(lcv::is_integer == true);
    STATIC_REQUIRE(lcv::is_bounded == true);
    REQUIRE(lcv::lowest() == lcv::min());
    REQUIRE(lcv::max() > lcv::min());
    REQUIRE(lcv::epsilon() == TestType {});
    REQUIRE(lcv::round_error() == TestType {});
    REQUIRE(lcv::infinity() == TestType {});
    REQUIRE(lcv::quiet_NaN() == TestType {});
    REQUIRE(lcv::signaling_NaN() == TestType {});
    REQUIRE(lcv::denorm_min() == TestType {});
}

TEMPLATE_TEST_CASE("limits: numeric_limits<unsigned T>", "[limits]",
    unsigned char, unsigned short, unsigned int, unsigned long,
    unsigned long long)
{
    using l = etl::numeric_limits<TestType>;

    STATIC_REQUIRE(l::is_specialized == true);
    STATIC_REQUIRE(l::is_signed == false);
    STATIC_REQUIRE(l::is_integer == true);
    STATIC_REQUIRE(l::is_bounded == true);

    REQUIRE(l::lowest() == l::min());
    REQUIRE(l::max() > l::min());
    REQUIRE(l::epsilon() == TestType {});
    REQUIRE(l::round_error() == TestType {});
    REQUIRE(l::infinity() == TestType {});
    REQUIRE(l::quiet_NaN() == TestType {});
    REQUIRE(l::signaling_NaN() == TestType {});
    REQUIRE(l::denorm_min() == TestType {});
}

TEST_CASE("limits: numeric_limits<float>", "[limits]")
{
    STATIC_REQUIRE(etl::numeric_limits<float>::is_specialized == true);
    STATIC_REQUIRE(etl::numeric_limits<float>::is_signed == true);
    STATIC_REQUIRE(etl::numeric_limits<float>::is_integer == false);
    STATIC_REQUIRE(etl::numeric_limits<float>::is_bounded == true);

    REQUIRE(etl::numeric_limits<float>::min() == FLT_MIN);
    REQUIRE(etl::numeric_limits<float>::max() == FLT_MAX);
    REQUIRE(etl::numeric_limits<float>::lowest() == -FLT_MAX);
    REQUIRE(etl::numeric_limits<float>::epsilon() == FLT_EPSILON);
    REQUIRE(etl::numeric_limits<float>::round_error() == 0.5F);
    // REQUIRE(etl::numeric_limits<float>::infinity() == HUGE_VALF);
}

TEST_CASE("limits: numeric_limits<double>", "[limits]")
{
    STATIC_REQUIRE(etl::numeric_limits<double>::is_specialized == true);
    STATIC_REQUIRE(etl::numeric_limits<double>::is_signed == true);
    STATIC_REQUIRE(etl::numeric_limits<double>::is_integer == false);
    STATIC_REQUIRE(etl::numeric_limits<double>::is_bounded == true);

    REQUIRE(etl::numeric_limits<double>::min() == DBL_MIN);
    REQUIRE(etl::numeric_limits<double>::max() == DBL_MAX);
    REQUIRE(etl::numeric_limits<double>::lowest() == -DBL_MAX);
    REQUIRE(etl::numeric_limits<double>::epsilon() == DBL_EPSILON);
    REQUIRE(etl::numeric_limits<double>::round_error() == 0.5);
    // REQUIRE(etl::numeric_limits<double>::infinity() == HUGE_VAL);
}
