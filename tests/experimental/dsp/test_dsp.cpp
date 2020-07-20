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

#include "etl/experimental/dsp/dsp.hpp"

#include "catch2/catch.hpp"

TEST_CASE("experimental/dsp: identity", "[dsp][experimental]")
{
    auto id = etl::dsp::identity {};
    REQUIRE(id(0) == 0);
}

TEST_CASE("experimental/dsp: constant", "[dsp][experimental]")
{
    REQUIRE(etl::dsp::constant {0.0}() == 0.0);
    REQUIRE(etl::dsp::constant {42}() == 42);
}

TEST_CASE("experimental/dsp: constant literal", "[dsp][experimental]")
{
    using namespace etl::dsp::literals;
    REQUIRE(0.0_K() == 0.0L);
    REQUIRE(42_K() == 42);
}

TEST_CASE("experimental/dsp: pipe", "[dsp][experimental]")
{
    auto in  = etl::dsp::identity {};
    auto foo = [](int v) -> int { return v * 3; };
    auto bar = [](int v) -> int { return v / 2; };
    auto f   = in | foo | bar;

    REQUIRE(f(0) == 0);
    REQUIRE(f(2) == 3);
    REQUIRE(f(3) == 4);
}

TEST_CASE("experimental/dsp: delay", "[dsp][experimental]")
{
    WHEN("by zero (no delay)")
    {
        auto in = etl::dsp::identity {};
        auto f  = in | etl::dsp::Z<0, int>();
        REQUIRE(f(0) == 0);
        REQUIRE(f(2) == 2);
        REQUIRE(f(3) == 3);
    }

    WHEN("by one")
    {
        auto in = etl::dsp::identity {};
        auto f  = in | etl::dsp::Z<-1, int>();
        REQUIRE(f(0) == 0);
        REQUIRE(f(2) == 0);
        REQUIRE(f(3) == 2);
        REQUIRE(f(4) == 3);
    }

    WHEN("by two")
    {
        auto in = etl::dsp::identity {};
        auto f  = in | etl::dsp::Z<-2, int>();
        REQUIRE(f(0) == 0);
        REQUIRE(f(2) == 0);
        REQUIRE(f(3) == 0);
        REQUIRE(f(4) == 2);
    }
}

TEST_CASE("experimental/dsp: feedback_drain", "[dsp][experimental]")
{
    WHEN("No feedback is applied")
    {
        auto drain = etl::dsp::feedback_drain {};
        REQUIRE(drain(0.0f) == 0.0f);
        REQUIRE(drain(0.5f) == 0.5f);
        REQUIRE(drain(0.75f) == 0.75f);
        REQUIRE(drain(1.0f) == 1.0f);
    }

    WHEN("Feedback is applied")
    {
        auto drain = etl::dsp::feedback_drain {};
        drain.push(1.0f);
        REQUIRE(drain(0.0f) == 1.0f);
    }
}

TEST_CASE("experimental/dsp: feedback_tap", "[dsp][experimental]")
{
    WHEN("Pass Through")
    {
        auto drain = etl::dsp::feedback_drain {};
        auto tap   = etl::dsp::feedback_tap {drain};
        REQUIRE(tap(0.0f) == 0.0f);
        REQUIRE(tap(0.5f) == 0.5f);
        REQUIRE(tap(0.75f) == 0.75f);
        REQUIRE(tap(1.0f) == 1.0f);
    }

    WHEN("Pass to drain")
    {
        auto drain = etl::dsp::feedback_drain {};
        auto tap   = etl::dsp::feedback_tap {drain};

        REQUIRE(tap(1.0f) == 1.0f);
        REQUIRE(drain(0.0f) == 1.0f);

        REQUIRE(tap(0.0f) == 0.0f);
        REQUIRE(drain(0.0f) == 0.0f);

        REQUIRE(tap(0.5f) == 0.5f);
        REQUIRE(drain(0.0f) == 0.5f);
    }
}

// TODO
// TEST_CASE("experimental/dsp: feedback chain", "[dsp][experimental]")
// {
//     auto in    = etl::dsp::identity {};
//     auto drain = etl::dsp::feedback_drain {};
//     // auto tap   = etl::dsp::feedback_tap {drain};
//     auto chain = in | drain;  // | tap;
//     REQUIRE(chain(1.0f) == 1.0f);
//     REQUIRE(chain(0.0f) == 0.0f);

//     drain.push(0.5f);
//     REQUIRE(chain(0.0f) == 0.5f);
// }
