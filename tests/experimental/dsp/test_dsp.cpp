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

#include "taetl/experimental/dsp/dsp.hpp"

#include "catch2/catch.hpp"

TEST_CASE("experimental/dsp: identity", "[dsp][experimental]")
{
    auto id = taetl::dsp::identity {};
    REQUIRE(id(0) == 0);
}

TEST_CASE("experimental/dsp: constant", "[dsp][experimental]")
{
    REQUIRE(taetl::dsp::constant {0.0}() == 0.0);
    REQUIRE(taetl::dsp::constant {42}() == 42);
}

TEST_CASE("experimental/dsp: constant literal", "[dsp][experimental]")
{
    using namespace taetl::dsp::literals;
    REQUIRE(0.0_K() == 0.0);
    REQUIRE(42_K() == 42);
}

TEST_CASE("experimental/dsp: pipe", "[dsp][experimental]")
{
    auto in  = taetl::dsp::identity {};
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
        auto in = taetl::dsp::identity {};
        auto f  = in | taetl::dsp::Z<0, int>();
        REQUIRE(f(0) == 0);
        REQUIRE(f(2) == 2);
        REQUIRE(f(3) == 3);
    }

    WHEN("by one")
    {
        auto in = taetl::dsp::identity {};
        auto f  = in | taetl::dsp::Z<-1, int>();
        REQUIRE(f(0) == 0);
        REQUIRE(f(2) == 0);
        REQUIRE(f(3) == 2);
        REQUIRE(f(4) == 3);
    }

    WHEN("by two")
    {
        auto in = taetl::dsp::identity {};
        auto f  = in | taetl::dsp::Z<-2, int>();
        REQUIRE(f(0) == 0);
        REQUIRE(f(2) == 0);
        REQUIRE(f(3) == 0);
        REQUIRE(f(4) == 2);
    }
}