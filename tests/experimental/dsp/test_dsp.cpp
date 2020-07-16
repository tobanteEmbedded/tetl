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

using namespace taetl::dsp;

TEST_CASE("dsp: identity", "[dsp]")
{
    auto id = identity {};
    REQUIRE(id(0) == 0);
}

TEST_CASE("dsp: constant", "[dsp]")
{
    REQUIRE(constant {0.0}() == 0.0);
    REQUIRE(constant {42}() == 42);
}

TEST_CASE("dsp: constant literal", "[dsp]")
{
    using namespace taetl::dsp::literals;
    REQUIRE(0.0_K() == 0.0);
    REQUIRE(42_K() == 42);
}

TEST_CASE("dsp: pipe", "[dsp]")
{
    auto in  = identity {};
    auto foo = [](int v) -> int { return v * 3; };
    auto bar = [](int v) -> int { return v / 2; };
    auto f   = in | foo | bar;

    REQUIRE(f(0) == 0);
    REQUIRE(f(2) == 3);
    REQUIRE(f(3) == 4);
}