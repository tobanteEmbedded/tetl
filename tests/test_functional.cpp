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

#include "etl/functional.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("functional: function - ctor", "[functional]", int, float,
                   double)
{
    auto func = etl::function<TestType(void)> {[]() { return TestType {1}; }};
    REQUIRE(func() == TestType {1});
    REQUIRE(func() == TestType {1});
}

TEMPLATE_TEST_CASE("functional: function - ctor copy", "[functional]", int,
                   float, double)
{
    auto func  = etl::function<TestType(void)> {[]() { return TestType {1}; }};
    auto func2 = func;
    func       = func2;
    REQUIRE(func() == TestType {1});
    REQUIRE(func() == TestType {1});
}

TEMPLATE_TEST_CASE("functional: function - assigment copy", "[functional]", int,
                   float, double)
{
    auto func  = etl::function<TestType(void)> {[]() { return TestType {1}; }};
    auto func2 = func;
    REQUIRE(func() == TestType {1});
    REQUIRE(func2() == TestType {1});
    REQUIRE(func2() == TestType {1});
}