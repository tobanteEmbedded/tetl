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

#include "etl/experimental/units/units.hpp"

#include "catch2/catch.hpp"

using namespace etl::experimental;

TEMPLATE_TEST_CASE("experimental/units: add", "[units][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    auto const t1 = units::quantity<TestType, units::time> {TestType {3}};
    auto const t2 = units::quantity<TestType, units::time> {TestType {10}};
    auto const t3 = t1 + t2;
    REQUIRE(t3.value() == TestType {13});
}

TEMPLATE_TEST_CASE("experimental/units: add constexpr", "[units][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    constexpr auto t1 = units::quantity<TestType, units::time> {TestType {3}};
    constexpr auto t2 = units::quantity<TestType, units::time> {TestType {10}};
    constexpr auto t3 = t1 + t2;
    REQUIRE(t3.value() == TestType {13});
}
