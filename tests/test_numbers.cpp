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

#include "catch2/catch_approx.hpp"
#include "catch2/catch_template_test_macros.hpp"

#include "etl/numbers.hpp"

TEMPLATE_TEST_CASE(
    "numbers: constants", "[numbers]", float, double, long double)
{
    REQUIRE(etl::numbers::e_v<TestType> == Catch::Approx(2.7182818));
    REQUIRE(etl::numbers::log2e_v<TestType> == Catch::Approx(1.44269504));
    REQUIRE(etl::numbers::log10e_v<TestType> == Catch::Approx(0.4342944));
    REQUIRE(etl::numbers::pi_v<TestType> == Catch::Approx(3.1415926));
    REQUIRE(etl::numbers::inv_sqrtpi_v<TestType> == Catch::Approx(0.5641895));
    REQUIRE(etl::numbers::inv_pi_v<TestType> == Catch::Approx(0.3183098));
    REQUIRE(etl::numbers::ln2_v<TestType> == Catch::Approx(0.6931471));
    REQUIRE(etl::numbers::ln10_v<TestType> == Catch::Approx(2.3025850));
    REQUIRE(etl::numbers::sqrt2_v<TestType> == Catch::Approx(1.4142135));
    REQUIRE(etl::numbers::sqrt3_v<TestType> == Catch::Approx(1.7320508));
    REQUIRE(etl::numbers::inv_sqrt3_v<TestType> == Catch::Approx(0.5773502));
    REQUIRE(etl::numbers::egamma_v<TestType> == Catch::Approx(0.5772156));
    REQUIRE(etl::numbers::phi_v<TestType> == Catch::Approx(1.6180339));
}