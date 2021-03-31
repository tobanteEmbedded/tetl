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

#include "catch2/catch_template_test_macros.hpp"

#include "etl/cmath.hpp"

TEMPLATE_TEST_CASE("cmath: isinf", "[cmath]", float, double, long double)
{
  REQUIRE(etl::isinf(TestType {INFINITY}));
  REQUIRE_FALSE(etl::isinf(TestType {NAN}));
  REQUIRE_FALSE(etl::isinf(TestType {0}));
  REQUIRE_FALSE(etl::isinf(TestType {1}));
}

TEMPLATE_TEST_CASE("cmath: isnan", "[cmath]", float, double, long double)
{
  auto val = TestType {0.0};
  REQUIRE_FALSE(etl::isnan(val));

  val = 1.0;
  REQUIRE_FALSE(etl::isnan(val));

  val = INFINITY;
  REQUIRE_FALSE(etl::isnan(val));

  val = NAN;
  REQUIRE(etl::isnan(val));
}

TEMPLATE_TEST_CASE("cmath: isfinite", "[cmath]", float, double, long double)
{
  REQUIRE(etl::isfinite(TestType {0}));
  REQUIRE(etl::isfinite(TestType {1}));

  REQUIRE_FALSE(etl::isfinite(TestType {INFINITY}));
  REQUIRE_FALSE(etl::isfinite(TestType {NAN}));
}

TEMPLATE_TEST_CASE("cmath: lerp", "[cmath]", float, double, long double)
{
  using T = TestType;
  CHECK(etl::lerp(T(0), T(1), T(0)) == T(0));
  CHECK(etl::lerp(T(0), T(1), T(0.5)) == T(0.5));

  CHECK(etl::lerp(T(0), T(20), T(0)) == T(0));
  CHECK(etl::lerp(T(0), T(20), T(0.5)) == T(10));
  CHECK(etl::lerp(T(0), T(20), T(2)) == T(40));

  CHECK(etl::lerp(T(20), T(0), T(0)) == T(20));
  CHECK(etl::lerp(T(20), T(0), T(0.5)) == T(10));
  CHECK(etl::lerp(T(20), T(0), T(2)) == T(-20));

  CHECK(etl::lerp(T(0), T(-20), T(0)) == T(0));
  CHECK(etl::lerp(T(0), T(-20), T(0.5)) == T(-10));
  CHECK(etl::lerp(T(0), T(-20), T(2)) == T(-40));

  CHECK(etl::lerp(T(-10), T(-20), T(0)) == T(-10));
  CHECK(etl::lerp(T(-10), T(-20), T(0.5)) == T(-15));
  CHECK(etl::lerp(T(-10), T(-20), T(2)) == T(-30));
}

TEMPLATE_TEST_CASE("cmath: abs", "[cmath]", int, long, long long)
{
  using T = TestType;

  CHECK(etl::abs(T(0)) == T(0));

  CHECK(etl::abs(T(1)) == T(1));
  CHECK(etl::abs(T(2)) == T(2));
  CHECK(etl::abs(T(3)) == T(3));

  CHECK(etl::abs(T(-1)) == T(1));
  CHECK(etl::abs(T(-2)) == T(2));
  CHECK(etl::abs(T(-3)) == T(3));
}