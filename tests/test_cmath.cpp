/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cmath.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("cmath: isinf", "[cmath]", float, double, long double)
{
    REQUIRE(etl::isinf(HUGE_VAL));
    REQUIRE(etl::isinf(HUGE_VALF));
    REQUIRE(etl::isinf(HUGE_VALL));
    REQUIRE_FALSE(etl::isinf(NAN));
    REQUIRE_FALSE(etl::isinf(TestType { 0 }));
    REQUIRE_FALSE(etl::isinf(TestType { 1 }));
}

TEMPLATE_TEST_CASE("cmath: isnan", "[cmath]", float, double, long double)
{
    REQUIRE(etl::isnan(NAN));

    REQUIRE_FALSE(etl::isnan(TestType { 0 }));
    REQUIRE_FALSE(etl::isnan(TestType { 1 }));
    REQUIRE_FALSE(etl::isnan(INFINITY));
    REQUIRE_FALSE(etl::isnan(HUGE_VAL));
    REQUIRE_FALSE(etl::isnan(HUGE_VALF));
    REQUIRE_FALSE(etl::isnan(HUGE_VALL));
}

TEMPLATE_TEST_CASE("cmath: isfinite", "[cmath]", float, double, long double)
{
    REQUIRE(etl::isfinite(TestType { 0 }));
    REQUIRE(etl::isfinite(TestType { 1 }));

    REQUIRE_FALSE(etl::isfinite(INFINITY));
    REQUIRE_FALSE(etl::isfinite(HUGE_VAL));
    REQUIRE_FALSE(etl::isfinite(HUGE_VALF));
    REQUIRE_FALSE(etl::isfinite(HUGE_VALL));
    REQUIRE_FALSE(etl::isfinite(NAN));
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