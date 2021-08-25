/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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