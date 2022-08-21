/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/experimental/testing/testing.hpp"

TEST_CASE("A", "")
{
    CHECK_EQUAL(1, 1);
    CHECK_EQUAL(2, 2);

    SECTION("different assertion macro")
    {
        CHECK_NOT_EQUAL(42, 1);
        CHECK_NOT_EQUAL(42, 2);
    }
}

TEST_CASE("B", "")
{
    CHECK(143 == 143);
    CHECK_FALSE(42 == 41);
}

TEST_CASE("C", "")
{
    REQUIRE(143 == 143);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
    REQUIRE_FALSE(42 == 41);
}

#if not defined(TETL_MSVC)
namespace {
struct TestStruct { };
} // namespace

TEMPLATE_TEST_CASE("template test", "", int, char, float, TestStruct)
{
    using T = TestType;
    if constexpr (etl::is_arithmetic_v<T>) { CHECK(T(1) > T(0)); }
}
#endif
