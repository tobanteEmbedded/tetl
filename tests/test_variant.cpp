/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/variant.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("variant: bad_variant_access", "[variant]")
{
    using etl::is_base_of_v;
    using etl::is_constructible_v;
    using etl::is_default_constructible_v;

    STATIC_REQUIRE(is_default_constructible_v<etl::bad_variant_access>);
    STATIC_REQUIRE(is_constructible_v<etl::bad_variant_access, char const*>);
    STATIC_REQUIRE(is_base_of_v<etl::exception, etl::bad_variant_access>);
}

TEST_CASE("variant: monostate", "[variant]")
{
    // All instances of etl::monostate compare equal.
    auto lhs = etl::monostate {};
    auto rhs = etl::monostate {};

    CHECK(lhs == rhs);
    CHECK(lhs <= rhs);
    CHECK(lhs >= rhs);

    CHECK_FALSE(lhs != rhs);
    CHECK_FALSE(lhs < rhs);
    CHECK_FALSE(lhs > rhs);
}

TEST_CASE("variant: sizeof", "[variant]")
{
    using etl::int8_t;
    using etl::monostate;
    using etl::uint16_t;
    using etl::uint32_t;
    using etl::uint64_t;
    using etl::uint8_t;
    using etl::variant;

    struct S {
        uint32_t data[4];
    };

    STATIC_REQUIRE(sizeof(variant<monostate>) == 2);
    STATIC_REQUIRE(sizeof(variant<monostate, uint8_t>) == 2);
    STATIC_REQUIRE(sizeof(variant<monostate, int8_t, uint8_t>) == 2);
    STATIC_REQUIRE(sizeof(variant<monostate, char, int8_t, uint8_t>) == 2);

    STATIC_REQUIRE(sizeof(variant<monostate, uint16_t>) == 4);
    STATIC_REQUIRE(sizeof(variant<monostate, char, int8_t, uint16_t>) == 4);

    STATIC_REQUIRE(sizeof(variant<monostate, uint32_t>) == 8);
    STATIC_REQUIRE(sizeof(variant<monostate, uint32_t, uint32_t>) == 8);
    STATIC_REQUIRE(sizeof(variant<monostate, uint32_t, uint64_t>) == 16);
    STATIC_REQUIRE(sizeof(variant<monostate, S, uint64_t>) == 24);
}

TEST_CASE("variant: construct", "[variant]")
{
    struct S {
        S() : x { 42 } { }
        int x; // NOLINT
    };

    SECTION("default")
    {
        auto v1 = etl::variant<int, float> {};
        CHECK(etl::holds_alternative<int>(v1));
        CHECK_FALSE(etl::holds_alternative<float>(v1));

        auto v2 = etl::variant<float, int> {};
        CHECK(etl::holds_alternative<float>(v2));
        CHECK_FALSE(etl::holds_alternative<int>(v2));

        auto v3 = etl::variant<S, int> {};
        CHECK(etl::holds_alternative<S>(v3));
        CHECK_FALSE(etl::holds_alternative<int>(v3));
        CHECK(etl::get_if<S>(&v3)->x == 42);
    }

    SECTION("monostate")
    {
        auto var
            = etl::variant<etl::monostate, int, float> { etl::monostate {} };
        CHECK(etl::holds_alternative<etl::monostate>(var));
        CHECK(*etl::get_if<etl::monostate>(&var) == etl::monostate {});
    }

    SECTION("int")
    {
        auto v1 = etl::variant<etl::monostate, int, float> { 42 };
        CHECK(etl::holds_alternative<int>(v1));
        CHECK(*etl::get_if<int>(&v1) == 42);

        auto i  = 143;
        auto v2 = etl::variant<etl::monostate, int, float> { i };
        CHECK(etl::holds_alternative<int>(v2));
        CHECK(*etl::get_if<int>(&v2) == 143);

        auto const ic = 99;
        auto v3       = etl::variant<etl::monostate, float, int> { ic };
        CHECK(etl::holds_alternative<int>(v3));
        CHECK(*etl::get_if<int>(&v3) == 99);
        CHECK(*etl::get_if<2>(&v3) == 99);
    }

    SECTION("float")
    {
        auto var = etl::variant<etl::monostate, int, float> { 143.0F };
        CHECK(etl::holds_alternative<float>(var));
        CHECK(*etl::get_if<float>(&var) == 143.0F);
    }

    SECTION("in_place_type_t")
    {
        struct Point {
            Point(float initX, float initY) : x { initX }, y { initY } { }
            float x { 0.0F };
            float y { 0.0F };
        };

        auto v1 = etl::variant<etl::monostate, int, Point> {
            etl::in_place_type<Point>,
            143.0F,
            42.0F,
        };

        CHECK(etl::holds_alternative<Point>(v1));
        CHECK(etl::get_if<Point>(&v1)->x == 143.0F);
        CHECK(etl::get_if<Point>(&v1)->y == 42.0F);

        auto v2 = etl::variant<etl::monostate, int, Point> {
            etl::in_place_index<2>,
            143.0F,
            42.0F,
        };

        CHECK(etl::holds_alternative<Point>(v2));
        CHECK(etl::get_if<Point>(&v2)->x == 143.0F);
        CHECK(etl::get_if<Point>(&v2)->y == 42.0F);
    }
}

TEST_CASE("variant: index", "[variant]")
{
    SECTION("0")
    {
        auto var
            = etl::variant<etl::monostate, int, float> { etl::monostate {} };
        CHECK(var.index() == 0);
    }

    SECTION("1")
    {
        auto var = etl::variant<etl::monostate, int, float> { 42 };
        CHECK(var.index() == 1);
    }

    SECTION("2")
    {
        auto var = etl::variant<etl::monostate, int, float> { 143.0F };
        CHECK(var.index() == 2);
    }

    SECTION("3")
    {
        auto var = etl::variant<etl::monostate, int, float, double> { 143.0 };
        CHECK(var.index() == 3);
    }
}

TEST_CASE("variant: operator=(variant const&)", "[variant]")
{
    auto var = etl::variant<etl::monostate, int, float> { 42 };
    CHECK(etl::holds_alternative<int>(var));
    CHECK(*etl::get_if<int>(&var) == 42);

    auto var2 = etl::variant<etl::monostate, int, float> { 143 };
    CHECK(etl::holds_alternative<int>(var2));
    CHECK(*etl::get_if<int>(&var2) == 143);
    var2 = var;
    CHECK(etl::holds_alternative<int>(var2));
    CHECK(*etl::get_if<int>(&var2) == 42);

    // var = 42.0f;
    // CHECK(etl::holds_alternative<float>(var));
    // CHECK(etl::get_if<int>(&var) == nullptr);
    // CHECK(*etl::get_if<float>(&var) == 42.0f);
}

TEST_CASE("variant: swap", "[variant]")
{
    auto l = etl::variant<int, float> { 42 };
    auto r = etl::variant<int, float> { 143 };
    CHECK(*etl::get_if<int>(&l) == 42);
    CHECK(*etl::get_if<int>(&r) == 143);

    l.swap(r);
    CHECK(*etl::get_if<int>(&l) == 143);
    CHECK(*etl::get_if<int>(&r) == 42);

    auto other = etl::variant<int, float> { 999.0F };
    l.swap(other);
    CHECK(etl::holds_alternative<int>(l));
    CHECK(etl::holds_alternative<float>(other));
}

TEST_CASE("variant: compare", "[variant]")
{
    CHECK_FALSE(etl::variant<int> { 41 } == etl::variant<int> { 42 });
    CHECK(etl::variant<int> { 42 } == etl::variant<int> { 42 });

    CHECK(etl::variant<int> { 41 } != etl::variant<int> { 42 });
    CHECK(etl::variant<int> { 41 } <= etl::variant<int> { 42 });
    CHECK(etl::variant<int> { 42 } >= etl::variant<int> { 42 });
    CHECK(etl::variant<int> { 42 } <= etl::variant<int> { 42 });

    CHECK_FALSE(etl::variant<int> { 41 } >= etl::variant<int> { 42 });
    CHECK_FALSE(etl::variant<int> { 42 } != etl::variant<int> { 42 });
    CHECK_FALSE(etl::variant<int> { 42 } < etl::variant<int> { 42 });
    CHECK_FALSE(etl::variant<int> { 42 } > etl::variant<int> { 42 });
}

TEST_CASE("variant: holds_alternative", "[variant]")
{
    SECTION("mutable")
    {
        auto var = etl::variant<etl::monostate, int, float, double> { 42 };
        CHECK(etl::holds_alternative<int>(var));
        CHECK_FALSE(etl::holds_alternative<etl::monostate>(var));
        CHECK_FALSE(etl::holds_alternative<float>(var));
        CHECK_FALSE(etl::holds_alternative<double>(var));
    }

    SECTION("const")
    {
        auto const var
            = etl::variant<etl::monostate, int, float, double> { 42.0F };
        CHECK(etl::holds_alternative<float>(var));
        CHECK_FALSE(etl::holds_alternative<int>(var));
        CHECK_FALSE(etl::holds_alternative<etl::monostate>(var));
        CHECK_FALSE(etl::holds_alternative<double>(var));
    }
}

TEST_CASE("variant: get_if", "[variant]")
{
    SECTION("mutable")
    {
        auto var = etl::variant<etl::monostate, int, float, double> { 42 };
        CHECK(etl::get_if<int>(&var) != nullptr);
        CHECK(*etl::get_if<int>(&var) == 42);

        CHECK(etl::get_if<etl::monostate>(&var) == nullptr);
        CHECK(etl::get_if<float>(&var) == nullptr);
        CHECK(etl::get_if<double>(&var) == nullptr);
    }

    SECTION("const")
    {
        auto const var
            = etl::variant<etl::monostate, int, float, double> { 42 };
        CHECK(etl::get_if<int>(&var) != nullptr);
        CHECK(*etl::get_if<int>(&var) == 42);

        CHECK(etl::get_if<etl::monostate>(&var) == nullptr);
        CHECK(etl::get_if<float>(&var) == nullptr);
        CHECK(etl::get_if<double>(&var) == nullptr);
    }
}

TEST_CASE("variant: variant_size", "[variant]")
{
    using t1 = etl::variant<etl::monostate>;
    using t2 = etl::variant<etl::monostate, int>;
    using t3 = etl::variant<etl::monostate, int, float>;
    using t4 = etl::variant<etl::monostate, int, float, double>;

    STATIC_REQUIRE(etl::variant_size_v<t1> == 1);
    STATIC_REQUIRE(etl::variant_size_v<t2> == 2);
    STATIC_REQUIRE(etl::variant_size_v<t3> == 3);
    STATIC_REQUIRE(etl::variant_size_v<t4> == 4);
}

TEST_CASE("variant: variant_alternative", "[variant]")
{
    using etl::is_same_v;
    using etl::monostate;
    using etl::variant;
    using etl::variant_alternative_t;

    using t1 = etl::variant<char>;
    STATIC_REQUIRE(is_same_v<etl::variant_alternative_t<0, t1>, char>);

    using t2 = etl::variant<char, int>;
    using t3 = etl::variant<char, int, float>;
    using t4 = etl::variant<char, int, float, double>;
    STATIC_REQUIRE(is_same_v<etl::variant_alternative_t<0, t2>, char>);
    STATIC_REQUIRE(is_same_v<etl::variant_alternative_t<0, t3>, char>);
    STATIC_REQUIRE(is_same_v<etl::variant_alternative_t<0, t4>, char>);
}