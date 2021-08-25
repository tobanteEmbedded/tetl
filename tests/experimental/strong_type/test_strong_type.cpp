/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/experimental/strong_type/strong_type.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("experimental/strong_type: construct", "[experimental]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using namespace etl::experimental;
    using Kilogram = strong_type<TestType, struct Kilogram_tag>;
    auto kilo      = Kilogram {};
    kilo           = Kilogram { 0 };

    REQUIRE(kilo.raw_value() == TestType { 0 });
}

TEMPLATE_TEST_CASE("experimental/strong_type: type_traits", "[experimental]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using namespace etl::experimental;

    using Kilogram = strong_type<TestType, struct Kilogram_tag>;

    STATIC_REQUIRE(sizeof(Kilogram) == sizeof(typename Kilogram::value_type));

    STATIC_REQUIRE(etl::is_constructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_trivially_constructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_constructible_v<Kilogram>);

    STATIC_REQUIRE(etl::is_destructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_trivially_destructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_destructible_v<Kilogram>);

    STATIC_REQUIRE(etl::is_assignable_v<Kilogram, Kilogram>);
    STATIC_REQUIRE(etl::is_trivially_assignable_v<Kilogram, Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_assignable_v<Kilogram, Kilogram>);

    STATIC_REQUIRE(etl::is_copy_constructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_trivially_copy_constructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_copy_constructible_v<Kilogram>);

    STATIC_REQUIRE(etl::is_copy_assignable_v<Kilogram>);
    STATIC_REQUIRE(etl::is_trivially_copy_assignable_v<Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_copy_assignable_v<Kilogram>);

    STATIC_REQUIRE(etl::is_move_constructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_trivially_move_constructible_v<Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_move_constructible_v<Kilogram>);

    STATIC_REQUIRE(etl::is_move_assignable_v<Kilogram>);
    STATIC_REQUIRE(etl::is_trivially_move_assignable_v<Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_move_assignable_v<Kilogram>);

    STATIC_REQUIRE(etl::is_swappable_v<Kilogram>);
    STATIC_REQUIRE(etl::is_nothrow_swappable_v<Kilogram>);

    STATIC_REQUIRE(etl::is_trivial_v<Kilogram>);

    STATIC_REQUIRE(!etl::has_virtual_destructor_v<Kilogram>);
}

TEMPLATE_TEST_CASE("experimental/strong_type: skill::addable", "[experimental]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using namespace etl::experimental;

    using Kilo     = strong_type<TestType, struct Kilo_tag, skill::addable>;
    auto const lhs = Kilo(1);
    auto const rhs = Kilo(2);
    auto const sum = lhs + rhs;
    REQUIRE(sum.raw_value() == TestType(3));
}

TEMPLATE_TEST_CASE("experimental/strong_type: skill::subtractable",
    "[experimental]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
    etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
    long double)
{
    using namespace etl::experimental;

    using Kilo = strong_type<TestType, struct Kilo_tag, skill::subtractable>;
    auto const lhs = Kilo(2);
    auto const rhs = Kilo(1);
    auto const sum = lhs - rhs;
    REQUIRE(sum.raw_value() == TestType(1));
}

TEMPLATE_TEST_CASE("experimental/strong_type: skill::multipliable",
    "[experimental]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
    etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
    long double)
{
    using namespace etl::experimental;

    using Kilo = strong_type<TestType, struct Kilo_tag, skill::multipliable>;
    auto const lhs = Kilo(2);
    auto const rhs = Kilo(2);
    auto const sum = lhs * rhs;
    REQUIRE(sum.raw_value() == TestType(4));
}

TEMPLATE_TEST_CASE("experimental/strong_type: skill::divisible",
    "[experimental]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
    etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
    long double)
{
    using namespace etl::experimental;

    using Kilo     = strong_type<TestType, struct Kilo_tag, skill::divisible>;
    auto const lhs = Kilo(2);
    auto const rhs = Kilo(2);
    auto const sum = lhs / rhs;
    REQUIRE(sum.raw_value() == TestType(1));
}

TEMPLATE_TEST_CASE("experimental/strong_type: skill::comparable",
    "[experimental]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
    etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
    long double)
{
    using namespace etl::experimental;

    using Hertz    = strong_type<TestType, struct Hertz_tag, skill::comparable>;
    auto const lhs = Hertz { typename Hertz::value_type(44) };
    auto const rhs = Hertz { typename Hertz::value_type(48) };

    REQUIRE(lhs.raw_value() == typename Hertz::value_type(44));
    REQUIRE(rhs.raw_value() == typename Hertz::value_type(48));

    REQUIRE(lhs < rhs);
    REQUIRE(!(lhs > rhs));

    REQUIRE(lhs <= rhs);
    REQUIRE(!(lhs >= rhs));

    REQUIRE(lhs != rhs);
    REQUIRE(!(lhs == rhs));
}