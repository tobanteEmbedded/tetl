/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/experimental/meta/meta.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace meta = etl::experimental::meta;

TEST_CASE("experimental/meta: int_c", "[experimental][meta]")
{
    using etl::integral_constant;
    using meta::int_c;
    using meta::type_c;

    STATIC_REQUIRE(int_c<0> + int_c<0> == int_c<0>);
    STATIC_REQUIRE(int_c<1> + int_c<1> == int_c<2>);
    STATIC_REQUIRE(int_c<1> + int_c<2> == int_c<3>);
    STATIC_REQUIRE(int_c<1> + int_c<3> == int_c<4>);

    // clang-format off
    STATIC_REQUIRE(type_c<decltype(int_c<1> + int_c<1>)> == type_c<integral_constant<int, 2>>);
    STATIC_REQUIRE(type_c<decltype(int_c<1> + int_c<2>)> == type_c<integral_constant<int, 3>>);
    STATIC_REQUIRE(type_c<decltype(int_c<1> + int_c<3>)> == type_c<integral_constant<int, 4>>);
    // clang-format on
}

TEST_CASE("experimental/meta: type_c", "[experimental][meta]")
{
    STATIC_REQUIRE(meta::type_c<int> == meta::type_c<int>);
    STATIC_REQUIRE(meta::type_c<int const> == meta::type_c<int const>);
    STATIC_REQUIRE(meta::type_c<int> != meta::type_c<int const>);

    // clang-format off
    STATIC_REQUIRE(etl::is_same_v<decltype(meta::type_c<int> == meta::type_c<int>), etl::bool_constant<true>>);
    STATIC_REQUIRE(etl::is_same_v<decltype(meta::type_c<int> != meta::type_c<int>), etl::bool_constant<false>>);

    STATIC_REQUIRE(decltype(meta::type_id(etl::declval<int const>())) {} == meta::type_c<int>);
    STATIC_REQUIRE(decltype(meta::type_id(etl::declval<int volatile>())) {} == meta::type_c<int>);
    STATIC_REQUIRE(decltype(meta::type_id(etl::declval<int const volatile>())) {} == meta::type_c<int>);
    // clang-format on
}

TEMPLATE_TEST_CASE("experimental/meta: make_type_tuple", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    constexpr auto t = meta::make_type_tuple<int, T>();
    STATIC_REQUIRE(etl::get<0>(t) == meta::type_c<int>);
    STATIC_REQUIRE(etl::get<1>(t) == meta::type_c<T>);
}

TEMPLATE_TEST_CASE("experimental/meta: size_of", "[experimental][meta]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    using T = TestType;
    using meta::size_c;
    using meta::size_of;
    using meta::type_c;

    REQUIRE(size_of(type_c<T>) == size_c<sizeof(T)>);
    REQUIRE(decltype(size_of(type_c<T>) == size_c<sizeof(T)>)::value);
}