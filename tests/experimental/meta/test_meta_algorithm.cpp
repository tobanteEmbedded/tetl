/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/experimental/meta/meta.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace meta = etl::experimental::meta;

TEMPLATE_TEST_CASE("experimental/meta: for_each", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto t       = meta::make_type_tuple<int, TestType, float, double>();
    auto counter = 0;
    meta::for_each(t, [&counter](auto x) {
        if (counter == 0) { REQUIRE(x == meta::type_c<int>); }
        if (counter == 1) { REQUIRE(x == meta::type_c<TestType>); }
        if (counter == 2) { REQUIRE(x == meta::type_c<float>); }
        if (counter == 3) { REQUIRE(x == meta::type_c<double>); }
        counter++;
    });

    REQUIRE(counter == 4);
}

TEMPLATE_TEST_CASE("experimental/meta: all_of,any_of,none_of",
    "[experimental][meta]", etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
    auto const sizeGreater1 = [](auto t) {
        return etl::bool_constant<(sizeof(typename decltype(t)::name) > 1)> {};
    };

    auto const sizeEqual16 = [](auto t) {
        constexpr auto is16bytes = sizeof(typename decltype(t)::name) == 16;
        return etl::bool_constant<is16bytes> {};
    };

    auto l = meta::make_type_tuple<TestType, long, long long>();
    STATIC_REQUIRE(meta::all_of(l, sizeGreater1));
    STATIC_REQUIRE(meta::none_of(l, sizeEqual16));
    STATIC_REQUIRE(meta::any_of(l, sizeGreater1));
}

TEMPLATE_TEST_CASE("experimental/meta: transform", "[experimental][meta]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double)
{
    using T = TestType;
    using etl::tuple_element_t;
    using meta::type_c;

    auto old    = etl::tuple<T, long, int>();
    using old_t = decltype(old);
    STATIC_REQUIRE(type_c<tuple_element_t<0, old_t>> == type_c<T>);
    STATIC_REQUIRE(type_c<tuple_element_t<1, old_t>> == type_c<long>);
    STATIC_REQUIRE(type_c<tuple_element_t<2, old_t>> == type_c<int>);

    auto transformed = meta::transform(old, [](auto /*t*/) { return 0; });
    using new_t      = decltype(transformed);
    STATIC_REQUIRE(type_c<tuple_element_t<0, new_t>> == type_c<int>);
    STATIC_REQUIRE(type_c<tuple_element_t<1, new_t>> == type_c<int>);
    STATIC_REQUIRE(type_c<tuple_element_t<2, new_t>> == type_c<int>);
}

TEMPLATE_TEST_CASE("experimental/meta: count_if", "[experimental][meta]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    auto isFloat = [](auto x) {
        return meta::traits::is_floating_point(meta::type_id(x));
    };

    auto t0 = meta::make_type_tuple<TestType, long, int>();
    STATIC_REQUIRE(meta::count_if(t0, isFloat) == meta::int_c<0>);

    // auto t1 = meta::make_type_tuple<TestType, long, int, float>();
    // STATIC_REQUIRE(meta::count_if(t1, isFloat) == meta::int_c<1>);

    // auto t2 = meta::make_type_tuple<TestType, long, int, float, double>();
    // REQUIRE(meta::count_if(t2, isFloat) == meta::int_c<2>);

    // auto t3 = meta::make_type_tuple<TestType, float, double, long double>();
    // REQUIRE(meta::count_if(t3, isFloat) == meta::int_c<3>);
}
