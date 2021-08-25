/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/tuple.hpp"

#include "etl/cstdint.hpp"     // for int16_t, int32_t, int64_t, int8_t
#include "etl/type_traits.hpp" // for is_same_v
#include "etl/warning.hpp"     // for ignore_unused

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("tuple: constructor", "[tuple]", bool, etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)

{
    etl::tuple<TestType, float> t1 { TestType { 1 }, 2.0F };
    etl::ignore_unused(t1);
}

TEMPLATE_TEST_CASE("tuple: get", "[tuple]", bool, etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    auto t1 = etl::tuple<TestType, float> { TestType { 1 }, 2.0F };
    CHECK(etl::get<0>(t1) == TestType { 1 });
    CHECK(etl::get<1>(t1) == 2.0F);
}

TEMPLATE_TEST_CASE("tuple: tuple_element<tuple>", "[tuple]", bool, etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_same_v;
    using etl::tuple;
    using etl::tuple_element_t;

    STATIC_REQUIRE(is_same_v<tuple_element_t<0, tuple<T, float>>, T>);
    STATIC_REQUIRE(is_same_v<tuple_element_t<1, tuple<T, float>>, float>);

    STATIC_REQUIRE(is_same_v<tuple_element_t<0, tuple<T, int>>, T>);
    STATIC_REQUIRE(is_same_v<tuple_element_t<1, tuple<T, int>>, int>);

    STATIC_REQUIRE(is_same_v<tuple_element_t<0, tuple<double, T>>, double>);
    STATIC_REQUIRE(is_same_v<tuple_element_t<1, tuple<double, T>>, T>);

    STATIC_REQUIRE(is_same_v<tuple_element_t<0, tuple<int, T, float>>, int>);
    STATIC_REQUIRE(is_same_v<tuple_element_t<1, tuple<int, T, float>>, T>);
    STATIC_REQUIRE(is_same_v<tuple_element_t<2, tuple<int, T, float>>, float>);
}

TEMPLATE_TEST_CASE("tuple: tuple_size<tuple>", "[tuple]", bool, etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::tuple_size_v<etl::tuple<T>> == 1);
    STATIC_REQUIRE(etl::tuple_size_v<etl::tuple<T, float>> == 2);
    STATIC_REQUIRE(etl::tuple_size_v<etl::tuple<T, float, char>> == 3);
    STATIC_REQUIRE(etl::tuple_size_v<etl::tuple<T, float, char, int>> == 4);
}

TEMPLATE_TEST_CASE("tuple: make_tuple", "[tuple]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    using T = TestType;

    auto t1 = etl::make_tuple(T { 1 }, 'a', true);
    REQUIRE(etl::get<0>(t1) == T { 1 });
    REQUIRE(etl::get<1>(t1) == 'a');
    REQUIRE(etl::get<2>(t1) == true);
}

template <typename T>
struct Foo {
    Foo(T first, float second, bool third)
        : f { first }, s { second }, t { third }
    {
    }

    T f;
    float s;
    bool t;
};

TEMPLATE_TEST_CASE("tuple: make_from_tuple", "[tuple]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::make_from_tuple;
    using etl::make_tuple;

    auto foo = make_from_tuple<Foo<T>>(make_tuple(T { 1 }, 1.0F, true));
    REQUIRE(foo.f == T { 1 });
    REQUIRE(foo.s == 1.0F);
    REQUIRE(foo.t == true);
}

TEMPLATE_TEST_CASE("tuple: tuple", "[tuple]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_same_v;
    using etl::tuple;
    using etl::tuple_element_t;

    CHECK((is_same_v<tuple_element_t<0, tuple<T, float>>, T>));
    CHECK((is_same_v<tuple_element_t<1, tuple<T, float>>, float>));

    CHECK((is_same_v<tuple_element_t<0, tuple<T, int>>, T>));
    CHECK((is_same_v<tuple_element_t<1, tuple<T, int>>, int>));

    CHECK((is_same_v<tuple_element_t<0, tuple<double, T>>, double>));
    CHECK((is_same_v<tuple_element_t<1, tuple<double, T>>, T>));

    CHECK((is_same_v<tuple_element_t<0, tuple<int, T, float>>, int>));
    CHECK((is_same_v<tuple_element_t<1, tuple<int, T, float>>, T>));
    CHECK((is_same_v<tuple_element_t<2, tuple<int, T, float>>, float>));

    CHECK((etl::tuple_size_v<tuple<short>> == 1));
    CHECK((etl::tuple_size_v<tuple<short, float>> == 2));
    CHECK((etl::tuple_size_v<tuple<short, float, T>> == 3));
    CHECK((etl::tuple_size_v<tuple<short, float, T, int>> == 4));

    auto t = etl::tuple<int, char> { 1, 'a' };
    auto b = etl::tuple<int, char> { 2, 'b' };
    CHECK(etl::get<0>(t) == 1);
    CHECK(etl::get<1>(t) == 'a');
    CHECK(etl::get<0>(b) == 2);
    CHECK(etl::get<1>(b) == 'b');
    CHECK(t == t);
    CHECK(b == b);
    CHECK(t != b);

    t.swap(b);
    CHECK(etl::get<0>(b) == 1);
    CHECK(etl::get<1>(b) == 'a');
    CHECK(etl::get<0>(t) == 2);
    CHECK(etl::get<1>(t) == 'b');
    CHECK(t == t);
    CHECK(b == b);
    CHECK(t != b);

    CHECK(etl::get<1>(etl::tuple<int, char> { 1, 'c' }) == 'c');
}
