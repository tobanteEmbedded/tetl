// SPDX-License-Identifier: BSL-1.0

#include <etl/tuple.hpp>

#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>
#include <etl/warning.hpp>

#include "testing/testing.hpp"

namespace {
template <typename T>
struct Foo {
    constexpr Foo(T first, float second, bool third) : f{first}, s{second}, t{third} { }

    T f;
    float s;
    bool t;
};
} // namespace

template <typename T>
constexpr auto test() -> bool
{

    {
        etl::tuple<T, float> t1{T{1}, 2.0F};
        etl::ignore_unused(t1);
    }

    {
        auto t1 = etl::tuple<T, float>{T{1}, 2.0F};
        CHECK(etl::get<0>(t1) == T{1});
        CHECK(etl::get<1>(t1) == 2.0F);
    }

    {
        using etl::is_same_v;
        using etl::tuple;
        using etl::tuple_element_t;

        CHECK(is_same_v<tuple_element_t<0, tuple<T, float>>, T>);
        CHECK(is_same_v<tuple_element_t<1, tuple<T, float>>, float>);

        CHECK(is_same_v<tuple_element_t<0, tuple<T, int>>, T>);
        CHECK(is_same_v<tuple_element_t<1, tuple<T, int>>, int>);

        CHECK(is_same_v<tuple_element_t<0, tuple<double, T>>, double>);
        CHECK(is_same_v<tuple_element_t<1, tuple<double, T>>, T>);

        CHECK(is_same_v<tuple_element_t<0, tuple<int, T, float>>, int>);
        CHECK(is_same_v<tuple_element_t<1, tuple<int, T, float>>, T>);
        CHECK(is_same_v<tuple_element_t<2, tuple<int, T, float>>, float>);
    }

    {

        CHECK(etl::tuple_size_v<etl::tuple<T>> == 1);
        CHECK(etl::tuple_size_v<etl::tuple<T, float>> == 2);
        CHECK(etl::tuple_size_v<etl::tuple<T, float, char>> == 3);
        CHECK(etl::tuple_size_v<etl::tuple<T, float, char, int>> == 4);
    }

    {

        auto t1 = etl::make_tuple(T{1}, 'a', true);
        CHECK(etl::get<0>(t1) == T{1});
        CHECK(etl::get<1>(t1) == 'a');
        CHECK(etl::get<2>(t1) == true);
    }

    {
        using etl::make_from_tuple;
        using etl::make_tuple;

        auto foo = make_from_tuple<Foo<T>>(make_tuple(T{1}, 1.0F, true));
        CHECK(foo.f == T{1});
        CHECK(foo.s == 1.0F);
        CHECK(foo.t);
    }

    {
        using etl::is_same_v;
        using etl::tuple;
        using etl::tuple_element_t;

        CHECK(is_same_v<tuple_element_t<0, tuple<T, float>>, T>);
        CHECK(is_same_v<tuple_element_t<1, tuple<T, float>>, float>);

        CHECK(is_same_v<tuple_element_t<0, tuple<T, int>>, T>);
        CHECK(is_same_v<tuple_element_t<1, tuple<T, int>>, int>);

        CHECK(is_same_v<tuple_element_t<0, tuple<double, T>>, double>);
        CHECK(is_same_v<tuple_element_t<1, tuple<double, T>>, T>);

        CHECK(is_same_v<tuple_element_t<0, tuple<int, T, float>>, int>);
        CHECK(is_same_v<tuple_element_t<1, tuple<int, T, float>>, T>);
        CHECK(is_same_v<tuple_element_t<2, tuple<int, T, float>>, float>);

        CHECK(etl::tuple_size_v<tuple<short>> == 1);
        CHECK(etl::tuple_size_v<tuple<short, float>> == 2);
        CHECK(etl::tuple_size_v<tuple<short, float, T>> == 3);
        CHECK(etl::tuple_size_v<tuple<short, float, T, int>> == 4);

        auto t = etl::tuple<int, char>{1, 'a'};
        auto b = etl::tuple<int, char>{2, 'b'};
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

        CHECK(etl::get<1>(etl::tuple<int, char>{1, 'c'}) == 'c');
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
