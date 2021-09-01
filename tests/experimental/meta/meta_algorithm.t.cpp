/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/experimental/meta/meta.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "testing.hpp"

namespace meta = etl::experimental::meta;

template <typename T>
constexpr auto test() -> bool
{
    {
        auto t       = meta::make_type_tuple<int, T, float, double>();
        auto counter = 0;
        meta::for_each(t, [&counter](auto x) {
            if (counter == 0) { assert(x == meta::type_c<int>); }
            if (counter == 1) { assert(x == meta::type_c<T>); }
            if (counter == 2) { assert(x == meta::type_c<float>); }
            if (counter == 3) { assert(x == meta::type_c<double>); }
            counter++;
        });

        assert(counter == 4);
    }
    {
        auto const sizeGreaterOr1 = [](auto t) {
            return etl::bool_constant<(
                sizeof(typename decltype(t)::name) >= 1)> {};
        };

        auto const sizeEqual16 = [](auto t) {
            constexpr auto is16bytes = sizeof(typename decltype(t)::name) == 16;
            return etl::bool_constant<is16bytes> {};
        };

        auto l = meta::make_type_tuple<T, long, long long>();
        assert((meta::all_of(l, sizeGreaterOr1)));
        assert((meta::none_of(l, sizeEqual16)));
        assert((meta::any_of(l, sizeGreaterOr1)));
    }
    {
        using etl::tuple_element_t;
        using meta::type_c;

        auto old    = etl::tuple<T, long, int>();
        using old_t = decltype(old);
        assert((type_c<tuple_element_t<0, old_t>> == type_c<T>));
        assert((type_c<tuple_element_t<1, old_t>> == type_c<long>));
        assert((type_c<tuple_element_t<2, old_t>> == type_c<int>));

        auto transformed = meta::transform(old, [](auto /*t*/) { return 0; });
        using new_t      = decltype(transformed);
        assert((type_c<tuple_element_t<0, new_t>> == type_c<int>));
        assert((type_c<tuple_element_t<1, new_t>> == type_c<int>));
        assert((type_c<tuple_element_t<2, new_t>> == type_c<int>));
    }
    {
        auto const isFalse = [](auto /*x*/) { return meta::false_c; };
        auto const isTrue  = [](auto /*x*/) { return meta::true_c; };

        auto t1 = meta::make_type_tuple<T>();
        assert((meta::count_if(t1, isFalse) == meta::int_c<0>));
        assert((meta::count_if(t1, isTrue) == meta::int_c<1>));

        auto t2 = meta::make_type_tuple<T, long>();
        assert((meta::count_if(t2, isFalse) == meta::int_c<0>));
        assert((meta::count_if(t2, isTrue) == meta::int_c<2>));

        auto t3 = meta::make_type_tuple<T, long, int>();
        assert((meta::count_if(t3, isFalse) == meta::int_c<0>));
        assert((meta::count_if(t3, isTrue) == meta::int_c<3>));

        auto const isFloat = [](auto x) {
            using type_t = typename decltype(x)::name;
            return meta::traits::is_floating_point(meta::type<type_t> {});
        };

        auto tf1 = meta::make_type_tuple<char, long, int, float>();
        assert((meta::count_if(tf1, isFloat) == meta::int_c<1>));

        auto tf2 = meta::make_type_tuple<char, long, int, float, double>();
        assert((meta::count_if(tf2, isFloat) == meta::int_c<2>));

        auto tf3 = meta::make_type_tuple<char, float, double, long double>();
        assert((meta::count_if(tf3, isFloat) == meta::int_c<3>));
    }

    {
        using etl::tuple_element_t;
        using meta::type_c;

        auto normal    = etl::tuple<T, long, int>();
        using normal_t = decltype(normal);
        assert((type_c<tuple_element_t<0, normal_t>> == type_c<T>));
        assert((type_c<tuple_element_t<1, normal_t>> == type_c<long>));
        assert((type_c<tuple_element_t<2, normal_t>> == type_c<int>));

        using reversed_t = decltype(meta::reverse(normal));
        assert((type_c<tuple_element_t<0, reversed_t>> == type_c<int>));
        assert((type_c<tuple_element_t<1, reversed_t>> == type_c<long>));
        assert((type_c<tuple_element_t<2, reversed_t>> == type_c<T>));
    }
    {
        using etl::tuple_size_v;
        auto original = etl::tuple<T, long, int>();
        assert((tuple_size_v<decltype(original)> == 3));
        assert((tuple_size_v<decltype(meta::remove_last(original))> == 2));
    }
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}