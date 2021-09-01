/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/vector.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        assert((etl::max<T>(1, 5) == 5));
        assert((etl::max<T>(-10, 5) == 5));
        assert((etl::max<T>(-10, -20) == -10));

        auto cmp
            = [](auto x, auto y) { return etl::abs(x) < etl::abs(y) ? y : x; };
        assert((etl::max<T>(-10, -20, cmp) == -20));
        assert((etl::max<T>(10, -20, cmp) == -20));
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T(1));
        vec.push_back(T(2));
        vec.push_back(T(3));
        vec.push_back(T(4));
        vec.push_back(T(-5));

        auto const cmp
            = [](auto a, auto b) -> bool { return etl::abs(a) < etl::abs(b); };
        assert((*etl::max_element(vec.begin(), vec.end()) == T(4)));
        assert((*etl::max_element(vec.begin(), vec.end(), cmp) == T(-5)));
    }

    {
        assert((etl::min<T>(1, 5) == 1));
        assert((etl::min<T>(-10, 5) == -10));
        assert((etl::min<T>(-10, -20) == -20));

        auto cmp = [](auto x, auto y) { return etl::abs(x) < etl::abs(y); };
        assert((etl::min<T>(-10, -20, cmp) == -10));
        assert((etl::min<T>(10, -20, cmp) == 10));
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T { 1 });
        vec.push_back(T { 2 });
        vec.push_back(T { 3 });
        vec.push_back(T { 4 });
        vec.push_back(T { -5 });

        auto const cmp
            = [](auto a, auto b) -> bool { return etl::abs(a) < etl::abs(b); };
        assert((*etl::min_element(vec.begin(), vec.end()) == T { -5 }));
        assert((*etl::min_element(vec.begin(), vec.end(), cmp) == T { 1 }));
    }

    // in order
    {
        auto a   = T(1);
        auto b   = T(2);
        auto res = etl::minmax(a, b);
        assert((res.first == a));
        assert((res.second == b));
    }

    // reversed
    {
        auto a   = T(2);
        auto b   = T(1);
        auto res = etl::minmax(a, b);
        assert((res.first == b));
        assert((res.second == a));
    }

    // same
    {
        auto a   = T(42);
        auto b   = T(42);
        auto res = etl::minmax(a, b);
        assert((res.first == T(42)));
        assert((res.second == T(42)));
    }

    {
        auto test0 = etl::array { T(1), T(2), T(3) };
        auto res0  = etl::minmax_element(begin(test0), end(test0));
        assert((*res0.first == T(1)));
        assert((*res0.second == T(3)));

        auto test1 = etl::array { T(1), T(2), T(3), T(4), T(5), T(6) };
        auto res1  = etl::minmax_element(begin(test1), end(test1));
        assert((*res1.first == T(1)));
        assert((*res1.second == T(6)));

        auto test2 = etl::array { T(1), T(4), T(5), T(3), T(2) };
        auto res2  = etl::minmax_element(begin(test2), end(test2));
        assert((*res2.first == T(1)));
        assert((*res2.second == T(5)));

        auto test3 = etl::array { T(100), T(99), T(0) };
        auto res3  = etl::minmax_element(begin(test3), end(test3));
        assert((*res3.first == T(0)));
        assert((*res3.second == T(100)));
    }

    {
        assert((etl::clamp<T>(55, 0, 20) == T { 20 }));
        assert((etl::clamp<T>(55, 0, 100) == T { 55 }));
        assert((etl::clamp<T>(55, 0, 20) == T { 20 }));
        assert((etl::clamp<T>(55, 0, 100) == T { 55 }));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
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