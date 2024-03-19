// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cmath.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        CHECK(etl::max<T>(1, 5) == 5);
        CHECK(etl::max<T>(-10, 5) == 5);
        CHECK(etl::max<T>(-10, -20) == -10);

        auto cmp = [](auto x, auto y) { return etl::abs(x) < etl::abs(y); };
        CHECK(etl::max<T>(-10, -20, cmp) == -20);
        CHECK(etl::max<T>(10, -20, cmp) == -20);
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T(1));
        vec.push_back(T(2));
        vec.push_back(T(3));
        vec.push_back(T(4));
        vec.push_back(T(-5));

        auto const cmp = [](auto a, auto b) -> bool { return etl::abs(a) < etl::abs(b); };
        CHECK(*etl::max_element(vec.begin(), vec.end()) == T(4));
        CHECK(*etl::max_element(vec.begin(), vec.end(), cmp) == T(-5));
    }

    {
        CHECK(etl::min<T>(1, 5) == 1);
        CHECK(etl::min<T>(-10, 5) == -10);
        CHECK(etl::min<T>(-10, -20) == -20);

        auto cmp = [](auto x, auto y) { return etl::abs(x) < etl::abs(y); };
        CHECK(etl::min<T>(-10, -20, cmp) == -10);
        CHECK(etl::min<T>(10, -20, cmp) == 10);
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T{1});
        vec.push_back(T{2});
        vec.push_back(T{3});
        vec.push_back(T{4});
        vec.push_back(T{-5});

        auto const cmp = [](auto a, auto b) -> bool { return etl::abs(a) < etl::abs(b); };
        CHECK(*etl::min_element(vec.begin(), vec.end()) == T{-5});
        CHECK(*etl::min_element(vec.begin(), vec.end(), cmp) == T{1});
    }

    // in order
    {
        auto a   = T(1);
        auto b   = T(2);
        auto res = etl::minmax(a, b);
        CHECK(res.first == a);
        CHECK(res.second == b);
    }

    // reversed
    {
        auto a   = T(2);
        auto b   = T(1);
        auto res = etl::minmax(a, b);
        CHECK(res.first == b);
        CHECK(res.second == a);
    }

    // same
    {
        auto a   = T(42);
        auto b   = T(42);
        auto res = etl::minmax(a, b);
        CHECK(res.first == T(42));
        CHECK(res.second == T(42));
    }

    {
        CHECK(etl::clamp<T>(55, 0, 20) == T{20});
        CHECK(etl::clamp<T>(55, 0, 100) == T{55});
        CHECK(etl::clamp<T>(55, 0, 20) == T{20});
        CHECK(etl::clamp<T>(55, 0, 100) == T{55});
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
