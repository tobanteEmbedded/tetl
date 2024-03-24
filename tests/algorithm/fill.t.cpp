// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // c array
    {
        T data[4] = {};
        etl::fill(etl::begin(data), etl::end(data), T{42});
        CHECK(etl::all_of(etl::begin(data), etl::end(data), [](auto const& val) { return val == T{42}; }));
    }

    // etl::array
    {
        auto data = etl::array<T, 4>{};
        etl::fill(data.begin(), data.end(), T{42});
        CHECK(etl::all_of(data.begin(), data.end(), [](auto const& val) { return val == T{42}; }));
    }

    // c array
    {
        T t[4] = {};
        etl::fill_n(etl::begin(t), 4, T{42});
        CHECK(etl::all_of(etl::begin(t), etl::end(t), [](auto v) { return v == T(42); }));
    }

    // etl::array
    {
        auto tc0 = etl::array<T, 4>{};
        CHECK(etl::fill_n(begin(tc0), 0, T{42}) == begin(tc0));

        auto t1 = etl::array<T, 4>{};
        CHECK(etl::fill_n(begin(t1), 4, T{42}) == end(t1));
        CHECK(etl::all_of(begin(t1), end(t1), [](auto v) { return v == T(42); }));

        auto tc2   = etl::array<T, 4>{};
        auto* res2 = etl::fill_n(begin(tc2), 2, T{42});
        CHECK(res2 != begin(tc2));
        CHECK(res2 != end(tc2));
        CHECK(tc2[0] == T(42));
        CHECK(tc2[1] == T(42));
        CHECK(tc2[2] == T(0));
        CHECK(tc2[3] == T(0));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

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
