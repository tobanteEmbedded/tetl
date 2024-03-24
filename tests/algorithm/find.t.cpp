// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T(1));
        vec.push_back(T(2));
        vec.push_back(T(3));
        vec.push_back(T(4));

        auto const* result1 = etl::find(vec.cbegin(), vec.cend(), T(3));
        CHECK_FALSE(result1 == vec.cend());

        auto* result2 = etl::find(vec.begin(), vec.end(), T(5));
        CHECK(result2 == vec.end());
    }

    // empty range
    {
        auto data = etl::static_vector<T, 2>{};
        auto* res = etl::adjacent_find(data.begin(), data.end());
        CHECK(res == end(data));
    }

    // no match
    {
        auto const data = etl::array{T(0), T(1), T(2)};
        auto const* res = etl::adjacent_find(data.begin(), data.end());
        CHECK(res == end(data));
    }

    // match
    {
        auto const d1 = etl::array{T(0), T(0), T(2)};
        CHECK(etl::adjacent_find(begin(d1), end(d1)) == begin(d1));

        auto const d2 = etl::array{T(0), T(2), T(2)};
        CHECK(etl::adjacent_find(begin(d2), end(d2)) == begin(d2) + 1);
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T(1));
        vec.push_back(T(2));
        vec.push_back(T(3));
        vec.push_back(T(4));

        // find_if
        auto* res3 = etl::find_if(vec.begin(), vec.end(), [](auto& x) -> bool {
            return static_cast<bool>(static_cast<int>(x) % 2);
        });
        CHECK_FALSE(res3 == vec.end());

        auto* res4 = etl::find_if(vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x == 100); });
        CHECK(res4 == vec.end());
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T(1));
        vec.push_back(T(2));
        vec.push_back(T(3));
        vec.push_back(T(4));
        // find_if_not
        auto* result5 = etl::find_if_not(vec.begin(), vec.end(), [](auto& x) -> bool {
            return static_cast<bool>(static_cast<int>(x) % 2);
        });
        CHECK_FALSE(result5 == vec.end());

        auto* result6
            = etl::find_if_not(vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x == 100); });
        CHECK_FALSE(result6 == vec.end());

        auto* result7
            = etl::find_if_not(vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x != 100); });
        CHECK(result7 == vec.end());
    }

    // empty range
    {
        auto tc   = etl::static_vector<T, 16>{};
        auto s    = etl::array{T(2), T(42)};
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        CHECK(res == end(tc));
    }

    // empty matches
    {
        auto tc   = etl::static_vector<T, 16>{};
        auto s    = etl::static_vector<T, 16>{};
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        CHECK(res == end(tc));
    }

    // no matches
    {
        auto tc   = etl::array{T(0), T(1)};
        auto s    = etl::array{T(2), T(42)};
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        CHECK(res == end(tc));
    }

    // same ranges
    {
        auto tc   = etl::array{T(0), T(1)};
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(tc), end(tc));
        CHECK(res == begin(tc));
    }

    // matches
    {
        auto tc   = etl::array{T(0), T(1), T(42)};
        auto s    = etl::array{T(2), T(42)};
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        CHECK(res == end(tc) - 1);
        CHECK(*res == T(42));
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
