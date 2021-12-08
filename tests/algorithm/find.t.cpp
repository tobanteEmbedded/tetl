/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/vector.hpp"

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

        const auto* result1 = etl::find(vec.cbegin(), vec.cend(), T(3));
        assert(!(result1 == vec.cend()));

        auto* result2 = etl::find(vec.begin(), vec.end(), T(5));
        assert(result2 == vec.end());
    }

    // empty range
    {
        auto data = etl::static_vector<T, 2> {};
        auto* res = etl::adjacent_find(begin(data), end(data));
        assert(res == end(data));
    }

    // no match
    {
        auto const data = etl::array { T(0), T(1), T(2) };
        auto const* res = etl::adjacent_find(begin(data), end(data));
        assert(res == end(data));
    }

    // match
    {
        auto const d1 = etl::array { T(0), T(0), T(2) };
        assert(etl::adjacent_find(begin(d1), end(d1)) == begin(d1));

        auto const d2 = etl::array { T(0), T(2), T(2) };
        assert(etl::adjacent_find(begin(d2), end(d2)) == begin(d2) + 1);
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T(1));
        vec.push_back(T(2));
        vec.push_back(T(3));
        vec.push_back(T(4));

        // find_if
        auto* res3 = etl::find_if(
            vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(static_cast<int>(x) % 2); });
        assert(!(res3 == vec.end()));

        auto* res4 = etl::find_if(vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x == 100); });
        assert(res4 == vec.end());
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(T(1));
        vec.push_back(T(2));
        vec.push_back(T(3));
        vec.push_back(T(4));
        // find_if_not
        auto* result5 = etl::find_if_not(
            vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(static_cast<int>(x) % 2); });
        assert(!(result5 == vec.end()));

        auto* result6
            = etl::find_if_not(vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x == 100); });
        assert(!(result6 == vec.end()));

        auto* result7
            = etl::find_if_not(vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x != 100); });
        assert(result7 == vec.end());
    }

    // empty range
    {
        auto tc   = etl::static_vector<T, 16> {};
        auto s    = etl::array { T(2), T(42) };
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        assert(res == end(tc));
    }

    // empty matches
    {
        auto tc   = etl::static_vector<T, 16> {};
        auto s    = etl::static_vector<T, 16> {};
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        assert(res == end(tc));
    }

    // no matches
    {
        auto tc   = etl::array { T(0), T(1) };
        auto s    = etl::array { T(2), T(42) };
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        assert(res == end(tc));
    }

    // same ranges
    {
        auto tc   = etl::array { T(0), T(1) };
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(tc), end(tc));
        assert(res == begin(tc));
    }

    // matches
    {
        auto tc   = etl::array { T(0), T(1), T(42) };
        auto s    = etl::array { T(2), T(42) };
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(s), end(s));
        assert(res == end(tc) - 1);
        assert(*res == T(42));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
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