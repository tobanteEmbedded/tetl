/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"
#include "etl/iterator.hpp"
#include "etl/vector.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto arr = etl::array { T(11), T(1), T(12), T(13), T(2), T(3), T(4) };
        etl::partition(begin(arr), end(arr), [](auto n) { return n < 10; });
        assert(arr[0] == 1);
        assert(arr[1] == 2);
        assert(arr[2] == 3);
        assert(arr[3] == 4);
    }

    using etl::all_of;
    // empty range
    {
        auto src    = etl::static_vector<T, 5> {};
        auto dTrue  = etl::array<T, 5> {};
        auto dFalse = etl::array<T, 5> {};
        auto pred   = [](auto n) { return n < 10; };

        auto res = etl::partition_copy(
            begin(src), end(src), begin(dTrue), begin(dFalse), pred);
        assert(res.first == begin(dTrue));
        assert(res.second == begin(dFalse));
    }

    // range
    {
        auto src   = etl::array { T(11), T(1), T(12), T(13), T(2), T(3), T(4) };
        auto dTrue = etl::static_vector<T, 5> {};
        auto dFalse    = etl::static_vector<T, 5> {};
        auto predicate = [](auto n) { return n < 10; };

        auto falseIt = etl::back_inserter(dFalse);
        auto trueIt  = etl::back_inserter(dTrue);
        etl::partition_copy(begin(src), end(src), trueIt, falseIt, predicate);

        assert(dTrue.size() == 4);
        assert(all_of(begin(dTrue), end(dTrue), [](auto v) { return v < 10; }));
        assert(dFalse.size() == 3);
        assert((all_of(
            begin(dFalse), end(dFalse), [](auto v) { return v >= 10; })));
    }

    // empty range
    {
        auto data = etl::static_vector<T, 5> {};
        auto pred = [](auto v) { return v < 10; };
        auto* res = etl::partition_point(begin(data), end(data), pred);
        assert(res == end(data));
    }

    // range
    {
        auto data = etl::array { T(1), T(2), T(10), T(11) };
        auto pred = [](auto v) { return v < 10; };
        auto* res = etl::partition_point(begin(data), end(data), pred);
        assert(res != end(data));
        assert(*res == T(10));
    }

    {
        auto arr = etl::array { T(11), T(1), T(12), T(13), T(2), T(3), T(4) };

        etl::stable_partition(
            begin(arr), end(arr), [](auto n) { return n < 10; });
        assert(arr[0] == 1);
        assert(arr[1] == 2);
        assert(arr[2] == 3);
        assert(arr[3] == 4);
        assert(arr[4] == 11);
        assert(arr[5] == 12);
        assert(arr[6] == 13);
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

    // TODO: Fix
    // Fails on gcc-9, but passes clang-13 & gcc-11
    // static_assert(test_all());

    return 0;
}