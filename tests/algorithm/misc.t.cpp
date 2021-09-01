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
    using etl::back_inserter;
    using etl::begin;
    using etl::end;
    using etl::set_difference;

    // cppreference.com example #1
    {
        auto const v1 = etl::array { T(1), T(2), T(5), T(5), T(5), T(9) };
        auto const v2 = etl::array { T(2), T(5), T(7) };
        auto diff     = etl::static_vector<T, 4> {};

        set_difference(
            begin(v1), end(v1), begin(v2), end(v2), back_inserter(diff));

        assert((diff[0] == T { 1 }));
        assert((diff[1] == T { 5 }));
        assert((diff[2] == T { 5 }));
        assert((diff[3] == T { 9 }));
    }

    // cppreference.com example #2
    {
        // we want to know which orders "cut" between old and new states:
        etl::array<T, 4> oldOrders { T(1), T(2), T(5), T(9) };
        etl::array<T, 3> newOrders { T(2), T(5), T(7) };
        etl::static_vector<T, 2> cutOrders {};

        set_difference(oldOrders.begin(), oldOrders.end(), newOrders.begin(),
            newOrders.end(), back_inserter(cutOrders), etl::less<> {});

        assert((oldOrders[0] == T { 1 }));
        assert((oldOrders[1] == T { 2 }));
        assert((oldOrders[2] == T { 5 }));
        assert((oldOrders[3] == T { 9 }));

        assert((newOrders[0] == T { 2 }));
        assert((newOrders[1] == T { 5 }));
        assert((newOrders[2] == T { 7 }));

        assert((cutOrders[0] == T { 1 }));
        assert((cutOrders[1] == T { 9 }));
    }

    // cppreference.com example
    {
        etl::array<T, 8> v1 { T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8) };
        etl::array<T, 4> v2 { T(5), T(7), T(9), T(10) };
        etl::sort(v1.begin(), v1.end());
        etl::sort(v2.begin(), v2.end());

        etl::static_vector<T, 2> intersection {};
        etl::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(),
            etl::back_inserter(intersection));

        assert((intersection[0] == T { 5 }));
        assert((intersection[1] == T { 7 }));
    }

    // cppreference.com example
    {
        etl::array<T, 8> v1 { T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8) };
        etl::array<T, 4> v2 { T(5), T(7), T(9), T(10) };
        etl::sort(v1.begin(), v1.end());
        etl::sort(v2.begin(), v2.end());

        etl::static_vector<T, 8> symDifference {};
        etl::set_symmetric_difference(v1.begin(), v1.end(), v2.begin(),
            v2.end(), etl::back_inserter(symDifference));

        assert((symDifference[0] == T { 1 }));
        assert((symDifference[1] == T { 2 }));
        assert((symDifference[2] == T { 3 }));
        assert((symDifference[3] == T { 4 }));
        assert((symDifference[4] == T { 6 }));
        assert((symDifference[5] == T { 8 }));
        assert((symDifference[6] == T { 9 }));
        assert((symDifference[7] == T { 10 }));
    }

    // cppreference.com example #1
    {
        etl::array<T, 5> v1 = { T(1), T(2), T(3), T(4), T(5) };
        etl::array<T, 5> v2 = { T(3), T(4), T(5), T(6), T(7) };
        etl::static_vector<T, 7> dest;

        etl::set_union(
            begin(v1), end(v1), begin(v2), end(v2), back_inserter(dest));

        assert((dest[0] == T { 1 }));
        assert((dest[1] == T { 2 }));
        assert((dest[2] == T { 3 }));
        assert((dest[3] == T { 4 }));
        assert((dest[4] == T { 5 }));
        assert((dest[5] == T { 6 }));
        assert((dest[6] == T { 7 }));
    }

    // cppreference.com example #1
    {
        etl::array<T, 7> v1 = { T(1), T(2), T(3), T(4), T(5), T(5), T(5) };
        etl::array<T, 5> v2 = { T(3), T(4), T(5), T(6), T(7) };
        etl::static_vector<T, 9> dest;

        etl::set_union(
            begin(v1), end(v1), begin(v2), end(v2), back_inserter(dest));

        assert((dest[0] == T { 1 }));
        assert((dest[1] == T { 2 }));
        assert((dest[2] == T { 3 }));
        assert((dest[3] == T { 4 }));
        assert((dest[4] == T { 5 }));
        assert((dest[5] == T { 5 }));
        assert((dest[6] == T { 5 }));
        assert((dest[7] == T { 6 }));
        assert((dest[8] == T { 7 }));
    }

    // same data
    {
        auto const a = etl::array { T(1), T(2), T(3) };
        auto const b = etl::array { T(1), T(2), T(3) };
        assert((etl::is_permutation(begin(a), end(a), begin(b), end(b))));
    }

    // reverse data
    {
        auto const a = etl::array { T(1), T(2), T(3) };
        auto const b = etl::array { T(3), T(2), T(1) };
        assert((etl::is_permutation(begin(a), end(a), begin(b), end(b))));
    }

    // cppreference.com example
    {
        auto const a = etl::array { T(1), T(2), T(3), T(4), T(5) };
        auto const b = etl::array { T(3), T(5), T(4), T(1), T(2) };
        auto const c = etl::array { T(3), T(5), T(4), T(1), T(1) };
        assert((etl::is_permutation(begin(a), end(a), begin(b), end(b))));
        assert(!etl::is_permutation(begin(a), end(a), begin(c), end(c)));
    }

    {
        auto d = etl::array { T(1), T(2), T(3), T(4), T(5), T(6) };
        etl::shift_left(begin(d), end(d), 2);
        assert(d[0] == T(3));
        assert(d[1] == T(4));
        assert(d[2] == T(5));
        assert(d[3] == T(6));
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