// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::back_inserter;
    using etl::set_difference;

    // empty ranges
    auto e1 = etl::static_vector<T, 4>{};
    auto e2 = etl::static_vector<T, 4>{};
    auto d1 = etl::array<T, 4>{};
    set_difference(begin(e1), end(e1), begin(e2), end(e2), begin(d1));
    assert(e1.empty());
    assert(e2.empty());
    assert(d1[0] == T{0});

    // cppreference.com example #1
    auto const v1 = etl::array{T(1), T(2), T(5), T(5), T(5), T(9)};
    auto const v2 = etl::array{T(2), T(5), T(7)};
    auto d2       = etl::static_vector<T, 4>{};
    set_difference(begin(v1), end(v1), begin(v2), end(v2), back_inserter(d2));
    assert((d2[0] == T{1}));
    assert((d2[1] == T{5}));
    assert((d2[2] == T{5}));
    assert((d2[3] == T{9}));

    // cppreference.com example #2
    // we want to know which orders "cut" between old and new states:
    etl::array<T, 4> oldOrders{T(1), T(2), T(5), T(9)};
    etl::array<T, 3> newOrders{T(2), T(5), T(7)};
    etl::static_vector<T, 2> cutOrders{};

    set_difference(
        oldOrders.begin(),
        oldOrders.end(),
        newOrders.begin(),
        newOrders.end(),
        back_inserter(cutOrders),
        etl::less{}
    );

    assert((oldOrders[0] == T{1}));
    assert((oldOrders[1] == T{2}));
    assert((oldOrders[2] == T{5}));
    assert((oldOrders[3] == T{9}));

    assert((newOrders[0] == T{2}));
    assert((newOrders[1] == T{5}));
    assert((newOrders[2] == T{7}));

    assert((cutOrders[0] == T{1}));
    assert((cutOrders[1] == T{9}));

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
    STATIC_CHECK(test_all());
    return 0;
}
