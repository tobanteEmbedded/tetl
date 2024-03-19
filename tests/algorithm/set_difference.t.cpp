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
    CHECK(e1.empty());
    CHECK(e2.empty());
    CHECK(d1[0] == T{0});

    // cppreference.com example #1
    auto const v1 = etl::array{T(1), T(2), T(5), T(5), T(5), T(9)};
    auto const v2 = etl::array{T(2), T(5), T(7)};
    auto d2       = etl::static_vector<T, 4>{};
    set_difference(begin(v1), end(v1), begin(v2), end(v2), back_inserter(d2));
    CHECK(d2[0] == T{1});
    CHECK(d2[1] == T{5});
    CHECK(d2[2] == T{5});
    CHECK(d2[3] == T{9});

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

    CHECK(oldOrders[0] == T{1});
    CHECK(oldOrders[1] == T{2});
    CHECK(oldOrders[2] == T{5});
    CHECK(oldOrders[3] == T{9});

    CHECK(newOrders[0] == T{2});
    CHECK(newOrders[1] == T{5});
    CHECK(newOrders[2] == T{7});

    CHECK(cutOrders[0] == T{1});
    CHECK(cutOrders[1] == T{9});

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

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
