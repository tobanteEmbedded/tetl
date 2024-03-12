// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::adjacent_difference;
    using etl::array;
    using etl::begin;
    using etl::end;
    using etl::next;
    using etl::plus;
    using etl::prev;

    // "cppreference.com example"
    {
        etl::array a{T(2), T(4), T(6)};
        adjacent_difference(a.begin(), a.end(), a.begin());
        assert(a[0] == 2);
        assert(a[1] == 2);
        assert(a[2] == 2);
    }

    // "cppreference.com example fibonacci"
    {
        etl::array<T, 4> a{T(1)};
        adjacent_difference(begin(a), prev(end(a)), next(begin(a)), plus<T>{});
        assert(a[0] == 1);
        assert(a[1] == 1);
        assert(a[2] == 2);
        assert(a[3] == 3);
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
