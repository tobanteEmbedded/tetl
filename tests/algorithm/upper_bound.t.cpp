// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::upper_bound;
    auto greater = etl::greater<>();

    // empty range
    {
        auto const d = etl::static_vector<T, 4>{};
        assert(upper_bound(begin(d), end(d), T(0)) == end(d));
        assert(upper_bound(begin(d), end(d), T(0), greater) == end(d));
    }

    // single element
    {
        auto d = etl::static_vector<T, 4>{};
        d.push_back(T(0));
        assert(upper_bound(begin(d), end(d), T(0)) == end(d));
        assert(upper_bound(begin(d), end(d), T(1)) == end(d));
        assert(upper_bound(begin(d), end(d), T(1), greater) == begin(d));
    }

    // multiple elements
    {
        auto const d = etl::array{T(0), T(1), T(2), T(3)};
        assert(upper_bound(begin(d), end(d), T(0)) == begin(d) + 1);
        assert(upper_bound(begin(d), end(d), T(1)) == begin(d) + 2);
        assert(upper_bound(begin(d), end(d), T(5)) == end(d));
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
