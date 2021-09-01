/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::lower_bound;
    auto greater = etl::greater<>();

    // empty range
    {
        auto const vec = etl::static_vector<T, 4> {};
        assert(lower_bound(begin(vec), end(vec), T(0)) == end(vec));
        assert(lower_bound(begin(vec), end(vec), T(0), greater) == end(vec));
    }

    // single element
    {
        auto v = etl::static_vector<T, 4> {};
        v.push_back(T(0));
        assert(lower_bound(begin(v), end(v), T(0)) == begin(v));
        assert(lower_bound(begin(v), end(v), T(1)) == end(v));
        assert(lower_bound(begin(v), end(v), T(0), greater) == begin(v));
        assert(lower_bound(begin(v), end(v), T(1), greater) == begin(v));

        // reset
        v.clear();
        v.push_back(T(1));
        assert(lower_bound(begin(v), end(v), T(0)) == begin(v));
        assert(lower_bound(begin(v), end(v), T(1)) == begin(v));
        assert(lower_bound(begin(v), end(v), T(0), greater) == end(v));
        assert(lower_bound(begin(v), end(v), T(1), greater) == begin(v));
    }

    // multiple elements
    {
        auto const a = etl::array { T(0), T(1), T(2), T(3) };
        assert(lower_bound(begin(a), end(a), T(0)) == begin(a));
        assert(lower_bound(begin(a), end(a), T(1)) == begin(a) + 1);
        assert(lower_bound(begin(a), end(a), T(4)) == end(a));
        assert(lower_bound(begin(a), end(a), T(0), greater) == end(a));
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

    // TODO: Add constexpr tests
    // static_assert(test_all());

    return 0;
}