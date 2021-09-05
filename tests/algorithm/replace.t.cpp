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
    // empty range
    {
        auto data = etl::static_vector<T, 4> {};
        etl::replace(begin(data), end(data), T(0), T(1));
        assert(data.empty());
    }

    // range
    {
        auto data = etl::array { T(1), T(2), T(2), T(3) };
        etl::replace(begin(data), end(data), T(2), T(1));
        assert(etl::count(begin(data), end(data), T(2)) == 0);
        assert(etl::count(begin(data), end(data), T(1)) == 3);
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