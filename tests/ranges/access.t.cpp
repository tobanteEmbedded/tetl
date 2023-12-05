// SPDX-License-Identifier: BSL-1.0

#include <etl/ranges.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/memory.hpp>
#include <etl/string_view.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        T data[2] {T(1), T(2)};
        assert(etl::ranges::begin(data) == etl::addressof(data[0]));
        assert(etl::ranges::end(data) == etl::next(etl::addressof(data[0]), 2));
    }

    {
        auto data = etl::to_array<T>({1, 2, 3});
        assert(etl::ranges::begin(data) == data.begin());
        assert(etl::ranges::end(data) == data.end());
    }

    return true;
}

constexpr auto test_all() -> bool
{
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
