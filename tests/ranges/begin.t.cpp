// SPDX-License-Identifier: BSL-1.0

#include <etl/ranges.hpp>

#include <etl/array.hpp>
#include <etl/string_view.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto array = etl::to_array<T>({1, 2, 3});
    assert(etl::ranges::begin(array) == array.begin());
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
