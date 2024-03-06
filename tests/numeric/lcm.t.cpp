// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::lcm(T {10}, T {5}) == T {10});
    assert(etl::lcm(T {4}, T {6}) == T {12});
    assert(etl::lcm(T {6}, T {4}) == T {12});
    assert(etl::lcm(T {30}, T {120}) == T {120});
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
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
