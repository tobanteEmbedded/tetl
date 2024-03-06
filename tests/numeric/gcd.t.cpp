// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    assert(etl::gcd(5, 10) == 5);
    assert(etl::gcd(10, 5) == 5);
    assert(etl::gcd(10, 5) == 5);

    assert(etl::gcd(30, 105) == 15);
    assert(etl::gcd(105, 30) == 15);
    assert(etl::gcd(105, 30) == 15);

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
