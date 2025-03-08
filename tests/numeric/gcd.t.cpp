// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include "testing/testing.hpp"

static constexpr auto test() -> bool
{
    CHECK(etl::gcd(5, 10) == 5);
    CHECK(etl::gcd(10, 5) == 5);
    CHECK(etl::gcd(10, 5) == 5);

    CHECK(etl::gcd(30, 105) == 15);
    CHECK(etl::gcd(105, 30) == 15);
    CHECK(etl::gcd(105, 30) == 15);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
