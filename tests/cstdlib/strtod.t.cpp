// SPDX-License-Identifier: BSL-1.0
#include <etl/cstdlib.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T, typename F>
constexpr auto test(F func) -> bool
{
    CHECK_APPROX(func("0", nullptr), T(0));
    CHECK_APPROX(func("10", nullptr), T(10));
    CHECK_APPROX(func("100.0", nullptr), T(100));
    CHECK_APPROX(func("143.0", nullptr), T(143));
    CHECK_APPROX(func("1000.000", nullptr), T(1000));
    CHECK_APPROX(func("10000", nullptr), T(10000));
    CHECK_APPROX(func("999999.0", nullptr), T(999999));
    CHECK_APPROX(func("9999999", nullptr), T(9999999));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<float>(etl::strtof));
    assert(test<double>(etl::strtod));
    assert(test<long double>(etl::strtold));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
