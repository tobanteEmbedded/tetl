// SPDX-License-Identifier: BSL-1.0
#include <etl/cstdlib.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T, typename F>
constexpr auto test(F func) -> bool
{
    ASSERT_APPROX(func("0", nullptr), T(0));
    ASSERT_APPROX(func("10", nullptr), T(10));
    ASSERT_APPROX(func("100.0", nullptr), T(100));
    ASSERT_APPROX(func("143.0", nullptr), T(143));
    ASSERT_APPROX(func("1000.000", nullptr), T(1000));
    ASSERT_APPROX(func("10000", nullptr), T(10000));
    ASSERT_APPROX(func("999999.0", nullptr), T(999999));
    ASSERT_APPROX(func("9999999", nullptr), T(9999999));

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
    assert(test_all());
    static_assert(test_all());
    return 0;
}
