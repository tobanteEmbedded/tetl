// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT_APPROX(etl::log10(T(1)), T(0));
    ASSERT_APPROX(etl::log10(T(10)), T(1));
    ASSERT_APPROX(etl::log10(T(100)), T(2));
    ASSERT_APPROX(etl::log10(T(1000)), T(3));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());
    return 0;
}
