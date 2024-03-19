// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT_APPROX(etl::fma(T(0), T(0), T(0)), T(0));
    ASSERT_APPROX(etl::fma(T(0), T(1), T(0)), T(0));
    ASSERT_APPROX(etl::fma(T(1), T(0), T(0)), T(0));
    ASSERT_APPROX(etl::fma(T(1), T(1), T(0)), T(1));
    ASSERT_APPROX(etl::fma(T(1), T(1), T(1)), T(2));
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
