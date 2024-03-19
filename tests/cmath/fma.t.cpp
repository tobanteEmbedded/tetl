// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::fma(T(0), T(0), T(0)), T(0));
    CHECK_APPROX(etl::fma(T(0), T(1), T(0)), T(0));
    CHECK_APPROX(etl::fma(T(1), T(0), T(0)), T(0));
    CHECK_APPROX(etl::fma(T(1), T(1), T(0)), T(1));
    CHECK_APPROX(etl::fma(T(1), T(1), T(1)), T(2));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
