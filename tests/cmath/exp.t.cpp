// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::exp(T(0)), T(1));
    CHECK_APPROX(etl::exp(T(0.5)), T(1.64872));
    CHECK_APPROX(etl::exp(T(1)), T(2.71828));
    CHECK_APPROX(etl::exp(T(2)), T(7.38906));
    CHECK_APPROX(etl::exp(T(4)), T(54.5982));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    CHECK(test<float>());
    CHECK(test<double>());

    // TODO: Fix long double tests
    // static_assert(test<long double>());
    // CHECK(test<long double>());
    return 0;
}
