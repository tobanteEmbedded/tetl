// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::isfinite(T(0)));
    CHECK(etl::isfinite(T(1)));

    CHECK_FALSE(etl::isfinite(INFINITY));
    CHECK_FALSE(etl::isfinite(HUGE_VAL));
    CHECK_FALSE(etl::isfinite(HUGE_VALF));
    CHECK_FALSE(etl::isfinite(HUGE_VALL));
    CHECK_FALSE(etl::isfinite(NAN));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
