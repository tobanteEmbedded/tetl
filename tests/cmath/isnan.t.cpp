// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::isnan(NAN));

    CHECK_FALSE(etl::isnan(T{0}));
    CHECK_FALSE(etl::isnan(T{1}));
    CHECK_FALSE(etl::isnan(INFINITY));
    CHECK_FALSE(etl::isnan(HUGE_VAL));
    CHECK_FALSE(etl::isnan(HUGE_VALF));
    CHECK_FALSE(etl::isnan(HUGE_VALL));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
