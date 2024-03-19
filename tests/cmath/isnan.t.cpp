// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::isnan(NAN));

    CHECK(!etl::isnan(T{0}));
    CHECK(!etl::isnan(T{1}));
    CHECK(!etl::isnan(INFINITY));
    CHECK(!etl::isnan(HUGE_VAL));
    CHECK(!etl::isnan(HUGE_VALF));
    CHECK(!etl::isnan(HUGE_VALL));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return 0;
}
