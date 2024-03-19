// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::isfinite(T(0)));
    CHECK(etl::isfinite(T(1)));

    CHECK(!etl::isfinite(INFINITY));
    CHECK(!etl::isfinite(HUGE_VAL));
    CHECK(!etl::isfinite(HUGE_VALF));
    CHECK(!etl::isfinite(HUGE_VALL));
    CHECK(!etl::isfinite(NAN));
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
