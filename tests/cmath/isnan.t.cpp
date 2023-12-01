// SPDX-License-Identifier: BSL-1.0

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::isnan(NAN));

    assert(!etl::isnan(T {0}));
    assert(!etl::isnan(T {1}));
    assert(!etl::isnan(INFINITY));
    assert(!etl::isnan(HUGE_VAL));
    assert(!etl::isnan(HUGE_VALF));
    assert(!etl::isnan(HUGE_VALL));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    assert(test<float>());
    assert(test<double>());
    assert(test<long double>());
    return 0;
}
