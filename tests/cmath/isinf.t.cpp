// SPDX-License-Identifier: BSL-1.0

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::isinf(HUGE_VAL));
    assert(etl::isinf(HUGE_VALF));
    assert(etl::isinf(HUGE_VALL));
    assert(!etl::isinf(NAN));
    assert(!etl::isinf(T {0}));
    assert(!etl::isinf(T {1}));
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
