// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::isinf(HUGE_VAL));
    CHECK(etl::isinf(HUGE_VALF));
    CHECK(etl::isinf(HUGE_VALL));
    CHECK(!etl::isinf(NAN));
    CHECK(!etl::isinf(T{0}));
    CHECK(!etl::isinf(T{1}));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
