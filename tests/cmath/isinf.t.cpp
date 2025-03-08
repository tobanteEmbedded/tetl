// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/limits.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::isinf(etl::numeric_limits<T>::infinity()));
    CHECK_FALSE(etl::isinf(etl::numeric_limits<T>::quiet_NaN()));
    CHECK_FALSE(etl::isinf(T{0}));
    CHECK_FALSE(etl::isinf(T{1}));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
