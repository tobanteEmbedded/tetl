// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::log10(T(1)), T(0));
    CHECK_APPROX(etl::log10(T(10)), T(1));
    CHECK_APPROX(etl::log10(T(100)), T(2));
    CHECK_APPROX(etl::log10(T(1000)), T(3));
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
