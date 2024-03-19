// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT(etl::asin(short{0}) == 0.0);
    ASSERT(etl::asinl(0) == 0.0L);
    ASSERT(etl::asin(T(0)) == T(0));

    ASSERT_APPROX(etl::asin(T(0.5)), T(0.523599));
    ASSERT_APPROX(etl::asin(T(1)), T(1.5708));

    ASSERT(etl::isnan(etl::asin(T(2))));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    ASSERT(test<float>());
    ASSERT(test<double>());

    // TODO: Fix for long double
    // static_assert(test<long double>());
    // ASSERT(test<long double>());
    return 0;
}
