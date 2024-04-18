// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::asin(short{0}) == 0.0);
    CHECK(etl::asinl(0) == 0.0L);
    CHECK(etl::asin(T(0)) == T(0));

    CHECK_APPROX(etl::asin(T(0.5)), T(0.523599));
    CHECK_APPROX(etl::asin(T(1)), T(1.5708));

    CHECK(etl::isnan(etl::asin(T(2))));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
