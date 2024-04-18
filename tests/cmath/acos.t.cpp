// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::acos(short{1}) == 0.0);
    CHECK(etl::acosl(1) == 0.0L);
    CHECK(etl::acos(T(1)) == T(0));

    CHECK_APPROX(etl::acos(T(0)), T(1.570796327));
    CHECK_APPROX(etl::acos(T(0.5)), T(1.047197551));
    CHECK_APPROX(etl::acos(T(1)), T(0));
    CHECK(etl::isnan(etl::acos(T(2))));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
