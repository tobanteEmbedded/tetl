// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::acosh(short{1}) == 0.0);
    CHECK(etl::acoshl(1) == 0.0L);
    CHECK(etl::acosh(T(1)) == T(0));

    CHECK(etl::isnan(etl::acosh(T(0))));
    CHECK(etl::isnan(etl::acosh(T(0.5))));
    CHECK_APPROX(etl::acosh(T(2)), T(1.31696));
    CHECK_APPROX(etl::acosh(T(3)), T(1.76275));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
