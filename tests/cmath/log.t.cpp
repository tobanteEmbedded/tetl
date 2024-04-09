// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::log(T(1)), T(0));
    CHECK_APPROX(etl::log(T(2)), T(0.69314718056));

    CHECK_APPROX(etl::logf(1.0F), 0.0F);
    CHECK_APPROX(etl::logf(2.0F), 0.69314718056F);

    CHECK_APPROX(etl::logl(1.0L), 0.0L);
    CHECK_APPROX(etl::logl(2.0L), 0.69314718056L);

    CHECK_APPROX(etl::log(1U), 0.0);
    CHECK_APPROX(etl::log(2U), 0.69314718056);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
