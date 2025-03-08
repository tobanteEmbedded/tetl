// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_APPROX(etl::floor(T(0)), T(0));
    CHECK_APPROX(etl::floor(T(1)), T(1));
    CHECK_APPROX(etl::floor(T(2)), T(2));
    CHECK_APPROX(etl::floor(T(-2)), T(-2));

    CHECK_APPROX(etl::floor(T(0.1)), T(0));
    CHECK_APPROX(etl::floor(T(0.2)), T(0));
    CHECK_APPROX(etl::floor(T(0.3)), T(0));
    CHECK_APPROX(etl::floor(T(0.4)), T(0));
    CHECK_APPROX(etl::floor(T(0.5)), T(0));
    CHECK_APPROX(etl::floor(T(0.6)), T(0));
    CHECK_APPROX(etl::floor(T(0.7)), T(0));
    CHECK_APPROX(etl::floor(T(0.8)), T(0));
    CHECK_APPROX(etl::floor(T(0.9)), T(0));
    CHECK_APPROX(etl::floor(T(0.99)), T(0));
    CHECK_APPROX(etl::floor(T(1.01)), T(1));

    CHECK_APPROX(etl::floor(T(-0.1)), T(-1));
    CHECK_APPROX(etl::floor(T(-0.2)), T(-1));

    CHECK_APPROX(etl::floorf(0.1F), 0.0F);
    CHECK_APPROX(etl::floorf(0.2F), 0.0F);
    CHECK_APPROX(etl::floorf(0.3F), 0.0F);
    CHECK_APPROX(etl::floorf(1.3F), 1.0F);

    CHECK_APPROX(etl::floorl(0.1L), 0.0L);
    CHECK_APPROX(etl::floorl(0.2L), 0.0L);
    CHECK_APPROX(etl::floorl(0.3L), 0.0L);
    CHECK_APPROX(etl::floorl(1.3L), 1.0L);

    CHECK_APPROX(etl::floor(0U), 0.0);
    CHECK_APPROX(etl::floor(1U), 1.0);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
