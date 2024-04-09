// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::log2(T(1)), T(0));
    CHECK_APPROX(etl::log2(T(2)), T(1));
    CHECK_APPROX(etl::log2(T(4)), T(2));
    CHECK_APPROX(etl::log2(T(8)), T(3));

    CHECK_APPROX(etl::log2f(1.0F), 0.0F);
    CHECK_APPROX(etl::log2f(2.0F), 1.0F);
    CHECK_APPROX(etl::log2f(4.0F), 2.0F);
    CHECK_APPROX(etl::log2f(8.0F), 3.0F);

    CHECK_APPROX(etl::log2l(1.0L), 0.0L);
    CHECK_APPROX(etl::log2l(2.0L), 1.0L);
    CHECK_APPROX(etl::log2l(4.0L), 2.0L);
    CHECK_APPROX(etl::log2l(8.0L), 3.0L);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
