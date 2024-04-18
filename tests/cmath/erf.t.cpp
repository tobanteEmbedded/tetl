// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::erf(T(0)), T(0));
    CHECK_APPROX(etl::erf(T(0.5)), T(0.5204998778));
    CHECK_APPROX(etl::erf(T(1)), T(0.8427007929));
    CHECK_APPROX(etl::erf(T(2)), T(0.995322265));
    CHECK_APPROX(etl::erf(T(4)), T(0.9999999846));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
