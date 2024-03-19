// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::cos(short{0}) == 1.0);
    CHECK(etl::cosl(0) == 1.0L);
    CHECK(etl::cos(T(0)) == T(1));

    CHECK_APPROX(etl::cos(T(0)), T(1));
    CHECK_APPROX(etl::cos(T(-1.5)), T(0.0707372));
    CHECK_APPROX(etl::cos(T(1.5)), T(0.0707372));

    CHECK_APPROX(etl::cos(T(11.1)), T(0.104236));
    CHECK_APPROX(etl::cos(T(50)), T(0.964966));
    CHECK_APPROX(etl::cos(T(150)), T(0.699251));

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
