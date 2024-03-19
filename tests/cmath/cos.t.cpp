// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT(etl::cos(short{0}) == 1.0);
    ASSERT(etl::cosl(0) == 1.0L);
    ASSERT(etl::cos(T(0)) == T(1));

    ASSERT_APPROX(etl::cos(T(0)), T(1));
    ASSERT_APPROX(etl::cos(T(-1.5)), T(0.0707372));
    ASSERT_APPROX(etl::cos(T(1.5)), T(0.0707372));

    ASSERT_APPROX(etl::cos(T(11.1)), T(0.104236));
    ASSERT_APPROX(etl::cos(T(50)), T(0.964966));
    ASSERT_APPROX(etl::cos(T(150)), T(0.699251));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());
    return 0;
}
