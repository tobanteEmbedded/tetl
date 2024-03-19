// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT(etl::acos(short{1}) == 0.0);
    ASSERT(etl::acosl(1) == 0.0L);
    ASSERT(etl::acos(T(1)) == T(0));

    ASSERT_APPROX(etl::acos(T(0.5)), T(1.047197551));
    ASSERT_APPROX(etl::acos(T(1)), T(0));

    // TODO: Fix long double tests
    if constexpr (not etl::is_same_v<T, long double>) {
        ASSERT_APPROX(etl::acos(T(0)), T(1.570796327));
        ASSERT(etl::isnan(etl::acos(T(2))));
    }

    return true;
}

auto main() -> int
{
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    return 0;
}
