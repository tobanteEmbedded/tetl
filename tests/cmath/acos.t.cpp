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

    CHECK_APPROX(etl::acos(T(0.5)), T(1.047197551));
    CHECK_APPROX(etl::acos(T(1)), T(0));

    // TODO: Fix long double tests
    if constexpr (not etl::is_same_v<T, long double>) {
        CHECK_APPROX(etl::acos(T(0)), T(1.570796327));
        CHECK(etl::isnan(etl::acos(T(2))));
    }

    return true;
}

auto main() -> int
{
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    return 0;
}
