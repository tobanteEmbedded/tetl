// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::acos(short {1}) == 0.0);
    assert(etl::acosl(1) == 0.0L);
    assert(etl::acos(T(1)) == T(0));

    assert(approx(etl::acos(T(0.5)), T(1.047197551)));
    assert(approx(etl::acos(T(1)), T(0)));

    // TODO: Fix long double tests
    if constexpr (not etl::is_same_v<T, long double>) {
        assert(approx(etl::acos(T(0)), T(1.570796327)));
        assert(etl::isnan(etl::acos(T(2))));
    }

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    assert(test<float>());
    assert(test<double>());
    assert(test<long double>());
    return 0;
}
