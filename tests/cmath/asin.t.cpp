// SPDX-License-Identifier: BSL-1.0

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/numbers.hpp"

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::asin(short { 0 }) == 0.0);
    assert(etl::asinl(0) == 0.0L);
    assert(etl::asin(T(0)) == T(0));

    assert(approx(etl::asin(T(0.5)), T(0.523599)));
    assert(approx(etl::asin(T(1)), T(1.5708)));

    assert(etl::isnan(etl::asin(T(2))));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    assert(test<float>());
    assert(test<double>());

    // TODO: Fix for long double
    // static_assert(test<long double>());
    // assert(test<long double>());
    return 0;
}
