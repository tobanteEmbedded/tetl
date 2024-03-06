// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(approx(etl::exp(T(0)), T(1)));
    assert(approx(etl::exp(T(0.5)), T(1.64872)));
    assert(approx(etl::exp(T(1)), T(2.71828)));
    assert(approx(etl::exp(T(2)), T(7.38906)));
    assert(approx(etl::exp(T(4)), T(54.5982)));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    assert(test<float>());
    assert(test<double>());

    // TODO: Fix long double tests
    // static_assert(test<long double>());
    // assert(test<long double>());
    return 0;
}
