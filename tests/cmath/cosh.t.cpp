// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::cosh(short {0}) == 1.0);
    assert(etl::cosh(T(0)) == T(1));

    assert(approx(etl::cosh(T(0)), T(1)));
    assert(approx(etl::cosh(T(0.5)), T(1.127625965)));
    assert(approx(etl::cosh(T(1)), T(1.543080635)));
    assert(approx(etl::cosh(T(2)), T(3.762195691)));
    assert(approx(etl::cosh(T(4)), T(27.30823284)));
    assert(approx(etl::cosh(T(8)), T(1490.479161)));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    assert(test<float>());
    assert(test<double>());

    // TODO
    // static_assert(test<long double>());
    // assert(test<long double>());
    // assert(etl::coshl(0) == 1.0L);
    return 0;
}
