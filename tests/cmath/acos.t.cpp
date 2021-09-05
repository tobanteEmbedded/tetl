/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/numbers.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::acos(short { 1 }) == 0.0);
    assert(etl::acosl(1) == 0.0L);
    assert(etl::acos(T(1)) == T(0));

    assert(approx(etl::acos(T(0)), T(1.5708)));
    assert(approx(etl::acos(T(0.5)), T(1.0472)));
    assert(approx(etl::acos(T(1)), T(0)));

    assert(etl::isnan(etl::acos(T(2))));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    assert(test<float>());

    static_assert(test<double>());
    assert(test<double>());

    return 0;
}