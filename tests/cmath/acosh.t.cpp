/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/numbers.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::acosh(short { 1 }) == 0.0);
    assert(etl::acoshl(1) == 0.0L);
    assert(etl::acosh(T(1)) == T(0));

    assert(approx(etl::acosh(T(2)), T(1.31696)));
    assert(approx(etl::acosh(T(3)), T(1.76275)));

    assert(etl::isnan(etl::acosh(T(0))));
    assert(etl::isnan(etl::acosh(T(0.5))));

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