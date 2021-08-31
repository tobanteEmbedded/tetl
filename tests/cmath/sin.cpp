/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/numbers.hpp"

#include "helper.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::sin(short { 0 }) == 0.0);
    assert(etl::sinl(0) == 0.0L);
    assert(etl::sin(T(0)) == T(0));

    assert(approx(etl::sin(T(1)), T(0.841471)));
    assert(approx(etl::sin(static_cast<T>(etl::numbers::pi)), T(0)));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    assert(test<float>());

    static_assert(test<double>());
    assert(test<double>());

    static_assert(test<long double>());
    assert(test<long double>());
    return 0;
}