/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdlib.hpp"

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T, typename F>
constexpr auto test(F func) -> bool
{

    assert(approx(func("0", nullptr), T(0)));
    assert(approx(func("10", nullptr), T(10)));
    assert(approx(func("100.0", nullptr), T(100)));
    assert(approx(func("143.0", nullptr), T(143)));
    assert(approx(func("1000.000", nullptr), T(1000)));
    assert(approx(func("10000", nullptr), T(10000)));
    assert(approx(func("999999.0", nullptr), T(999999)));
    assert(approx(func("9999999", nullptr), T(9999999)));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<float>(etl::strtof));
    assert(test<double>(etl::strtod));
    assert(test<long double>(etl::strtold));
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
