/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/numeric.hpp"

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    assert(etl::gcd(5, 10) == 5);
    assert(etl::gcd(10, 5) == 5);
    assert(etl::gcd(10, 5) == 5);

    assert(etl::gcd(30, 105) == 15);
    assert(etl::gcd(105, 30) == 15);
    assert(etl::gcd(105, 30) == 15);

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
