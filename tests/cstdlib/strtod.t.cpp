/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdlib.hpp"

#include "testing.hpp"

constexpr auto test() -> bool
{
    // "strtof"
    {
        assert((approx(0.0F, etl::strtof("0"))));
        assert((approx(10.0F, etl::strtof("10"))));
        assert((approx(100.0F, etl::strtof("100.0"))));
        assert((approx(1000.0F, etl::strtof("1000.000"))));
        assert((approx(10000.0F, etl::strtof("10000"))));
        assert((approx(999999.0F, etl::strtof("999999.0"))));
        assert((approx(9999999.0F, etl::strtof("9999999"))));
    }

    // "strtod"
    {
        assert((approx(0.0, etl::strtod("0"))));
        assert((approx(10.0, etl::strtod("10"))));
        assert((approx(100.0, etl::strtod("100.0"))));
        assert((approx(1000.0, etl::strtod("1000.000"))));
        assert((approx(10000.0, etl::strtod("10000"))));
        assert((approx(999999.0, etl::strtod("999999.0"))));
        assert((approx(9999999.0, etl::strtod("9999999"))));
    }

    // "strtold"
    {
        assert((approx(0.0L, etl::strtold("0"))));
        assert((approx(10.0L, etl::strtold("10"))));
        assert((approx(100.0L, etl::strtold("100.0"))));
        assert((approx(1000.0L, etl::strtold("1000.000"))));
        assert((approx(10000.0L, etl::strtold("10000"))));
        assert((approx(999999.0L, etl::strtold("999999.0"))));
        assert((approx(9999999.0L, etl::strtold("9999999"))));
    }

    return true;
}

auto main() -> int
{
    assert(test());
    // static_assert(test());
    return 0;
}