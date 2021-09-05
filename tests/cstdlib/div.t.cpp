/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdlib.hpp"

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    // "int"
    {
        assert(etl::div(2, 1).quot == 2);
        assert(etl::div(2, 1).rem == 0);

        assert(etl::div(1, 2).quot == 0);
        assert(etl::div(1, 2).rem == 1);
    }

    // "long"
    {
        assert(etl::div(2L, 1L).quot == 2L);
        assert(etl::div(2L, 1L).rem == 0L);

        assert(etl::div(1L, 2L).quot == 0L);
        assert(etl::div(1L, 2L).rem == 1L);

        assert(etl::ldiv(2LL, 1LL).quot == 2LL);
        assert(etl::ldiv(2LL, 1LL).rem == 0LL);

        assert(etl::ldiv(1LL, 2LL).quot == 0LL);
        assert(etl::ldiv(1LL, 2LL).rem == 1LL);
    }

    // "long long"
    {
        assert(etl::div(2LL, 1LL).quot == 2LL);
        assert(etl::div(2LL, 1LL).rem == 0LL);

        assert(etl::div(1LL, 2LL).quot == 0LL);
        assert(etl::div(1LL, 2LL).rem == 1LL);

        assert(etl::lldiv(2LL, 1LL).quot == 2LL);
        assert(etl::lldiv(2LL, 1LL).rem == 0LL);

        assert(etl::lldiv(1LL, 2LL).quot == 0LL);
        assert(etl::lldiv(1LL, 2LL).rem == 1LL);
    }

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}