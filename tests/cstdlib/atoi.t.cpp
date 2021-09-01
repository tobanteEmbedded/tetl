/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdlib.hpp"

#include "testing.hpp"

constexpr auto test() -> bool
{
    // "cstdlib: atoi"
    {
        assert((etl::atoi("0") == 0));
        assert((etl::atoi("10") == 10));
        assert((etl::atoi("99") == 99));
        assert((etl::atoi("143") == 143));
        assert((etl::atoi("999") == 999));
        assert((etl::atoi("1111") == 1111));
        assert((etl::atoi("99999") == 99999));
        assert((etl::atoi("999999") == 999999));
        assert((etl::atoi("123456789") == 123456789));
    }

    // "cstdlib: atol"
    {
        assert((etl::atoi("0") == 0));
        assert((etl::atoi("10") == 10));
        assert((etl::atoi("99") == 99));
        assert((etl::atoi("143") == 143));
        assert((etl::atoi("999") == 999));
        assert((etl::atoi("1111") == 1111));
        assert((etl::atoi("99999") == 99999));
        assert((etl::atoi("999999") == 999999));
        assert((etl::atoi("123456789") == 123456789));
    }

    // "cstdlib: atoll"
    {
        assert((etl::atoi("0") == 0));
        assert((etl::atoi("10") == 10));
        assert((etl::atoi("99") == 99));
        assert((etl::atoi("143") == 143));
        assert((etl::atoi("999") == 999));
        assert((etl::atoi("1111") == 1111));
        assert((etl::atoi("99999") == 99999));
        assert((etl::atoi("999999") == 999999));
        assert((etl::atoi("123456789") == 123456789));
    }

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}