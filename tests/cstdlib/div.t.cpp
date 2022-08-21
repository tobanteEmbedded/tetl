/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdlib.hpp"

#include "testing/testing.hpp"

template <typename T, typename F>
constexpr auto test(F func) -> bool
{
    assert(etl::div(T(2), T(1)).quot == T(2));
    assert(etl::div(T(2), T(1)).rem == T(0));

    assert(etl::div(T(1), T(2)).quot == T(0));
    assert(etl::div(T(1), T(2)).rem == T(1));

    assert(func(T(2), T(1)).quot == T(2));
    assert(func(T(2), T(1)).rem == T(0));

    assert(func(T(1), T(2)).quot == T(0));
    assert(func(T(1), T(2)).rem == T(1));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<int>(static_cast<etl::div_t (*)(int, int)>(etl::div)));
    assert(test<long>(etl::ldiv));
    assert(test<long long>(etl::lldiv));
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
