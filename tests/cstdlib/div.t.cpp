// SPDX-License-Identifier: BSL-1.0
#include <etl/cstdlib.hpp>

#include "testing/testing.hpp"

template <typename T, typename F>
constexpr auto test(F func) -> bool
{
    CHECK(etl::div(T(2), T(1)).quot == T(2));
    CHECK(etl::div(T(2), T(1)).rem == T(0));

    CHECK(etl::div(T(1), T(2)).quot == T(0));
    CHECK(etl::div(T(1), T(2)).rem == T(1));

    CHECK(func(T(2), T(1)).quot == T(2));
    CHECK(func(T(2), T(1)).rem == T(0));

    CHECK(func(T(1), T(2)).quot == T(0));
    CHECK(func(T(1), T(2)).rem == T(1));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<int>(static_cast<etl::div_t (*)(int, int)>(etl::div)));
    CHECK(test<long>(etl::ldiv));
    CHECK(test<long long>(etl::lldiv));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
