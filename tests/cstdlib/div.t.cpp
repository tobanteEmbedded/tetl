// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/cstdlib.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename T, typename F>
static constexpr auto test(F func) -> bool
{
    CHECK(func(T(2), T(1)).quot == T(2));
    CHECK(func(T(2), T(1)).rem == T(0));

    CHECK(func(T(1), T(2)).quot == T(0));
    CHECK(func(T(1), T(2)).rem == T(1));

    if constexpr (not etl::is_same_v<etl::intmax_t, long long>) {
        CHECK(etl::div(T(2), T(1)).quot == T(2));
        CHECK(etl::div(T(2), T(1)).rem == T(0));

        CHECK(etl::div(T(1), T(2)).quot == T(0));
        CHECK(etl::div(T(1), T(2)).rem == T(1));
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<int>(static_cast<etl::div_t (*)(int, int)>(etl::div)));
    CHECK(test<long>(etl::ldiv));
    CHECK(test<long long>(etl::lldiv));
    CHECK(test<etl::intmax_t>(etl::imaxdiv));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
