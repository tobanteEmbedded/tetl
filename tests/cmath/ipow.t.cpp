// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
    #include <etl/concepts.hpp>
    #include <etl/type_traits.hpp>
#endif

template <etl::builtin_integer Int>
static constexpr auto test() -> bool
{
    static_assert(etl::same_as<decltype(etl::ipow(etl::declval<Int>(), etl::declval<Int>())), Int>);

    CHECK(etl::ipow(Int(1), Int(0)) == Int(1));
    CHECK(etl::ipow(Int(1), Int(1)) == Int(1));
    CHECK(etl::ipow(Int(1), Int(2)) == Int(1));

    CHECK(etl::ipow(Int(2), Int(0)) == Int(1));
    CHECK(etl::ipow(Int(2), Int(1)) == Int(2));
    CHECK(etl::ipow(Int(2), Int(2)) == Int(4));

    CHECK(etl::ipow<Int(1)>(Int(0)) == Int(1));
    CHECK(etl::ipow<Int(1)>(Int(1)) == Int(1));
    CHECK(etl::ipow<Int(1)>(Int(2)) == Int(1));

    CHECK(etl::ipow<Int(2)>(Int(0)) == Int(1));
    CHECK(etl::ipow<Int(2)>(Int(1)) == Int(2));
    CHECK(etl::ipow<Int(2)>(Int(2)) == Int(4));

    CHECK(etl::ipow<Int(8)>(Int(1)) == Int(8));
    CHECK(etl::ipow<Int(16)>(Int(1)) == Int(16));
    CHECK(etl::ipow<Int(32)>(Int(1)) == Int(32));
    CHECK(etl::ipow<Int(64)>(Int(1)) == Int(64));

    CHECK(etl::ipow<Int(8)>(Int(2)) == Int(64));

    if constexpr (sizeof(Int) > 1) {
        CHECK(etl::ipow<Int(16)>(Int(2)) == Int(256));
        CHECK(etl::ipow<Int(32)>(Int(2)) == Int(1024));
        CHECK(etl::ipow<Int(64)>(Int(2)) == Int(4096));
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<signed char>());
    STATIC_CHECK(test<signed short>());
    STATIC_CHECK(test<signed int>());
    STATIC_CHECK(test<signed long>());
    STATIC_CHECK(test<signed long long>());

    STATIC_CHECK(test<unsigned char>());
    STATIC_CHECK(test<unsigned short>());
    STATIC_CHECK(test<unsigned int>());
    STATIC_CHECK(test<unsigned long>());
    STATIC_CHECK(test<unsigned long long>());

    return 0;
}
