// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include <etl/cassert.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
#endif

auto main() -> int
{
    // SWAP
    auto v1 = 42;
    auto v2 = 100;
    etl::swap(v1, v2);
    assert(v1 == 100);
    assert(v2 == 42);

    // EXCHANGE
    auto val = 1;
    assert(etl::exchange(val, 2) == 1);

    // AS CONST
    auto c = 1;
    static_assert(not etl::is_const_v<decltype(c)>);
    static_assert(etl::is_const_v<etl::remove_reference_t<decltype(etl::as_const(c))>>);

    // CMP
    static_assert(etl::cmp_equal(42, 42));
    static_assert(not etl::cmp_equal(42UL, 100UL));
    static_assert(etl::cmp_not_equal(42UL, 100UL));

    // PAIR construct
    auto p1 = etl::pair<int, float>{1, 42.0F};
    assert(p1.first == 1);

    auto p2 = etl::make_pair(2, 1.43F);
    assert(p2.first == 2);

    auto p3 = p1;
    assert(p3.first == 1);

    // PAIR compare
    assert(p1 == p3);
    assert(p1 != p2);
    assert(p2 > p3);
    assert(p3 < p2);

    // PAIR swap
    swap(p2, p3);
    assert(p2.first == 1);
    assert(p3.first == 2);

    return 0;
}
