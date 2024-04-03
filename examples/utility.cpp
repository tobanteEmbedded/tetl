// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include "etl/utility.hpp"     // for in_range, pair, cmp_equal, as_const
#include "etl/cassert.hpp"     // for assert
#include "etl/type_traits.hpp" // for is_const_v, remove_reference_t

auto main() -> int
{
    using etl::as_const;
    using etl::cmp_equal;
    using etl::cmp_not_equal;
    using etl::exchange;
    using etl::is_const_v;
    using etl::make_pair;
    using etl::pair;
    using etl::remove_reference_t;
    using etl::swap;

    // SWAP
    auto v1 = 42;
    auto v2 = 100;
    swap(v1, v2);
    assert(v1 == 100);
    assert(v2 == 42);

    // EXCHANGE
    auto val = 1;
    assert(exchange(val, 2) == 1);

    // AS CONST
    auto c = 1;
    static_assert(!is_const_v<decltype(c)>);
    static_assert(is_const_v<remove_reference_t<decltype(as_const(c))>>);

    // CMP
    static_assert(cmp_equal(42, 42));
    static_assert(!cmp_equal(42UL, 100UL));
    static_assert(cmp_not_equal(42UL, 100UL));

    // PAIR construct
    auto p1 = pair<int, float>{1, 42.0F};
    assert(p1.first == 1);

    auto p2 = make_pair(2, 1.43F);
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
