// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/cassert.hpp>
#include <etl/concepts.hpp>

#include "testing/testing.hpp"

template <etl::integral Int>
constexpr auto test() -> bool
{
    static_assert(etl::same_as<decltype(etl::ipow(etl::declval<Int>(), etl::declval<Int>())), Int>);

    assert(etl::ipow(1, 0) == 1);
    assert(etl::ipow(1, 1) == 1);
    assert(etl::ipow(1, 2) == 1);

    assert(etl::ipow(2, 0) == 1);
    assert(etl::ipow(2, 1) == 2);
    assert(etl::ipow(2, 2) == 4);

    assert(etl::ipow<1>(0) == 1);
    assert(etl::ipow<1>(1) == 1);
    assert(etl::ipow<1>(2) == 1);

    assert(etl::ipow<2>(0) == 1);
    assert(etl::ipow<2>(1) == 2);
    assert(etl::ipow<2>(2) == 4);

    return true;
}

auto main() -> int
{
    static_assert(test<signed char>());
    static_assert(test<signed short>());
    static_assert(test<signed int>());
    static_assert(test<signed long>());
    static_assert(test<signed long long>());

    static_assert(test<unsigned char>());
    static_assert(test<unsigned short>());
    static_assert(test<unsigned int>());
    static_assert(test<unsigned long>());
    static_assert(test<unsigned long long>());

    assert(test<signed char>());
    assert(test<signed short>());
    assert(test<signed int>());
    assert(test<signed long>());
    assert(test<signed long long>());

    assert(test<unsigned char>());
    assert(test<unsigned short>());
    assert(test<unsigned int>());
    assert(test<unsigned long>());
    assert(test<unsigned long long>());

    return 0;
}
