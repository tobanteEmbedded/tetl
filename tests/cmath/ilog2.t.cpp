// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/cassert.hpp>
#include <etl/concepts.hpp>

#include "testing/testing.hpp"

template <etl::integral Int>
constexpr auto test() -> bool
{
    static_assert(etl::same_as<decltype(etl::ilog2(etl::declval<Int>())), Int>);

    assert(etl::ilog2(Int(1)) == Int(0));
    assert(etl::ilog2(Int(2)) == Int(1));
    assert(etl::ilog2(Int(4)) == Int(2));
    assert(etl::ilog2(Int(8)) == Int(3));
    assert(etl::ilog2(Int(16)) == Int(4));
    assert(etl::ilog2(Int(32)) == Int(5));
    assert(etl::ilog2(Int(64)) == Int(6));

    if constexpr (sizeof(Int) > 1) {
        assert(etl::ilog2(Int(128)) == Int(7));
        assert(etl::ilog2(Int(256)) == Int(8));
        assert(etl::ilog2(Int(512)) == Int(9));
        assert(etl::ilog2(Int(1024)) == Int(10));
        assert(etl::ilog2(Int(2048)) == Int(11));
        assert(etl::ilog2(Int(4096)) == Int(12));
        assert(etl::ilog2(Int(8192)) == Int(13));
    }

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
