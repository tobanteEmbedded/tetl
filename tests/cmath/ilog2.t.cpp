// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/cassert.hpp>
#include <etl/concepts.hpp>

#include "testing/testing.hpp"

template <etl::integral Int>
constexpr auto test() -> bool
{
    static_assert(etl::same_as<decltype(etl::ilog2(etl::declval<Int>())), Int>);

    CHECK(etl::ilog2(Int(1)) == Int(0));
    CHECK(etl::ilog2(Int(2)) == Int(1));
    CHECK(etl::ilog2(Int(4)) == Int(2));
    CHECK(etl::ilog2(Int(8)) == Int(3));
    CHECK(etl::ilog2(Int(16)) == Int(4));
    CHECK(etl::ilog2(Int(32)) == Int(5));
    CHECK(etl::ilog2(Int(64)) == Int(6));

    if constexpr (sizeof(Int) > 1) {
        CHECK(etl::ilog2(Int(128)) == Int(7));
        CHECK(etl::ilog2(Int(256)) == Int(8));
        CHECK(etl::ilog2(Int(512)) == Int(9));
        CHECK(etl::ilog2(Int(1024)) == Int(10));
        CHECK(etl::ilog2(Int(2048)) == Int(11));
        CHECK(etl::ilog2(Int(4096)) == Int(12));
        CHECK(etl::ilog2(Int(8192)) == Int(13));
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

    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    return 0;
}
