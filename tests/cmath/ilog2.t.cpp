// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cmath;
import etl.concepts;
import etl.type_traits;
#else
    #include <etl/cmath.hpp>
    #include <etl/concepts.hpp>
    #include <etl/type_traits.hpp>
#endif

template <etl::integral Int>
static constexpr auto test() -> bool
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
