// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
    #include <etl/concepts.hpp>
    #include <etl/type_traits.hpp>
#endif

template <etl::integral Int>
static constexpr auto test() -> bool
{
    static_assert(etl::same_as<decltype(etl::ipow(etl::declval<Int>(), etl::declval<Int>())), Int>);

    CHECK(etl::ipow(1, 0) == 1);
    CHECK(etl::ipow(1, 1) == 1);
    CHECK(etl::ipow(1, 2) == 1);

    CHECK(etl::ipow(2, 0) == 1);
    CHECK(etl::ipow(2, 1) == 2);
    CHECK(etl::ipow(2, 2) == 4);

    CHECK(etl::ipow<1>(0) == 1);
    CHECK(etl::ipow<1>(1) == 1);
    CHECK(etl::ipow<1>(2) == 1);

    CHECK(etl::ipow<2>(0) == 1);
    CHECK(etl::ipow<2>(1) == 2);
    CHECK(etl::ipow<2>(2) == 4);

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
