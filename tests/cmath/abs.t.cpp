// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cmath;
#else
    #include <etl/cmath.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::abs(T(0)) == T(0));

    CHECK(etl::abs(T(1)) == T(1));
    CHECK(etl::abs(T(2)) == T(2));
    CHECK(etl::abs(T(3)) == T(3));

    CHECK(etl::abs(T(-1)) == T(1));
    CHECK(etl::abs(T(-2)) == T(2));
    CHECK(etl::abs(T(-3)) == T(3));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
