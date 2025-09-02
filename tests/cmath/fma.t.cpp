// SPDX-License-Identifier: BSL-1.0

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_APPROX(etl::fma(T(0), T(0), T(0)), T(0));
    CHECK_APPROX(etl::fma(T(0), T(1), T(0)), T(0));
    CHECK_APPROX(etl::fma(T(1), T(0), T(0)), T(0));
    CHECK_APPROX(etl::fma(T(1), T(1), T(0)), T(1));
    CHECK_APPROX(etl::fma(T(1), T(1), T(1)), T(2));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
