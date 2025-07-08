// SPDX-License-Identifier: BSL-1.0

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cmath;
#else
    #include <etl/cmath.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::cosh(short{0}) == 1.0);
    CHECK(etl::cosh(T(0)) == T(1));

    CHECK_APPROX(etl::cosh(T(0)), T(1));
    CHECK_APPROX(etl::cosh(T(0.5)), T(1.127625965));
    CHECK_APPROX(etl::cosh(T(1)), T(1.543080635));
    CHECK_APPROX(etl::cosh(T(2)), T(3.762195691));
    CHECK_APPROX(etl::cosh(T(4)), T(27.30823284));
    CHECK_APPROX(etl::cosh(T(8)), T(1490.479161));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
