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
    CHECK_APPROX(etl::erf(T(0)), T(0));
    CHECK_APPROX(etl::erf(T(0.5)), T(0.5204998778));
    CHECK_APPROX(etl::erf(T(1)), T(0.8427007929));
    CHECK_APPROX(etl::erf(T(2)), T(0.995322265));
    CHECK_APPROX(etl::erf(T(4)), T(0.9999999846));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
