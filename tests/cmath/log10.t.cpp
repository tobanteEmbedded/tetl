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
    CHECK_APPROX(etl::log10(T(1)), T(0));
    CHECK_APPROX(etl::log10(T(10)), T(1));
    CHECK_APPROX(etl::log10(T(100)), T(2));
    CHECK_APPROX(etl::log10(T(1000)), T(3));

    CHECK_APPROX(etl::log10f(1.0F), 0.0F);
    CHECK_APPROX(etl::log10f(10.0F), 1.0F);
    CHECK_APPROX(etl::log10f(100.0F), 2.0F);
    CHECK_APPROX(etl::log10f(1000.0F), 3.0F);

    CHECK_APPROX(etl::log10l(1.0L), 0.0L);
    CHECK_APPROX(etl::log10l(10.0L), 1.0L);
    CHECK_APPROX(etl::log10l(100.0L), 2.0L);
    CHECK_APPROX(etl::log10l(1000.0L), 3.0L);
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
