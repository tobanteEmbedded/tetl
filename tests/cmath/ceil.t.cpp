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
    CHECK_APPROX(etl::ceil(T(0)), T(0));
    CHECK_APPROX(etl::ceil(T(1)), T(1));
    CHECK_APPROX(etl::ceil(T(2)), T(2));
    CHECK_APPROX(etl::ceil(T(-2)), T(-2));

    CHECK_APPROX(etl::ceil(T(0.1)), T(1));
    CHECK_APPROX(etl::ceil(T(0.2)), T(1));
    CHECK_APPROX(etl::ceil(T(0.3)), T(1));
    CHECK_APPROX(etl::ceil(T(0.4)), T(1));
    CHECK_APPROX(etl::ceil(T(0.5)), T(1));
    CHECK_APPROX(etl::ceil(T(0.6)), T(1));
    CHECK_APPROX(etl::ceil(T(0.7)), T(1));
    CHECK_APPROX(etl::ceil(T(0.8)), T(1));
    CHECK_APPROX(etl::ceil(T(0.9)), T(1));
    CHECK_APPROX(etl::ceil(T(0.99)), T(1));
    CHECK_APPROX(etl::ceil(T(1.01)), T(2));

    CHECK_APPROX(etl::ceil(T(-0.1)), T(0));
    CHECK_APPROX(etl::ceil(T(-0.2)), T(0));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
