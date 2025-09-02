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
    CHECK(etl::acosh(short{1}) == 0.0);
    CHECK(etl::acoshl(1) == 0.0L);
    CHECK(etl::acosh(T(1)) == T(0));

    CHECK(etl::isnan(etl::acosh(T(0))));
    CHECK(etl::isnan(etl::acosh(T(0.5))));
    CHECK_APPROX(etl::acosh(T(2)), T(1.31696));
    CHECK_APPROX(etl::acosh(T(3)), T(1.76275));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
