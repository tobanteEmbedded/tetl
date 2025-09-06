// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

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
    CHECK_APPROX(etl::round(T(0)), T(0));
    CHECK_APPROX(etl::round(T(1)), T(1));
    CHECK_APPROX(etl::round(T(2)), T(2));
    CHECK_APPROX(etl::round(T(-2)), T(-2));

    CHECK_APPROX(etl::round(T(0.1)), T(0));
    CHECK_APPROX(etl::round(T(0.2)), T(0));
    CHECK_APPROX(etl::round(T(0.3)), T(0));
    CHECK_APPROX(etl::round(T(0.4)), T(0));
    CHECK_APPROX(etl::round(T(0.5)), T(1));
    CHECK_APPROX(etl::round(T(0.6)), T(1));
    CHECK_APPROX(etl::round(T(0.7)), T(1));
    CHECK_APPROX(etl::round(T(0.8)), T(1));
    CHECK_APPROX(etl::round(T(0.9)), T(1));
    CHECK_APPROX(etl::round(T(0.99)), T(1));
    CHECK_APPROX(etl::round(T(1.01)), T(1));

    CHECK_APPROX(etl::round(T(-0.1)), T(0));
    CHECK_APPROX(etl::round(T(-0.2)), T(0));

    CHECK_APPROX(etl::roundf(0.1F), 0.0F);
    CHECK_APPROX(etl::roundf(0.2F), 0.0F);
    CHECK_APPROX(etl::roundf(0.3F), 0.0F);
    CHECK_APPROX(etl::roundf(1.3F), 1.0F);

    CHECK_APPROX(etl::roundl(0.1L), 0.0L);
    CHECK_APPROX(etl::roundl(0.2L), 0.0L);
    CHECK_APPROX(etl::roundl(0.3L), 0.0L);
    CHECK_APPROX(etl::roundl(1.3L), 1.0L);

    CHECK_APPROX(etl::round(0U), 0.0);
    CHECK_APPROX(etl::round(1U), 1.0);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
