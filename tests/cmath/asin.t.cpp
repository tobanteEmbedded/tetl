// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

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
    CHECK(etl::asin(short{0}) == 0.0);
    CHECK(etl::asinl(0) == 0.0L);
    CHECK(etl::asin(T(0)) == T(0));

    CHECK_APPROX(etl::asin(T(0.5)), T(0.523599));
    CHECK_APPROX(etl::asin(T(1)), T(1.5708));

    CHECK(etl::isnan(etl::asin(T(2))));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
