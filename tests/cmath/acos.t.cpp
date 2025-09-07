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
    CHECK(etl::acos(short{1}) == 0.0);
    CHECK(etl::acosl(1) == 0.0L);
    CHECK(etl::acos(T(1)) == T(0));

    CHECK_APPROX(etl::acos(T(0)), T(1.570796327));
    CHECK_APPROX(etl::acos(T(0.5)), T(1.047197551));
    CHECK_APPROX(etl::acos(T(1)), T(0));
    CHECK(etl::isnan(etl::acos(T(2))));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
