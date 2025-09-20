// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
    #include <etl/numbers.hpp>
#endif

template <typename T>
static constexpr auto test_type() -> bool
{
    CHECK_APPROX(etl::pow(T(0), T(1)), T(0));
    CHECK_APPROX(etl::pow(T(2), T(0)), T(1));
    CHECK_APPROX(etl::pow(T(2), T(1)), T(2));
    CHECK_APPROX(etl::pow(T(2), T(2)), T(4));
    CHECK_APPROX(etl::pow(T(etl::numbers::pi), T(1)), T(etl::numbers::pi));

    return true;
}

static constexpr auto test_all() -> bool
{
    // float
    CHECK_APPROX(etl::pow(4.0F, 2), 16.0F);
    CHECK_APPROX(etl::pow(4.0F, 2.0F), 16.0F);
    CHECK_APPROX(etl::powf(4.0F, 2.0F), 16.0F);

    // double
    CHECK_APPROX(etl::pow(4.0, 2), 16.0);
    CHECK_APPROX(etl::pow(4.0, 2.0), 16.0);

    // long double
    CHECK_APPROX(etl::pow(4.0L, 2), 16.0L);
    CHECK_APPROX(etl::pow(4.0L, 2.0L), 16.0L);
    CHECK_APPROX(etl::powl(4.0L, 2.0L), 16.0L);

    CHECK(test_type<float>());
    CHECK(test_type<double>());
    CHECK(test_type<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
