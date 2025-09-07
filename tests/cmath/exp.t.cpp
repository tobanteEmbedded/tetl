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
    CHECK_APPROX(etl::exp(T(0)), T(1));
    CHECK_APPROX(etl::exp(T(0.5)), T(1.64872));
    CHECK_APPROX(etl::exp(T(1)), T(2.71828));
    CHECK_APPROX(etl::exp(T(2)), T(7.38906));
    CHECK_APPROX(etl::exp(T(4)), T(54.5982));

    CHECK_APPROX(etl::expf(0.0F), 1.0F);
    CHECK_APPROX(etl::expf(0.5F), 1.64872F);
    CHECK_APPROX(etl::expf(1.0F), 2.71828F);
    CHECK_APPROX(etl::expf(2.0F), 7.38906F);
    CHECK_APPROX(etl::expf(4.0F), 54.5982F);

    CHECK_APPROX(etl::expl(0.0L), 1.0L);
    CHECK_APPROX(etl::expl(0.5L), 1.64872L);
    CHECK_APPROX(etl::expl(1.0L), 2.71828L);
    CHECK_APPROX(etl::expl(2.0L), 7.38906L);
    CHECK_APPROX(etl::expl(4.0L), 54.5982L);

    CHECK_APPROX(etl::exp(0U), 1.0);
    CHECK_APPROX(etl::exp(1U), 2.71828);
    CHECK_APPROX(etl::exp(2U), 7.38906);
    CHECK_APPROX(etl::exp(4U), 54.5982);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    STATIC_CHECK(test<long double>());
#endif

    return 0;
}
