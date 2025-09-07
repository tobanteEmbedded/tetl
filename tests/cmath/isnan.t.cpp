// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
    #include <etl/limits.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::isnan(etl::numeric_limits<T>::quiet_NaN()));
    CHECK(etl::isnan(etl::numeric_limits<T>::signaling_NaN()));

    CHECK_FALSE(etl::isnan(T{0}));
    CHECK_FALSE(etl::isnan(T{1}));
    CHECK_FALSE(etl::isnan(etl::numeric_limits<T>::infinity()));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
