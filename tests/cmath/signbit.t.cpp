// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
    #include <etl/concepts.hpp>
    #include <etl/limits.hpp>
#endif

template <typename Float>
static constexpr auto test(auto signbit) -> bool
{
    using limits = etl::numeric_limits<Float>;

    CHECK(signbit(static_cast<Float>(-0.0F)));
    CHECK(signbit(static_cast<Float>(-1.0F)));
    CHECK(signbit(-limits::infinity()));
    CHECK(signbit(-limits::quiet_NaN()));

    CHECK_FALSE(signbit(static_cast<Float>(+0.0F)));
    CHECK_FALSE(signbit(static_cast<Float>(+1.0F)));
    CHECK_FALSE(signbit(+limits::infinity()));
    CHECK_FALSE(signbit(+limits::quiet_NaN()));

    return true;
}

template <typename Float>
static constexpr auto test_type() -> bool
{
    CHECK(test<Float>([](auto x) { return etl::signbit(x); }));
    CHECK(test<Float>([](auto x) { return etl::detail::signbit_fallback(x); }));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_type<float>());
    STATIC_CHECK(test_type<double>());
    CHECK(test_type<long double>());
    return 0;
}
