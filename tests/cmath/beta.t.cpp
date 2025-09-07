// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
#endif

namespace {
template <typename T>
constexpr auto binom(int n, int k) -> T
{
    auto const tmp = 1 / ((n + 1) * etl::beta(n - k + 1, k + 1));
    return static_cast<T>(tmp);
}

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(binom<T>(1, 1), T(1));
    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
