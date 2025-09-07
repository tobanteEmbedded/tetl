// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/numeric.hpp>
#endif

static constexpr auto test() -> bool
{
    CHECK(etl::gcd(5, 10) == 5);
    CHECK(etl::gcd(10, 5) == 5);
    CHECK(etl::gcd(10, 5) == 5);

    CHECK(etl::gcd(30, 105) == 15);
    CHECK(etl::gcd(105, 30) == 15);
    CHECK(etl::gcd(105, 30) == 15);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
