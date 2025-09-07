// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2022 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/random.hpp>
#endif

static constexpr auto test_xorshift32() -> bool
{
    CHECK(etl::xorshift32::min() == 0);
    CHECK(etl::xorshift32::max() == etl::uint32_t(-2));
    CHECK(etl::xorshift32::default_seed == 5489U);
    CHECK(etl::xorshift32() == etl::xorshift32());
    CHECK(etl::xorshift32() != etl::xorshift32(1));
    return true;
}

static constexpr auto test_xorshift64() -> bool
{
    CHECK(etl::xorshift64::min() == 0);
    CHECK(etl::xorshift64::max() == etl::uint64_t(-2));
    CHECK(etl::xorshift64::default_seed == 5489U);
    CHECK(etl::xorshift64() == etl::xorshift64());
    CHECK(etl::xorshift64() != etl::xorshift64(1));
    return true;
}

static constexpr auto test() -> bool
{
    CHECK(test_xorshift32());
    CHECK(test_xorshift64());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
