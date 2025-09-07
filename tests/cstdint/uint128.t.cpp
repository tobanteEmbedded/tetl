// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/limits.hpp>
#endif

static constexpr auto test() -> bool
{
    CHECK(sizeof(etl::uint128) == 16);
    CHECK(sizeof(etl::uint128_t) == 16);

    CHECK_NOEXCEPT(etl::uint128{});
    CHECK_NOEXCEPT(etl::uint128{0});
    CHECK_NOEXCEPT(etl::uint128{0, 0});

    CHECK_FALSE(static_cast<bool>(etl::uint128{0}));
    CHECK(static_cast<bool>(etl::uint128{1}));
    CHECK(static_cast<bool>(etl::uint128{1, 1}));

    CHECK(etl::uint128{1}.high() == 0);
    CHECK(etl::uint128{1}.low() == 1);
    CHECK(static_cast<etl::uint64_t>(etl::uint128{2}) == 2);

    CHECK(etl::uint128{1, 2}.high() == 1);
    CHECK(etl::uint128{1, 2}.low() == 2);

    CHECK(etl::uint128{1, 1} == etl::uint128{1, 1});
    CHECK(etl::uint128{1, 1} != etl::uint128{2, 1});

    auto const max64 = etl::uint128{etl::numeric_limits<etl::uint64_t>::max()};
    auto const one   = etl::uint128{1};
    CHECK(max64 + one == etl::uint128{1, 0});

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
