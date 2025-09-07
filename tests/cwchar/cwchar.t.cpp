// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/cwchar.hpp>
#endif

namespace {
constexpr auto test() -> bool
{
    // wmemcpy
    {
        CHECK(etl::wmemcpy(nullptr, nullptr, 0) == nullptr);

        auto const src = etl::array<wchar_t, 4>{L'A'};

        auto dest = etl::array<wchar_t, 4>{};
        CHECK(etl::wmemcpy(dest.data(), src.data(), 4) == dest.data());
        CHECK(dest == src);
    }

    // wmemset
    {
        CHECK(etl::wmemset(nullptr, L'A', 0) == nullptr);

        auto dest = etl::array<wchar_t, 4>{};
        CHECK(etl::wmemset(dest.data(), L'A', dest.size()) == dest.data());
        CHECK(dest == etl::array{L'A', L'A', L'A', L'A'});
    }

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
