// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/array.hpp>

#include "testing/testing.hpp"

namespace {
[[nodiscard]] constexpr auto test_wchar() -> bool
{
    // copy
    {
        auto const src = etl::array<wchar_t, 4>{L'A', L'B', L'C', L'D'};

        {
            auto dest = etl::array<wchar_t, 4>{};
            etl::char_traits<wchar_t>::copy(dest.data(), src.data(), 0);
            CHECK(dest == etl::array<wchar_t, 4>{});
        }

        {
            auto dest = etl::array<wchar_t, 4>{};
            etl::char_traits<wchar_t>::copy(dest.data(), src.data(), src.size());
            CHECK(dest == src);
        }
    }

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test_wchar());
    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
