// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "mdarray.t.hpp"

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_index<signed char>());
    CHECK(test_index<signed short>());
    CHECK(test_index<signed int>());
    CHECK(test_index<signed long>());
    CHECK(test_index<signed long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
