// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "mdarray.t.hpp"

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_index<unsigned char>());
    CHECK(test_index<unsigned short>());
    CHECK(test_index<unsigned int>());
    CHECK(test_index<unsigned long>());
    CHECK(test_index<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
