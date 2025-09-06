// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include <etl/cassert.hpp>

auto main() -> int
{
    auto const* str = "foo";
    TETL_ASSERT(str[0] == 'b');
    return 0;
}
