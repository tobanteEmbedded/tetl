// SPDX-License-Identifier: BSL-1.0

#include <etl/cassert.hpp>

auto main() -> int
{
    auto const* str = "foo";
    TETL_ASSERT(str[0] == 'b');
    return 0;
}
