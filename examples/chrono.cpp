// SPDX-License-Identifier: BSL-1.0

#include <stdio.h>

#include <etl/chrono.hpp>

auto main() -> int
{
    using namespace etl::literals;
    {
        auto hour = etl::chrono::hours{1};
        printf("%ld\n", static_cast<long>(hour.count()));
    }
    {
        auto const hour = 1_h;
        printf("%ld\n", static_cast<long>(hour.count()));
    }
    return 0;
}
