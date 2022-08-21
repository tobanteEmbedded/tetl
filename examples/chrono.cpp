/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include <stdio.h>

#include "etl/chrono.hpp"

auto main() -> int
{
    using namespace etl::literals;
    {
        auto hour = etl::chrono::hours { 1 };
        printf("%ld\n", static_cast<long>(hour.count()));
    }
    {
        auto const hour = 1_h;
        printf("%ld\n", static_cast<long>(hour.count()));
    }
    return 0;
}
