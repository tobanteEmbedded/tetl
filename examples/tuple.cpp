// SPDX-License-Identifier: BSL-1.0

#include "etl/tuple.hpp"

#include <stdio.h>
#include <stdlib.h>

auto main(int /*unused*/, char** /*unused*/) -> int
{
    etl::tuple<int, int, double> c(3, 5, 1.1);
    printf("%d\n", etl::get<1>(c));
    return EXIT_SUCCESS;
}
