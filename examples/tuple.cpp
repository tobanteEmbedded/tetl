/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/tuple.hpp"

#include <stdio.h>
#include <stdlib.h>

auto main(int /*unused*/, char** /*unused*/) -> int
{
    etl::tuple<int, int, double> c(3, 5, 1.1);
    printf("%d\n", etl::get<1>(c));
    return EXIT_SUCCESS;
}