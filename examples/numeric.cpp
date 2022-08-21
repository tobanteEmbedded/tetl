/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include <stdio.h>

#include "etl/numbers.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

auto main() -> int
{
    etl::static_vector<double, 16> vec;
    vec.push_back(etl::numbers::pi);
    vec.push_back(2.0);
    vec.push_back(3.0);
    vec.push_back(4.0);

    auto sum = etl::accumulate(vec.begin(), vec.end(), 0.0);

    printf("%f\n", sum);

    return 0;
}
