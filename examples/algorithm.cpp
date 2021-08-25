/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include <stdio.h>

#include "etl/algorithm.hpp"
#include "etl/vector.hpp"

auto main() -> int
{
    using etl::find;
    using etl::for_each;
    using etl::for_each_n;
    using etl::static_vector;

    static_vector<double, 16> vec;
    vec.push_back(1.0);
    vec.push_back(2.0);
    vec.push_back(3.0);
    vec.push_back(4.0);

    // FOR_EACH
    auto print = [](auto& x) { printf("%f\n", x); };

    for_each(vec.begin(), vec.end(), print);
    for_each_n(vec.begin(), 3, [](auto const& x) { printf("%f\n", x * 2); });

    // FIND FIND_IF
    double n1 = 3.0;
    double n2 = 5;

    auto* result1 = find(vec.begin(), vec.end(), n1);
    auto* result2 = find(vec.begin(), vec.end(), n2);

    if (result1 != vec.end()) {
        printf("v contains: %f\n", n1);
    } else {
        printf("v does not contain: %f\n", n1);
    }

    if (result2 != vec.end()) {
        printf("v contains: %f\n", n2);
    } else {
        printf("v does not contain: %f\n", n2);
    }

    return 0;
}
