/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#undef NDEBUG

#include "etl/set.hpp"       // for static_set
#include "etl/algorithm.hpp" // for for_each
#include "etl/array.hpp"     // for array
#include "etl/cassert.hpp"   // for TETL_ASSERT
#include "etl/iterator.hpp"  // for begin, end

#include <stdio.h> // for printf

auto main() -> int
{
    using etl::array;
    using etl::for_each;
    using etl::static_set;

    // Basic usage
    static_set<int, 16> set1;
    set1.insert(3); // 3
    set1.insert(1); // 1, 3
    set1.insert(2); // 1, 2, 3
    set1.insert(4); // 1, 2, 3, 4
    set1.insert(4); // 1, 2, 3, 4

    for_each(begin(set1), end(set1), [](auto key) { printf("%d\n", key); });

    TETL_ASSERT(set1.contains(2));
    TETL_ASSERT(set1.contains(5) == false);

    // Construct from range
    auto data = array { 1.0F, 2.0F, 3.0F };
    auto set2 = static_set<float, 3> { begin(data), end(data) };

    TETL_ASSERT(set2.full());
    TETL_ASSERT(set2.size() == 3);
    TETL_ASSERT(set2.count(1.0F) == 1);

    return 0;
}
