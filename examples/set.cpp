// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include <etl/algorithm.hpp>
#include <etl/array.hpp>
#include <etl/cassert.hpp>
#include <etl/iterator.hpp>
#include <etl/set.hpp>

#include <stdio.h>

auto main() -> int
{
    // Basic usage
    etl::static_set<int, 16> set1;
    set1.insert(3); // 3
    set1.insert(1); // 1, 3
    set1.insert(2); // 1, 2, 3
    set1.insert(4); // 1, 2, 3, 4
    set1.insert(4); // 1, 2, 3, 4

    etl::for_each(set1.begin(), set1.end(), [](auto key) { ::printf("%d\n", key); });

    assert(set1.contains(2));
    assert(not set1.contains(5));

    // Construct from range
    auto data = etl::array{1.0F, 2.0F, 3.0F};
    auto set2 = etl::static_set<float, 3>{data.begin(), data.end()};

    assert(set2.full());
    assert(set2.size() == 3);
    assert(set2.count(1.0F) == 1);

    return 0;
}
