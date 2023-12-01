// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include <stdio.h>  // for printf
#include <stdlib.h> // for EXIT_SUCCESS

#include "etl/algorithm.hpp" // for all_of, copy
#include "etl/array.hpp"     // for array
#include "etl/cassert.hpp"   // for TETL_ASSERT
#include "etl/iterator.hpp"  // for begin, end

auto main() -> int
{
    using etl::all_of;
    using etl::array;
    using etl::copy;

    auto src = array {1, 2, 3, 4}; // size & type are deduced
    for (auto& item : src) { printf("%d\n", item); }

    src.fill(42);
    TETL_ASSERT(all_of(begin(src), end(src), [](auto v) { return v == 42; }));

    decltype(src) dest = {};
    TETL_ASSERT(all_of(begin(dest), end(dest), [](auto v) { return v == 0; }));

    copy(begin(src), end(src), begin(dest));
    TETL_ASSERT(all_of(begin(dest), end(dest), [](auto v) { return v == 42; }));

    return EXIT_SUCCESS;
}
