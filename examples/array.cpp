// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include <etl/algorithm.hpp> // for all_of, copy
#include <etl/array.hpp>     // for array
#include <etl/cassert.hpp>   // for assert
#include <etl/iterator.hpp>  // for begin, end

#include <stdio.h>  // for printf
#include <stdlib.h> // for EXIT_SUCCESS

auto main() -> int
{
    auto src = etl::array{1, 2, 3, 4}; // size & type are deduced
    for (auto& item : src) {
        printf("%d\n", item);
    }

    src.fill(42);
    assert(etl::all_of(src.begin(), src.end(), [](auto v) { return v == 42; }));

    decltype(src) dest = {};
    assert(etl::all_of(dest.begin(), dest.end(), [](auto v) { return v == 0; }));

    etl::copy(src.begin(), src.end(), dest.begin());
    assert(etl::all_of(dest.begin(), dest.end(), [](auto v) { return v == 42; }));

    return EXIT_SUCCESS;
}
