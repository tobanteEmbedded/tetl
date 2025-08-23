// SPDX-License-Identifier: BSL-1.0

#include <etl/cassert.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/iterator.hpp>
#endif

auto main() -> int
{
    auto src = etl::array{1, 2, 3, 4}; // size & type are deduced

    src.fill(42);
    assert(etl::all_of(src.begin(), src.end(), [](auto v) { return v == 42; }));

    decltype(src) dest = {};
    assert(etl::all_of(dest.begin(), dest.end(), [](auto v) { return v == 0; }));

    etl::copy(src.begin(), src.end(), dest.begin());
    assert(etl::all_of(dest.begin(), dest.end(), [](auto v) { return v == 42; }));

    return 0;
}
