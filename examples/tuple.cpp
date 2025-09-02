// SPDX-License-Identifier: BSL-1.0

#include <etl/cassert.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/tuple.hpp>
#endif

auto main() -> int
{
    auto c = etl::tuple<int, int, double>{3, 5, 1.1};
    assert(etl::get<0>(c) == 3);
    assert(etl::get<1>(c) == 5);
    return 0;
}
