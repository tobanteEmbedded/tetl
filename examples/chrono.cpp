// SPDX-License-Identifier: BSL-1.0

#include <etl/cassert.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/chrono.hpp>
#endif

auto main() -> int
{
    using namespace etl::literals;
    assert(etl::chrono::hours(1) == 1_h);
    assert(etl::chrono::hours(1) == 60_min);
    return 0;
}
