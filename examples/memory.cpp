// SPDX-License-Identifier: BSL-1.0

#include <etl/cassert.hpp> // for assert
#include <etl/memory.hpp>  // for pointer_int_pair

auto main() -> int
{
#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    auto val = 42.0;
    auto ptr = etl::pointer_int_pair<double*, 2>{&val, 1U};
    assert(*ptr.get_pointer() == 42.0);
    assert(ptr.get_int() == 1U);
#endif

    return 0;
}
