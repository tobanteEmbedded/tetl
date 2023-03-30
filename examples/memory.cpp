// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include "etl/memory.hpp"  // for pointer_int_pair
#include "etl/cassert.hpp" // for TETL_ASSERT

auto main() -> int
{
#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    auto ptr = etl::pointer_int_pair<double*, 2> { new double(42.0), 1U };
    TETL_ASSERT(*ptr.get_pointer() == 42.0);
    TETL_ASSERT(ptr.get_int() == 1U);
    delete ptr.get_pointer();
#endif

    return 0;
}
