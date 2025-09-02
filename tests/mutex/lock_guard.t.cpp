// SPDX-License-Identifier: BSL-1.0

#include "test_mutex.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/mutex.hpp>
    #include <etl/utility.hpp>
#endif

static auto test() -> bool
{
    // "not locked"
    {
        Mutex mtx{};
        CHECK_FALSE(mtx.is_locked());
        {
            etl::lock_guard lock{mtx};
            CHECK(mtx.is_locked());
            etl::ignore_unused(lock);
        }
        CHECK_FALSE(mtx.is_locked());
    }

    // "already locked"
    {
        Mutex mtx{};
        mtx.lock();
        {
            etl::lock_guard lock{mtx, etl::adopt_lock};
            CHECK(mtx.is_locked());
            etl::ignore_unused(lock);
        }
        CHECK_FALSE(mtx.is_locked());
    }

    return true;
}

auto main() -> int
{
    CHECK(test());
    return 0;
}
