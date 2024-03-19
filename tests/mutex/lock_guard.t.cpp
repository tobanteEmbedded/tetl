// SPDX-License-Identifier: BSL-1.0

#include <etl/mutex.hpp>
#include <etl/warning.hpp>

#include "test_mutex.hpp"
#include "testing/testing.hpp"

static auto test() -> bool
{
    // "not locked"
    {
        test_mutex mtx{};
        CHECK(!mtx.is_locked());
        {
            etl::lock_guard lock{mtx};
            CHECK(mtx.is_locked());
            etl::ignore_unused(lock);
        }
        CHECK(!mtx.is_locked());
    }

    // "already locked"
    {
        test_mutex mtx{};
        mtx.lock();
        {
            etl::lock_guard lock{mtx, etl::adopt_lock};
            CHECK(mtx.is_locked());
            etl::ignore_unused(lock);
        }
        CHECK(!mtx.is_locked());
    }

    return true;
}

auto main() -> int
{
    CHECK(test());
    // static_assert(test());
    return 0;
}
