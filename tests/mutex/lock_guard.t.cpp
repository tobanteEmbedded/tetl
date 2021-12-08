/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/mutex.hpp"
#include "etl/warning.hpp"

#include "test_mutex.hpp"
#include "testing/testing.hpp"

static auto test() -> bool
{
    //  "not locked"
    {
        test_mutex mtx {};
        assert(!mtx.is_locked());
        {
            etl::lock_guard lock { mtx };
            assert(mtx.is_locked());
            etl::ignore_unused(lock);
        }
        assert(!mtx.is_locked());
    }

    // "already locked"
    {
        test_mutex mtx {};
        mtx.lock();
        {
            etl::lock_guard lock { mtx, etl::adopt_lock };
            assert(mtx.is_locked());
            etl::ignore_unused(lock);
        }
        assert(!mtx.is_locked());
    }

    return true;
}

auto main() -> int
{
    assert(test());
    // static_assert(test());
    return 0;
}