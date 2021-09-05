/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/mutex.hpp"
#include "etl/warning.hpp"

#include "test_mutex.hpp"
#include "testing/testing.hpp"

auto test() -> bool
{

    // "default construction"
    {
        test_mutex mtx {};
        assert(!mtx.is_locked());
        {
            etl::unique_lock<test_mutex> lock {};
            assert(lock.mutex() == nullptr);
            assert(!mtx.is_locked());
        }
        assert(!mtx.is_locked());
    }

    // "lock on construction"
    {
        test_mutex mtx {};
        assert(!mtx.is_locked());
        {
            etl::unique_lock lock { mtx };
            assert(lock.mutex() == &mtx);
            assert(mtx.is_locked());
        }
        assert(!mtx.is_locked());
    }

    // "try_lock on construction"
    {
        test_mutex success { false };
        assert(!success.is_locked());
        {
            etl::unique_lock lock { success, etl::try_to_lock };
            assert(success.is_locked());
        }
        assert(!success.is_locked());

        test_mutex fail { true };
        assert(!fail.is_locked());
        {
            etl::unique_lock lock { fail, etl::try_to_lock };
            assert(!fail.is_locked());
        }
        assert(!fail.is_locked());
    }

    // "defer lock on construction"
    {
        test_mutex mtx {};
        assert(!mtx.is_locked());
        {
            etl::unique_lock lock { mtx, etl::defer_lock };
            assert(!mtx.is_locked());
        }
        assert(!mtx.is_locked());
    }

    // "adopt lock on construction"
    {
        test_mutex mtx {};
        mtx.lock();
        assert(mtx.is_locked());
        {
            etl::unique_lock lock { mtx, etl::adopt_lock };
            assert(mtx.is_locked());
        }
        assert(!mtx.is_locked());
    }

    // "move"
    {
        test_mutex mtx {};
        assert(!mtx.is_locked());
        {
            etl::unique_lock l1 { mtx };
            assert(l1.owns_lock());
            assert(mtx.is_locked());

            etl::unique_lock l2 { etl::move(l1) };
            assert(!l1.owns_lock()); // NOLINT(clang-analyzer-cplusplus.Move)
            assert(l2.owns_lock());
            assert(mtx.is_locked());

            etl::unique_lock<test_mutex> l3 {};
            l3 = etl::move(l2);
            assert(!l2.owns_lock()); // NOLINT(clang-analyzer-cplusplus.Move)
            assert(l3.owns_lock());
            assert(mtx.is_locked());
        }
        assert(!mtx.is_locked());
    }

    // "swap"
    {
        test_mutex mtx {};
        assert(!mtx.is_locked());
        {
            etl::unique_lock l1 { mtx };
            assert(l1.owns_lock());
            assert(mtx.is_locked());

            decltype(l1) l2 {};
            etl::swap(l1, l2);

            assert(!l1.owns_lock());
            assert(l2.owns_lock());
            assert(!static_cast<bool>(l1));
            assert(static_cast<bool>(l2));
            assert(mtx.is_locked());
        }
        assert(!mtx.is_locked());
    }

    // "release"
    {
        test_mutex mtx {};
        assert(!mtx.is_locked());
        {
            etl::unique_lock lock { mtx };
            assert(lock.owns_lock());
            assert(mtx.is_locked());

            auto* m = lock.release();
            assert(!lock.owns_lock());
            assert(m->is_locked());
        }
        assert(mtx.is_locked());
    }

    return true;
}

auto main() -> int
{
    assert(test());
    // static_assert(test());
    return 0;
}