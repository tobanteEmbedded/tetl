// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "test_mutex.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/mutex.hpp>
    #include <etl/utility.hpp>
#endif

static constexpr auto test() -> bool
{
    // "default construction"
    {
        Mutex mtx{};
        CHECK_FALSE(mtx.is_locked());
        {
            etl::unique_lock<Mutex> lock{};
            CHECK(lock.mutex() == nullptr);
            CHECK_FALSE(mtx.is_locked());
        }
        CHECK_FALSE(mtx.is_locked());
    }

    // "lock on construction"
    {
        Mutex mtx{};
        CHECK_FALSE(mtx.is_locked());
        {
            etl::unique_lock lock{mtx};
            CHECK(lock.mutex() == &mtx);
            CHECK(mtx.is_locked());
        }
        CHECK_FALSE(mtx.is_locked());
    }

    // "try_lock on construction"
    {
        Mutex success{false};
        CHECK_FALSE(success.is_locked());
        {
            etl::unique_lock lock{success, etl::try_to_lock};
            CHECK(success.is_locked());
        }
        CHECK_FALSE(success.is_locked());

        Mutex fail{true};
        CHECK_FALSE(fail.is_locked());
        {
            etl::unique_lock lock{fail, etl::try_to_lock};
            CHECK_FALSE(fail.is_locked());
        }
        CHECK_FALSE(fail.is_locked());
    }

    // "defer lock on construction"
    {
        Mutex mtx{};
        CHECK_FALSE(mtx.is_locked());
        {
            etl::unique_lock lock{mtx, etl::defer_lock};
            CHECK_FALSE(mtx.is_locked());
        }
        CHECK_FALSE(mtx.is_locked());
    }

    // "adopt lock on construction"
    {
        Mutex mtx{};
        mtx.lock();
        CHECK(mtx.is_locked());
        {
            etl::unique_lock lock{mtx, etl::adopt_lock};
            CHECK(mtx.is_locked());
        }
        CHECK_FALSE(mtx.is_locked());
    }

    // "move"
    {
        Mutex mtx{};
        CHECK_FALSE(mtx.is_locked());
        {
            etl::unique_lock l1{mtx};
            CHECK(l1.owns_lock());
            CHECK(mtx.is_locked());

            etl::unique_lock l2{etl::move(l1)};
            CHECK_FALSE(l1.owns_lock()); // NOLINT(clang-analyzer-cplusplus.Move)
            CHECK(l2.owns_lock());
            CHECK(mtx.is_locked());

            etl::unique_lock<Mutex> l3{};
            l3 = etl::move(l2);
            CHECK_FALSE(l2.owns_lock()); // NOLINT(clang-analyzer-cplusplus.Move)
            CHECK(l3.owns_lock());
            CHECK(mtx.is_locked());

            auto mtx2 = Mutex{};
            auto l4   = etl::unique_lock{mtx2};
            CHECK(mtx2.is_locked());
            l4 = etl::move(l3);
            CHECK(l4.owns_lock());
            CHECK_FALSE(mtx2.is_locked());
            CHECK_FALSE(l3.owns_lock()); // NOLINT(clang-analyzer-cplusplus.Move)
        }
        CHECK_FALSE(mtx.is_locked());
    }

    // "swap"
    {
        Mutex mtx{};
        CHECK_FALSE(mtx.is_locked());
        {
            etl::unique_lock l1{mtx};
            CHECK(l1.owns_lock());
            CHECK(mtx.is_locked());

            decltype(l1) l2{};
            swap(l1, l2);

            CHECK_FALSE(l1.owns_lock());
            CHECK(l2.owns_lock());
            CHECK_FALSE(static_cast<bool>(l1));
            CHECK(static_cast<bool>(l2));
            CHECK(mtx.is_locked());
        }
        CHECK_FALSE(mtx.is_locked());
    }

    // "release"
    {
        Mutex mtx{};
        CHECK_FALSE(mtx.is_locked());
        {
            etl::unique_lock lock{mtx};
            CHECK(lock.owns_lock());
            CHECK(mtx.is_locked());

            auto* m = lock.release();
            CHECK_FALSE(lock.owns_lock());
            CHECK(m->is_locked());
        }
        CHECK(mtx.is_locked());
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
