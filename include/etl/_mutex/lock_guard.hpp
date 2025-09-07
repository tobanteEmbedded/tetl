// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_MUTEX_LOCK_GUARD_HPP
#define TETL_MUTEX_LOCK_GUARD_HPP

#include <etl/_mutex/tags.hpp>

namespace etl {

/// \brief The struct lock_guard is a mutex wrapper that provides a convenient
/// RAII-style mechanism for owning a mutex for the duration of a scoped block.
/// When a lock_guard object is created, it attempts to take ownership of the
/// mutex it is given. When control leaves the scope in which the lock_guard
/// object was created, the lock_guard is destructed and the mutex is released.
/// The lock_guard struct is non-copyable.
/// \ingroup mutex
template <typename MutexT>
struct lock_guard {
    using mutex_type = MutexT;

    explicit lock_guard(mutex_type& m)
        : _mutex{m}
    {
        _mutex.lock();
    }

    lock_guard(mutex_type& m, adopt_lock_t /*tag*/)
        : _mutex{m}
    {
    }

    ~lock_guard()
    {
        _mutex.unlock();
    }

    lock_guard(lock_guard const&)                    = delete;
    auto operator=(lock_guard const&) -> lock_guard& = delete;

private:
    mutex_type& _mutex;
};

} // namespace etl

#endif // TETL_MUTEX_LOCK_GUARD_HPP
