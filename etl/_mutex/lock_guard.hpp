// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_MUTEX_LOCK_GUARD_HPP
#define TETL_MUTEX_LOCK_GUARD_HPP

#include "etl/_mutex/tags.hpp"

namespace etl {

/// \brief The struct lock_guard is a mutex wrapper that provides a convenient
/// RAII-style mechanism for owning a mutex for the duration of a scoped block.
/// When a lock_guard object is created, it attempts to take ownership of the
/// mutex it is given. When control leaves the scope in which the lock_guard
/// object was created, the lock_guard is destructed and the mutex is released.
/// The lock_guard struct is non-copyable.
template <typename MutexT>
struct lock_guard {
    using mutex_type = MutexT;

    explicit lock_guard(mutex_type& m) : mutex_ { m } { mutex_.lock(); }
    lock_guard(mutex_type& m, adopt_lock_t /*tag*/) : mutex_ { m } { }
    ~lock_guard() { mutex_.unlock(); }

    lock_guard(lock_guard const&) = delete;
    auto operator=(lock_guard const&) -> lock_guard& = delete;

private:
    mutex_type& mutex_;
};

} // namespace etl

#endif // TETL_MUTEX_LOCK_GUARD_HPP