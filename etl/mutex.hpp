/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_MUTEX_HPP
#define TAETL_MUTEX_HPP

namespace etl
{
/**
 * @brief Empty class tag types used to specify locking strategy for etl::lock_guard,
 * etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
 *
 * @details Do not acquire ownership of the mutex.
 */
struct defer_lock_t
{
    explicit defer_lock_t() = default;
};

/**
 * @brief Empty class tag types used to specify locking strategy for etl::lock_guard,
 * etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
 *
 * @details Try to acquire ownership of the mutex without blocking.
 */
struct try_to_lock_t
{
    explicit try_to_lock_t() = default;
};

/**
 * @brief Empty class tag types used to specify locking strategy for etl::lock_guard,
 * etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
 *
 * @details Assume the calling thread already has ownership of the mutex.
 */
struct adopt_lock_t
{
    explicit adopt_lock_t() = default;
};

/**
 * @brief Instances of empty struct tag types. See defer_lock_t.
 */
inline constexpr defer_lock_t defer_lock {};

/**
 * @brief Instances of empty struct tag types. See try_to_lock_t.
 */
inline constexpr try_to_lock_t try_to_lock {};

/**
 * @brief Instances of empty struct tag types. See adopt_lock_t.
 */
inline constexpr adopt_lock_t adopt_lock {};

/**
 * @brief The class lock_guard is a mutex wrapper that provides a convenient RAII-style
 * mechanism for owning a mutex for the duration of a scoped block. When a lock_guard
 * object is created, it attempts to take ownership of the mutex it is given. When control
 * leaves the scope in which the lock_guard object was created, the lock_guard is
 * destructed and the mutex is released. The lock_guard class is non-copyable.
 */
template <typename MutexT>
class lock_guard
{
public:
    using mutex_type = MutexT;

    explicit lock_guard(mutex_type& m) : mutex_ {m} { mutex_.lock(); }
    lock_guard(mutex_type& m, adopt_lock_t /*unused*/) : mutex_ {m} { }
    ~lock_guard() { mutex_.unlock(); }

    lock_guard(const lock_guard&) = delete;
    auto operator=(const lock_guard&) -> lock_guard& = delete;

private:
    mutex_type& mutex_;
};

/**
 * @brief RAII based lock.
 * @todo Fix move special member funcs. Make variadic.
 */
template <typename MutexT>
class scoped_lock
{
public:
    explicit scoped_lock(MutexT& m) : mutex_ {m} { mutex_.lock(); }
    ~scoped_lock() { mutex_.unlock(); }

    scoped_lock(const scoped_lock&) = delete;
    auto operator=(const scoped_lock&) = delete;

    scoped_lock(scoped_lock&&) noexcept = default;
    auto operator=(scoped_lock&&) noexcept -> scoped_lock& = default;

private:
    MutexT& mutex_;
};
}  // namespace etl

#endif  // TAETL_MUTEX_HPP