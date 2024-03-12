// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MUTEX_UNIQUE_LOCK_HPP
#define TETL_MUTEX_UNIQUE_LOCK_HPP

#include <etl/_chrono/duration.hpp>
#include <etl/_chrono/time_point.hpp>
#include <etl/_mutex/tags.hpp>
#include <etl/_utility/exchange.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

/// \brief The struct unique_lock is a general-purpose mutex ownership wrapper
/// allowing deferred locking, time-constrained attempts at locking, recursive
/// locking, transfer of lock ownership, and use with condition variables.
///
/// \details The struct unique_lock is movable, but not copyable -- it meets the
/// requirements of MoveConstructible and MoveAssignable but not of
/// CopyConstructible or CopyAssignable. The struct unique_lock meets the
/// BasicLockable requirements. If Mutex meets the Lockable requirements,
/// unique_lock also meets the Lockable requirements (ex.: can be used in lock);
/// if Mutex meets the TimedLockable requirements, unique_lock also meets the
/// TimedLockable requirements.
template <typename Mutex>
struct unique_lock {
private:
    Mutex* _mutex{nullptr};
    bool _owns{false};

public:
    using mutex_type = Mutex;

    /// \brief Constructs a unique_lock with no associated mutex.
    unique_lock() noexcept = default;

    /// \brief Constructs a unique_lock with m as the associated mutex.
    /// Additionally: Locks the associated mutex by calling m.lock(). The
    /// behavior is undefined if the current thread already owns the mutex
    /// except when the mutex is recursive.
    explicit unique_lock(mutex_type& m) : _mutex{&m} { lock(); }

    /// \brief Constructs a unique_lock with m as the associated mutex.
    /// Additionally: Does not lock the associated mutex.
    unique_lock(mutex_type& m, defer_lock_t /*tag*/) noexcept : _mutex{&m} { }

    /// \brief Constructs a unique_lock with m as the associated mutex.
    /// Additionally: Tries to lock the associated mutex without blocking by
    /// calling m.try_lock(). The behavior is undefined if the current thread
    /// already owns the mutex except when the mutex is recursive.
    unique_lock(mutex_type& m, try_to_lock_t /*tag*/) noexcept : _mutex{&m} { try_lock(); }

    /// \brief Constructs a unique_lock with m as the associated mutex.
    /// Additionally: Assumes the calling thread already owns m.
    unique_lock(mutex_type& m, adopt_lock_t /*tag*/) : _mutex{&m}, _owns{true} { }

    /// \brief Constructs a unique_lock with m as the associated mutex.
    /// Additionally: Tries to lock the associated mutex by calling
    /// m.try_lock_until(timeout_time). Blocks until specified timeout_time has
    /// been reached or the lock is acquired, whichever comes first. May block
    /// for longer than until timeout_time has been reached.
    template <typename Clock, typename Duration>
    unique_lock(mutex_type& m, chrono::time_point<Clock, Duration> const& absTime) noexcept : _mutex{&m}
    {
        try_lock_until(absTime);
    }

    /// \brief Constructs a unique_lock with m as the associated mutex.
    /// Additionally: Tries to lock the associated mutex by calling
    /// m.try_lock_for(timeout_duration). Blocks until specified
    /// timeout_duration has elapsed or the lock is acquired, whichever comes
    /// first. May block for longer than timeout_duration.
    template <typename Rep, typename Period>
    unique_lock(mutex_type& m, chrono::duration<Rep, Period> const& relTime) noexcept : _mutex{&m}
    {
        try_lock_for(relTime);
    }

    /// \brief Deleted copy constructor. unique_lock is move only.
    unique_lock(unique_lock const&) = delete;

    /// \brief Deleted copy assignment. unique_lock is move only.
    auto operator=(unique_lock const&) -> unique_lock& = delete;

    /// \brief Move constructor. Initializes the unique_lock with the contents
    /// of other. Leaves other with no associated mutex.
    unique_lock(unique_lock&& u) noexcept : _mutex{exchange(u._mutex, nullptr)}, _owns{exchange(u._owns, false)} { }

    /// \brief Move assignment operator. Replaces the contents with those of
    /// other using move semantics. If prior to the call *this has an associated
    /// mutex and has acquired ownership of it, the mutex is unlocked.
    auto operator=(unique_lock&& u) noexcept -> unique_lock&
    {
        if (_mutex != nullptr && _owns) {
            unlock();
        }
        _mutex = exchange(u._mutex, nullptr);
        _owns  = exchange(u._owns, false);
        return *this;
    }

    ~unique_lock() noexcept { unlock(); }

    /// \brief Locks (i.e., takes ownership of) the associated mutex.
    auto lock() noexcept(noexcept(_mutex->lock())) -> void
    {
        if ((_mutex != nullptr) and !_owns) {
            _mutex->lock();
            _owns = true;
        }
    }

    /// \brief Tries to lock (i.e., takes ownership of) the associated mutex
    /// without blocking.
    /// \returns true if the ownership of the mutex has been acquired
    /// successfully, false otherwise.
    auto try_lock() noexcept(noexcept(_mutex->try_lock())) -> bool
    {
        if ((_mutex != nullptr) && !_owns) {
            if (auto success = _mutex->try_lock(); success) {
                _owns = true;
                return true;
            }
        }

        return false;
    }

    /// \brief Tries to lock (i.e., takes ownership of) the associated mutex.
    /// Blocks until specified timeout_duration has elapsed or the lock is
    /// acquired, whichever comes first. On successful lock acquisition returns
    /// true, otherwise returns false. Effectively calls
    /// mutex()->try_lock_for(timeout_duration). This function may block for
    /// longer than timeout_duration due to scheduling or resource contention
    /// delays.
    template <typename Rep, typename Period>
    auto try_lock_for(chrono::duration<Rep, Period> const& dur) noexcept(noexcept(_mutex->try_lock_for(dur))) -> bool
    {
        if ((_mutex != nullptr) && !_owns) {
            if (auto success = _mutex->try_lock_for(dur); success) {
                _owns = true;
                return true;
            }
        }
        return false;
    }

    /// \brief Tries to lock (i.e., takes ownership of) the associated mutex
    /// without blocking.
    template <typename Clock, typename Duration>
    auto try_lock_until(chrono::time_point<Clock, Duration> const& tp) noexcept(noexcept(_mutex->try_lock_until(tp))
    ) -> bool
    {
        if ((_mutex != nullptr) && !_owns) {
            if (auto success = _mutex->try_lock_until(tp); success) {
                _owns = true;
                return true;
            }
        }
        return false;
    }

    /// \brief Unlocks (i.e., releases ownership of) the associated mutex and
    /// releases ownership. Silently does nothing, if there is no associated
    /// mutex or if the mutex is not locked.
    auto unlock() -> void
    {
        if ((_mutex != nullptr) and _owns) {
            _mutex->unlock();
            _owns = false;
        }
    }

    /// \brief Exchanges the internal states of the lock objects.
    auto swap(unique_lock& other) noexcept -> void
    {
        using etl::swap;
        swap(_mutex, other._mutex);
        swap(_owns, other._owns);
    }

    /// \brief Breaks the association of the associated mutex, if any, and
    /// *this. No locks are unlocked. If the *this held ownership of the
    /// associated mutex prior to the call, the caller is now responsible to
    /// unlock the mutex.
    ///
    /// \returns Pointer to the associated mutex or a null pointer if there was
    /// no associated mutex.
    [[nodiscard]] auto release() noexcept -> mutex_type*
    {
        _owns = false;
        return _mutex;
    }

    /// \brief Checks whether *this owns a locked mutex or not.
    [[nodiscard]] auto owns_lock() const noexcept -> bool { return _owns; }

    /// \brief Checks whether *this owns a locked mutex or not.
    [[nodiscard]] explicit operator bool() const noexcept { return owns_lock(); }

    /// \brief Returns a pointer to the associated mutex, or a null pointer if
    /// there is no associated mutex.
    [[nodiscard]] auto mutex() const noexcept -> mutex_type* { return _mutex; }
};

/// \brief Specializes the swap algorithm for unique_lock. Exchanges the state
/// of lhs with that of rhs.
template <typename Mutex>
void swap(unique_lock<Mutex>& lhs, unique_lock<Mutex>& rhs) noexcept(noexcept(lhs.swap(rhs)))
{
    lhs.swap(rhs);
}

} // namespace etl

#endif // TETL_MUTEX_UNIQUE_LOCK_HPP
