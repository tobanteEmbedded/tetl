// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_TEST_MUTEX_TEST_MUTEX_HPP
#define TETL_TEST_MUTEX_TEST_MUTEX_HPP

struct Mutex {
    constexpr Mutex(bool failOnTryLock = false) noexcept
        : _failOnTryLock{failOnTryLock}
    {
    }

    ~Mutex() noexcept = default;

    auto operator=(Mutex const&) -> Mutex& = delete;
    Mutex(Mutex const&)                    = delete;

    auto operator=(Mutex&&) -> Mutex& = default;
    Mutex(Mutex&&)                    = default;

    constexpr auto lock() noexcept
    {
        if (not _isLocked) {
            _isLocked = true;
        }
    }

    constexpr auto try_lock() noexcept -> bool
    {
        if (not _isLocked && not _failOnTryLock) {
            _isLocked = true;
            return true;
        }

        return false;
    }

    constexpr auto unlock() noexcept
    {
        if (_isLocked) {
            _isLocked = false;
        }
    }

    [[nodiscard]] constexpr auto is_locked() const noexcept
    {
        return _isLocked;
    }

private:
    bool _failOnTryLock{false};
    bool _isLocked = false;
};

#endif // TETL_TEST_MUTEX_TEST_MUTEX_HPP
