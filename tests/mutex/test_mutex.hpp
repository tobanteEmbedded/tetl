// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_MUTEX_TEST_MUTEX_HPP
#define TETL_TEST_MUTEX_TEST_MUTEX_HPP

struct test_mutex {
    constexpr test_mutex(bool failOnTryLock = false) noexcept : _failOnTryLock{failOnTryLock} { }

    ~test_mutex() noexcept = default;

    auto operator=(test_mutex const&) -> test_mutex& = delete;
    test_mutex(test_mutex const&)                    = delete;

    auto operator=(test_mutex&&) -> test_mutex& = default;
    test_mutex(test_mutex&&)                    = default;

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

    [[nodiscard]] constexpr auto is_locked() const noexcept { return _isLocked; }

private:
    bool _failOnTryLock{false};
    bool _isLocked = false;
};

#endif // TETL_TEST_MUTEX_TEST_MUTEX_HPP
