/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TEST_MUTEX_TEST_MUTEX_HPP
#define TETL_TEST_MUTEX_TEST_MUTEX_HPP

struct test_mutex {
    constexpr test_mutex(bool failOnTryLock = false) noexcept : failOnTryLock_ { failOnTryLock } { }

    ~test_mutex() noexcept = default;

    auto operator=(test_mutex const&) -> test_mutex& = delete;
    test_mutex(test_mutex const&)                    = delete;

    auto operator=(test_mutex&&) -> test_mutex& = default;
    test_mutex(test_mutex&&)                    = default;

    constexpr auto lock() noexcept
    {
        if (not isLocked_) { isLocked_ = true; }
    }

    constexpr auto try_lock() noexcept -> bool
    {
        if (not isLocked_ && not failOnTryLock_) {
            isLocked_ = true;
            return true;
        }

        return false;
    }

    constexpr auto unlock() noexcept
    {
        if (isLocked_) { isLocked_ = false; }
    }

    [[nodiscard]] constexpr auto is_locked() const noexcept { return isLocked_; }

private:
    bool failOnTryLock_ { false };
    bool isLocked_ = false;
};

#endif // TETL_TEST_MUTEX_TEST_MUTEX_HPP
