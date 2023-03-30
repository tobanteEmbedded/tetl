// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MUTEX_TAGS_HPP
#define TETL_MUTEX_TAGS_HPP

namespace etl {

/// \brief Empty struct tag types used to specify locking strategy for
/// etl::lock_guard, etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
///
/// \details Do not acquire ownership of the mutex.
struct defer_lock_t {
    explicit defer_lock_t() = default;
};

/// \brief Empty struct tag types used to specify locking strategy for
/// etl::lock_guard, etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
///
/// \details Try to acquire ownership of the mutex without blocking.
struct try_to_lock_t {
    explicit try_to_lock_t() = default;
};

/// \brief Empty struct tag types used to specify locking strategy for
/// etl::lock_guard, etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
///
/// \details Assume the calling thread already has ownership of the mutex.
struct adopt_lock_t {
    explicit adopt_lock_t() = default;
};

/// \brief Instances of empty struct tag types. See defer_lock_t.
inline constexpr defer_lock_t defer_lock {};

/// \brief Instances of empty struct tag types. See try_to_lock_t.
inline constexpr try_to_lock_t try_to_lock {};

/// \brief Instances of empty struct tag types. See adopt_lock_t.
inline constexpr adopt_lock_t adopt_lock {};

} // namespace etl

#endif // TETL_MUTEX_TAGS_HPP
