// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_MUTEX_TAGS_HPP
#define TETL_MUTEX_TAGS_HPP

namespace etl {

/// \brief Empty struct tag types used to specify locking strategy for
/// etl::lock_guard, etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
///
/// \details Do not acquire ownership of the mutex.
/// \ingroup mutex
struct defer_lock_t {
    explicit defer_lock_t() = default;
};

/// \brief Instances of empty struct tag types. See defer_lock_t.
/// \relates defer_lock_t
/// \ingroup mutex
inline constexpr auto defer_lock = defer_lock_t{};

/// \brief Empty struct tag types used to specify locking strategy for
/// etl::lock_guard, etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
///
/// \details Try to acquire ownership of the mutex without blocking.
/// \ingroup mutex
struct try_to_lock_t {
    explicit try_to_lock_t() = default;
};

/// \brief Instances of empty struct tag types. See try_to_lock_t.
/// \relates try_to_lock_t
/// \ingroup mutex
inline constexpr auto try_to_lock = try_to_lock_t{};

/// \brief Empty struct tag types used to specify locking strategy for
/// etl::lock_guard, etl::scoped_lock, etl::unique_lock, and etl::shared_lock.
///
/// \details Assume the calling thread already has ownership of the mutex.
/// \ingroup mutex
struct adopt_lock_t {
    explicit adopt_lock_t() = default;
};

/// \brief Instances of empty struct tag types. See adopt_lock_t.
/// \relates adopt_lock_t
/// \ingroup mutex
inline constexpr auto adopt_lock = adopt_lock_t{};

} // namespace etl

#endif // TETL_MUTEX_TAGS_HPP
