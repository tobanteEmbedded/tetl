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