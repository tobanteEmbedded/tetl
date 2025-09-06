// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_MEMORY_ASSUME_ALIGNED_HPP
#define TETL_MEMORY_ASSUME_ALIGNED_HPP

#include <etl/_config/all.hpp>

#include <etl/_bit/has_single_bit.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// Informs the implementation that the object ptr points to is aligned
/// to at least N. The implementation may use this information to generate more
/// efficient code, but it might only make this assumption if the object is
/// accessed via the return value of assume_aligned.
///
/// The program is ill-formed if N is not a power of 2. The behavior is
/// undefined if ptr does not point to an object of type T (ignoring
/// cv-qualification at every level), or if the object's alignment is not at
/// least N.
///
/// https://en.cppreference.com/w/cpp/memory/assume_aligned
///
/// \ingroup memory
template <etl::size_t N, typename T>
[[nodiscard]] constexpr auto assume_aligned(T* ptr) -> T*
{
    static_assert(etl::has_single_bit(N));
    static_assert(alignof(T) <= N);

    if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_assume_aligned)
        return static_cast<T*>(__builtin_assume_aligned(ptr, N));
#endif
    }

    return ptr;
}

} // namespace etl

#endif // TETL_MEMORY_ASSUME_ALIGNED_HPP
