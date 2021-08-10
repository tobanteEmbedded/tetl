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

#ifndef TETL_MEMORY_ASSUME_ALIGNED_HPP
#define TETL_MEMORY_ASSUME_ALIGNED_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_math/pow.hpp"
#include "etl/_type_traits/is_constant_evaluated.hpp"

namespace etl {

/// \brief Informs the implementation that the object ptr points to is aligned
/// to at least N. The implementation may use this information to generate more
/// efficient code, but it might only make this assumption if the object is
/// accessed via the return value of assume_aligned.
///
/// \details The program is ill-formed if N is not a power of 2. The behavior is
/// undefined if ptr does not point to an object of type T (ignoring
/// cv-qualification at every level), or if the object's alignment is not at
/// least N.
///
/// https://en.cppreference.com/w/cpp/memory/assume_aligned
///
template <::etl::size_t N, typename T>
[[nodiscard]] constexpr auto assume_aligned(T* ptr) -> T*
{
    static_assert(detail::is_power2(N));
    static_assert(alignof(T) <= N);

#if defined(TETL_IS_CONSTANT_EVALUATED)
    if (::etl::is_constant_evaluated()) { return ptr; }
#endif

    return static_cast<T*>(TETL_BUILTIN_ASSUME_ALIGNED(ptr, N));
}

} // namespace etl

#endif // TETL_MEMORY_ASSUME_ALIGNED_HPP