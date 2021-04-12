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

#ifndef TAETL_DETAIL_CSTDDEF_INTERNAL_HPP
#define TAETL_DETAIL_CSTDDEF_INTERNAL_HPP

#include "etl/detail/intrinsics.hpp"

namespace etl
{
/// \brief etl::size_t is the unsigned integer type of the result of the sizeof
/// operator.
///
/// \notes [cppreference.com/w/cpp/types/size_t](https://en.cppreference.com/w/cpp/types/size_t)
using size_t = TAETL_BUILTIN_SIZET;

/// \brief etl::ptrdiff_t is the signed integer type of the result of
/// subtracting two pointers.
///
/// \notes [cppreference.com/w/cpp/types/ptrdiff_t](https://en.cppreference.com/w/cpp/types/ptrdiff_t)
using ptrdiff_t = TAETL_BUILTIN_PTRDIFF;

/// \brief etl::nullptr_t is the type of the null pointer literal, nullptr. It
/// is a distinct type that is not itself a pointer type or a pointer to member
/// type.
///
/// \notes [cppreference.com/w/cpp/types/nullptr_t](https://en.cppreference.com/w/cpp/types/nullptr_t)
using nullptr_t = decltype(nullptr);

/// \brief etl::max_align_t is a trivial standard-layout type whose alignment
/// requirement is at least as strict (as large) as that of every scalar type.
///
/// \notes
/// [cppreference.com/w/cpp/types/max_align_t](https://en.cppreference.com/w/cpp/types/max_align_t)
struct alignas(long double) max_align_t
{
};

}  // namespace etl

#endif  // TAETL_DETAIL_CSTDDEF_INTERNAL_HPP