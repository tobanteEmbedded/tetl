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

#ifndef TETL_DETAIL_CSTDDEF_MAX_ALIGN_T_HPP
#define TETL_DETAIL_CSTDDEF_MAX_ALIGN_T_HPP

#include "etl/_config/builtin_types.hpp"
#include "etl/_config/compiler.hpp"

namespace etl {

#if defined(TETL_MSVC)
#pragma warning(disable : 4324) // Padding was added at the end of a structure
#endif

/// \brief etl::max_align_t is a trivial standard-layout type whose alignment
/// requirement is at least as strict (as large) as that of every scalar type.
///
/// \notes
/// [cppreference.com/w/cpp/types/max_align_t](https://en.cppreference.com/w/cpp/types/max_align_t)
struct alignas(long double) max_align_t {
};

#if defined(TETL_MSVC)
#pragma warning(default : 4324) // Padding was added at the end of a structure
#endif

} // namespace etl

#endif // TETL_DETAIL_CSTDDEF_MAX_ALIGN_T_HPP