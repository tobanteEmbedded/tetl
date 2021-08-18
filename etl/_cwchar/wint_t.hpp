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

#ifndef TETL_CWCHAR_WINT_T_HPP
#define TETL_CWCHAR_WINT_T_HPP

#include "etl/_config/builtin_types.hpp"
#include "etl/_config/compiler.hpp"

#if defined(TETL_MSVC)
#include <wchar.h>
#else

#if !defined(WEOF)
#define WEOF (static_cast<wint_t>(-1))
#endif

#if !defined(WCHAR_MIN)
#define WCHAR_MIN TETL_WCHAR_MIN
#endif

#if !defined(WCHAR_MAX)
#define WCHAR_MAX TETL_WCHAR_MAX
#endif

#endif

namespace etl {

#if !defined(wint_t)
using wint_t = unsigned int;
#else
using wint_t = wint_t;
#endif

} // namespace etl

#endif // TETL_CWCHAR_WINT_T_HPP