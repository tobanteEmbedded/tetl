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

#ifndef TETL_CTIME_HPP
#define TETL_CTIME_HPP

#include "etl/version.hpp"

#include "etl/detail/cstddef_internal.hpp"

#if defined(TETL_MSVC)
#include <wchar.h>
#else

#if !defined(NULL)
#define NULL nullptr
#endif // NULL

#if !defined(WEOF)
#define WEOF ((wint_t)-1)
#endif

#if !defined(WCHAR_MIN)
#define WCHAR_MIN TETL_DETAIL_WCHAR_MIN
#endif

#if !defined(WCHAR_MAX)
#define WCHAR_MAX TETL_DETAIL_WCHAR_MAX
#endif

#endif

namespace etl {

using wint_t = unsigned short;
using tm     = ::etl::detail::tm;

} // namespace etl

#endif // TETL_CTIME_HPP