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

#ifndef TETL_CSTDARG_HPP
#define TETL_CSTDARG_HPP

#include "etl/version.hpp"

#if defined(TETL_MSVC)
#include <cstdarg>
#endif

namespace etl
{
#if not defined(TETL_MSVC)

/// \brief va_list is a complete object type suitable for holding the
/// information needed by the macros va_start, va_copy, va_arg, and va_end. If a
/// va_list instance is created, passed to another function, and used via va_arg
/// in that function, then any subsequent use in the calling function should be
/// preceded by a call to va_end. It is legal to pass a pointer to a va_list
/// object to another function and then use that object after the function
/// returns.
///
/// \notes
/// [cppreference.com/w/cpp/utility/variadic/va_list](https://en.cppreference.com/w/cpp/utility/variadic/va_list)
using va_list = TETL_BUILTIN_VA_LIST;
#else
using va_list = ::std::va_list;
#endif
}  // namespace etl

#if not defined(va_start)

/// \brief The va_start macro enables access to the variable arguments following
/// the named argument parm_n. va_start should be invoked with an instance to a
/// valid va_list object ap before any calls to va_arg.
/// If the parm_n is a pack expansion or an entity resulting from a
/// lambda capture, the program is ill-formed, no diagnostic required. If parm_n
/// is declared with reference type or with a type not compatible with the type
/// that results from default argument promotions, the behavior is undefined.
///
/// \notes
/// [cppreference.com/w/cpp/utility/variadic/va_start](https://en.cppreference.com/w/cpp/utility/variadic/va_start)
#define va_start(ap, param) __builtin_va_start(ap, param)
#endif

#if not defined(va_end)

/// \brief The va_end macro performs cleanup for an ap object initialized by a
/// call to va_start or va_copy. va_end may modify ap so that it is no longer
/// usable.
///
/// \details If there is no corresponding call to va_start or va_copy, or if
/// va_end is not called before a function that calls va_start or va_copy
/// returns, the behavior is undefined.
///
/// \notes
/// [cppreference.com/w/cpp/utility/variadic/va_end](https://en.cppreference.com/w/cpp/utility/variadic/va_end)
#define va_end(ap) __builtin_va_end(ap)
#endif

#if not defined(va_arg)

/// \brief The va_arg macro expands to an expression of type T that corresponds
/// to the next parameter from the va_list ap. Prior to calling va_arg, ap must
/// be initialized by a call to either va_start or va_copy, with no intervening
/// call to va_end. Each invocation of the va_arg macro modifies ap to point to
/// the next variable argument.
///
/// \notes
/// [cppreference.com/w/cpp/utility/variadic/va_arg](https://en.cppreference.com/w/cpp/utility/variadic/va_arg)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#endif

#if not defined(va_copy)

/// \brief The va_copy macro copies src to dest.
///
/// \details va_end should be called on dest before the function returns or any
/// subsequent re-initialization of dest (via calls to va_start or va_copy).
///
/// \notes
/// [cppreference.com/w/cpp/utility/variadic/va_copy](https://en.cppreference.com/w/cpp/utility/variadic/va_copy)
#define va_copy(dest, src) __builtin_va_copy(dest, src)
#endif

#endif  // TETL_CSTDARG_HPP
