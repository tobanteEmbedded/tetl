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

#include "etl/cassert.hpp"

#include "etl/detail/cstddef_internal.hpp"
#include "etl/detail/cstring_algorithm.hpp"

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

#if !defined(wint_t)
using wint_t = unsigned int;
#else
using wint_t = wint_t;
#endif

using tm = ::etl::detail::tm;

/// \brief Copies the wide string pointed to by src (including the terminating
/// null wide character) to wide character array pointed to by dest.
///
/// \details The behavior is undefined if the dest array is not large enough.
/// The behavior is undefined if the strings overlap.
///
/// \returns dest
///
/// \module Strings
constexpr auto wcscpy(wchar_t* dest, wchar_t const* src) -> wchar_t*
{
    TETL_ASSERT(dest != nullptr && src != nullptr);
    return detail::strcpy_impl(dest, src);
}

/// \brief Copies at most count characters of the wide string pointed to by src
/// (including the terminating null wide character) to wide character array
/// pointed to by dest.
///
/// \details If count is reached before the entire string src was copied, the
/// resulting character array is not null-terminated. If, after copying the
/// terminating null character from src, count is not reached, additional null
/// characters are written to dest until the total of count characters have
/// been written. If the strings overlap, the behavior is undefined.
///
/// \returns dest
///
/// \module Strings
constexpr auto wcsncpy(
    wchar_t* dest, wchar_t const* src, etl::size_t const count) -> wchar_t*
{
    TETL_ASSERT(dest != nullptr && src != nullptr);
    return detail::strncpy_impl(dest, src, count);
}

/// \brief Appends a copy of the wide string pointed to by src to the end of the
/// wide string pointed to by dest. The wide character src[0] replaces the null
/// terminator at the end of dest. The resulting wide string is null-terminated.
///
/// \details The behavior is undefined if the destination array is not large
/// enough for the contents of both src and dest and the terminating null
/// character. The behavior is undefined if the strings overlap.
///
/// \module Strings
constexpr auto wcscat(wchar_t* dest, wchar_t const* src) -> wchar_t*
{
    return detail::strcat_impl<wchar_t, etl::size_t>(dest, src);
}

/// \brief Appends at most count wide characters from the wide string pointed to
/// by src to the end of the character string pointed to by dest, stopping if
/// the null terminator is copied. The wide character src[0] replaces the null
/// terminator at the end of dest. The null terminator is always appended in the
/// end (so the maximum number of wide characters the function may write is
/// count+1).
///
/// \details The destination byte string must have enough space for the contents
/// of both dest and src plus the terminating null character, except that the
/// size of src is limited to count. The behavior is undefined if the strings
/// overlap.
///
/// \module Strings
constexpr auto wcsncat(
    wchar_t* dest, wchar_t const* src, etl::size_t const count) -> wchar_t*
{
    return detail::strncat_impl<wchar_t, etl::size_t>(dest, src, count);
}

/// \brief Returns the length of a wide string, that is the number of non-null
/// wide characters that precede the terminating null wide character.
///
/// \module Strings
constexpr auto wcslen(wchar_t const* str) -> etl::size_t
{
    return detail::strlen_impl<wchar_t, etl::size_t>(str);
}

} // namespace etl

#endif // TETL_CTIME_HPP