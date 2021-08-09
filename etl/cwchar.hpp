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

#include "etl/_assert/macro.hpp"
#include "etl/_cstddef/null.hpp"
#include "etl/_cstddef/nullptr_t.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_cstddef/tm.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

#if defined(TETL_MSVC)
#include <wchar.h>
#else

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

/// \brief Compares two null-terminated wide strings lexicographically.
///
/// \details The sign of the result is the sign of the difference between the
/// values of the first pair of wide characters that differ in the strings being
/// compared.
///
/// The behavior is undefined if lhs or rhs are not pointers to null-terminated
/// wide strings.
///
/// \module Strings
[[nodiscard]] constexpr auto wcscmp(wchar_t const* lhs, wchar_t const* rhs)
    -> int
{
    return detail::strcmp_impl<wchar_t>(lhs, rhs);
}

/// \brief Compares at most count wide characters of two null-terminated wide
/// strings. The comparison is done lexicographically.
///
/// \details The sign of the result is the sign of the difference between the
/// values of the first pair of wide characters that differ in the strings being
/// compared.
///
/// The behavior is undefined if lhs or rhs are not pointers to null-terminated
/// strings.
///
/// \module Strings
[[nodiscard]] constexpr auto wcsncmp(
    wchar_t const* lhs, wchar_t const* rhs, etl::size_t count) -> int
{
    return detail::strncmp_impl<wchar_t, etl::size_t>(lhs, rhs, count);
}

/// \brief Finds the first occurrence of the wide character ch in the wide
/// string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcschr
///
/// \module Strings
[[nodiscard]] constexpr auto wcschr(wchar_t* str, int ch) -> wchar_t*
{
    return detail::strchr_impl<wchar_t>(str, ch);
}

/// \brief Finds the first occurrence of the wide character ch in the wide
/// string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcschr
///
/// \module Strings
[[nodiscard]] constexpr auto wcschr(wchar_t const* str, int ch)
    -> wchar_t const*
{
    return detail::strchr_impl<wchar_t const>(str, ch);
}

/// \brief Finds the last occurrence of the wide character ch in the wide string
/// pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcsrchr
///
/// \module Strings
[[nodiscard]] constexpr auto wcsrchr(wchar_t* str, int ch) -> wchar_t*
{
    return detail::strrchr_impl<wchar_t, etl::size_t>(str, ch);
}

/// \brief Finds the last occurrence of the wide character ch in the wide string
/// pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcsrchr
///
/// \module Strings
[[nodiscard]] constexpr auto wcsrchr(wchar_t const* str, int ch)
    -> wchar_t const*
{
    return detail::strrchr_impl<wchar_t const, etl::size_t>(str, ch);
}

/// \brief Returns the length of the maximum initial segment of the wide string
/// pointed to by dest, that consists of only the characters found in wide
/// string pointed to by src.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcsspn
///
/// \module Strings
[[nodiscard]] constexpr auto wcsspn(
    wchar_t const* dest, wchar_t const* src) noexcept -> etl::size_t
{
    return detail::str_span_impl<wchar_t, etl::size_t, true>(dest, src);
}

/// \brief Returns the length of the maximum initial segment of the wide string
/// pointed to by dest, that consists of only the characters not found in wide
/// string pointed to by src.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcscspn
///
/// \module Strings
[[nodiscard]] constexpr auto wcscspn(
    wchar_t const* dest, wchar_t const* src) noexcept -> etl::size_t
{
    return detail::str_span_impl<wchar_t, etl::size_t, false>(dest, src);
}

/// \brief Finds the first character in wide string pointed to by dest, that is
/// also in wide string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
///
/// \module Strings
[[nodiscard]] constexpr auto wcspbrk(wchar_t* dest, wchar_t* breakset) noexcept
    -> wchar_t*
{
    return detail::strpbrk_impl<wchar_t, etl::size_t>(dest, breakset);
}

/// \brief Finds the first character in wide string pointed to by dest, that is
/// also in wide string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
///
/// \module Strings
[[nodiscard]] constexpr auto wcspbrk(
    wchar_t const* dest, wchar_t const* breakset) noexcept -> wchar_t const*
{
    return detail::strpbrk_impl<wchar_t const, etl::size_t>(dest, breakset);
}

/// \brief Finds the first occurrence of the wide string needle in the wide
/// string pointed to by haystack. The terminating null characters are not
/// compared.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
///
/// \module Strings
[[nodiscard]] constexpr auto wcsstr(wchar_t* haystack, wchar_t* needle) noexcept
    -> wchar_t*
{
    return detail::strstr_impl<wchar_t>(haystack, needle);
}

/// \brief Finds the first occurrence of the wide string needle in the wide
/// string pointed to by haystack. The terminating null characters are not
/// compared.
///
/// https://en.cppreference.com/w/cpp/string/wide/wcspbrk
///
/// \module Strings
[[nodiscard]] constexpr auto wcsstr(
    wchar_t const* haystack, wchar_t const* needle) noexcept -> wchar_t const*
{
    return detail::strstr_impl<wchar_t const>(haystack, needle);
}

/// \brief Copies exactly count successive wide characters from the wide
/// character array pointed to by src to the wide character array pointed to by
/// dest. If the objects overlap, the behavior is undefined. If count is zero,
/// the function does nothing.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemcpy
///
/// \module Strings
constexpr auto wmemcpy(
    wchar_t* dest, const wchar_t* src, etl::size_t count) noexcept -> wchar_t*
{
    return detail::strncpy_impl(dest, src, count);
}

/// \brief Copies exactly count successive wide characters from the wide
/// character array pointed to by src to the wide character array pointed to by
/// dest.
///
/// \details If count is zero, the function does nothing. The arrays may
/// overlap: copying takes place as if the wide characters were copied to a
/// temporary wide character array and then copied from the temporary array to
/// dest. This function is not locale-sensitive and pays no attention to the
/// values of the wchar_t objects it copies: nulls as well as invalid characters
/// are copied too.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemmove
///
/// \module Strings
constexpr auto wmemmove(
    wchar_t* dest, const wchar_t* src, etl::size_t count) noexcept -> wchar_t*
{
    return detail::memmove_impl<wchar_t, etl::size_t>(dest, src, count);
}

/// \brief Compares the first count wide characters of the wide character arrays
/// pointed to by lhs and rhs. The comparison is done lexicographically.
///
/// \details The sign of the result is the sign of the difference between the
/// values of the first pair of wide characters that differ in the arrays being
/// compared. If count is zero, the function does nothing.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemcmp
///
/// \module Strings
constexpr auto wmemcmp(
    wchar_t const* lhs, const wchar_t* rhs, etl::size_t count) noexcept -> int
{
    return detail::strncmp_impl<wchar_t, etl::size_t>(lhs, rhs, count);
}

/// \brief Locates the first occurrence of wide character ch in the initial
/// count wide characters of the wide character array pointed to by ptr.
///
/// \details If count is zero, the function returns a null pointer.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemchr
///
/// \module Strings
[[nodiscard]] constexpr auto wmemchr(
    wchar_t* ptr, wchar_t ch, etl::size_t count) noexcept -> wchar_t*
{
    return detail::memchr_impl<wchar_t>(ptr, ch, count);
}

/// \brief Locates the first occurrence of wide character ch in the initial
/// count wide characters of the wide character array pointed to by ptr.
///
/// \details If count is zero, the function returns a null pointer.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemchr
///
/// \module Strings
[[nodiscard]] constexpr auto wmemchr(wchar_t const* ptr, wchar_t ch,
    etl::size_t count) noexcept -> wchar_t const*
{
    return detail::memchr_impl<wchar_t const>(ptr, ch, count);
}

/// \brief Copies the wide character ch into each of the first count wide
/// characters of the wide character array pointed to by dest.
///
/// \details If overflow occurs, the behavior is undefined. If count is zero,
/// the function does nothing.
///
/// https://en.cppreference.com/w/cpp/string/wide/wmemset
///
/// \module Strings
constexpr auto wmemset(wchar_t* dest, wchar_t ch, etl::size_t count) noexcept
    -> wchar_t*
{
    return detail::memset_impl(dest, ch, count);
}
} // namespace etl

#endif // TETL_CTIME_HPP