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

#ifndef TETL_CSTRING_HPP
#define TETL_CSTRING_HPP

#include "etl/version.hpp"

#include "etl/cassert.hpp"
#include "etl/cstddef.hpp"

namespace etl {
/// \brief Copies the character string pointed to by src, including the null
/// terminator, to the character array whose first element is pointed to by
/// dest.
///
/// \details The behavior is undefined if the dest array is not large enough.
/// The behavior is undefined if the strings overlap.
///
/// \returns dest
/// \module Strings
constexpr auto strcpy(char* dest, char const* src) -> char*
{
    TETL_ASSERT(dest != nullptr && src != nullptr);
    auto* temp = dest;
    while ((*dest++ = *src++) != '\0') { ; }
    return temp;
}

/// \brief Copies at most count characters of the byte string pointed to by src
/// (including the terminating null character) to character array pointed to by
/// dest.
///
/// \details If count is reached before the entire string src was copied, the
/// resulting character array is not null-terminated. If, after copying the
/// terminating null character from src, count is not reached, additional null
/// characters are written to dest until the total of count characters have
/// been written. If the strings overlap, the behavior is undefined.
///
/// \returns dest
/// \module Strings
constexpr auto strncpy(char* dest, char const* src, etl::size_t const count)
    -> char*
{
    TETL_ASSERT(dest != nullptr && src != nullptr);
    auto* temp = dest;
    for (etl::size_t counter = 0; *src != '\0' && counter != count;) {
        *dest = *src;
        ++src;
        ++dest;
        ++counter;
    }

    return temp;
}

/// \brief Returns the length of the C string str.
/// \module Strings
constexpr auto strlen(char const* str) -> etl::size_t
{
    char const* s = nullptr;
    for (s = str; *s != 0; ++s) { ; }
    return static_cast<etl::size_t>(s - str);
}

/// \brief Appends a copy of the character string pointed to by src to the end
/// of the character string pointed to by dest. The character src[0] replaces
/// the null terminator at the end of dest. The resulting byte string is
/// null-terminated.
///
/// \details The behavior is undefined if the destination array is not large
/// enough for the contents of both src and dest and the terminating null
/// character. The behavior is undefined if the strings overlap.
/// \module Strings
constexpr auto strcat(char* dest, char const* src) -> char*
{
    auto* ptr = dest + etl::strlen(dest);
    while (*src != '\0') { *ptr++ = *src++; }
    *ptr = '\0';
    return dest;
}

/// \brief Appends a byte string pointed to by src to a byte string pointed to
/// by dest. At most count characters are copied. The resulting byte string is
/// null-terminated.
///
/// \details The destination byte string must have enough space for the contents
/// of both dest and src plus the terminating null character, except that the
/// size of src is limited to count. The behavior is undefined if the strings
/// overlap.
/// \module Strings
constexpr auto strncat(char* dest, char const* src, etl::size_t const count)
    -> char*
{
    auto* ptr                = dest + etl::strlen(dest);
    etl::size_t localCounter = 0;
    while (*src != '\0' && localCounter != count) {
        *ptr++ = *src++;
        ++localCounter;
    }

    *ptr = '\0';
    return dest;
}

/// \brief Compares the C string lhs to the C string rhs.
///
/// \details This function starts comparing the first character of each string.
/// If they are equal to each other, it continues with the following pairs until
/// the characters differ or until a terminating null-character is reached.
/// \module Strings
constexpr auto strcmp(char const* lhs, char const* rhs) -> int
{
    for (; *lhs != '\0'; ++lhs, ++rhs) {
        if (*lhs != *rhs) { break; }
    }

    return static_cast<unsigned char>(*lhs) - static_cast<unsigned char>(*rhs);
}

/// \brief Compares at most count characters of two possibly null-terminated
/// arrays. The comparison is done lexicographically. Characters following the
/// null character are not compared.
///
/// \details The behavior is undefined when access occurs past the end of either
/// array lhs or rhs. The behavior is undefined when either lhs or rhs is the
/// null pointer.
/// \module Strings
constexpr auto strncmp(
    char const* lhs, char const* rhs, etl::size_t const count) -> int
{
    unsigned char u1 {};
    unsigned char u2 {};

    auto localCount = count;
    while (localCount-- > 0) {
        u1 = static_cast<unsigned char>(*lhs++);
        u2 = static_cast<unsigned char>(*rhs++);
        if (u1 != u2) { return u1 - u2; }
        if (u1 == '\0') { return 0; }
    }

    return 0;
}

namespace detail {
    template <typename CharT>
    [[nodiscard]] constexpr auto strchr_impl(CharT* str, int ch) -> CharT*
    {
        if (str == nullptr) { return nullptr; }

        while (*str != '\0') {
            if (*str == static_cast<char>(ch)) { return str; }
            ++str;
        }

        if (static_cast<char>(ch) == '\0') { return str; }
        return nullptr;
    }

    template <typename CharT>
    [[nodiscard]] constexpr auto strrchr_impl(CharT* str, int ch) -> CharT*
    {
        if (str == nullptr) { return nullptr; }
        auto len = static_cast<etl::size_t>(etl::strlen(str));
        if (static_cast<char>(ch) == '\0') { return str + len; }

        while (len-- != 0) {
            if (str[len] == static_cast<char>(ch)) { return str + len; }
        }

        return nullptr;
    }
}

/// \brief Finds the first occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strchr
///
/// \module Strings
[[nodiscard]] constexpr auto strchr(char const* str, int ch) -> char const*
{
    return detail::strchr_impl<char const>(str, ch);
}

/// \brief Finds the first occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strchr
///
/// \module Strings
[[nodiscard]] constexpr auto strchr(char* str, int ch) -> char*
{
    return detail::strchr_impl<char>(str, ch);
}

/// \brief Finds the last occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strrchr
///
/// \module Strings
[[nodiscard]] constexpr auto strrchr(char const* str, int ch) -> char const*
{
    return detail::strrchr_impl<char const>(str, ch);
}

/// \brief Finds the last occurrence of the character static_cast<char>(ch) in
/// the byte string pointed to by str.
///
/// \details The terminating null character is considered to be a part of the
/// string and can be found if searching for '\0'.
///
/// https://en.cppreference.com/w/cpp/string/byte/strrchr
///
/// \module Strings
[[nodiscard]] constexpr auto strrchr(char* str, int ch) -> char*
{
    return detail::strrchr_impl<char>(str, ch);
}

namespace detail {
    template <bool InclusiveSearch>
    [[nodiscard]] constexpr auto is_legal_char(
        char const* options, ::etl::size_t len, char ch) noexcept -> bool
    {
        for (etl::size_t i = 0; i < len; ++i) {
            if (options[i] == ch) { return InclusiveSearch; }
        }
        return !InclusiveSearch;
    }

    template <bool InclusiveSearch>
    [[nodiscard]] constexpr auto str_span_impl(
        char const* dest, char const* src) noexcept -> ::etl::size_t
    {
        auto result       = etl::size_t { 0 };
        auto const length = etl::strlen(dest);
        auto const srcLen = etl::strlen(src);
        for (etl::size_t i = 0; i < length; ++i) {
            if (!is_legal_char<InclusiveSearch>(src, srcLen, dest[i])) {
                break;
            }
            ++result;
        }

        return result;
    }
}

/// \brief Returns the length of the maximum initial segment (span) of the byte
/// string pointed to by dest, that consists of only the characters found in
/// byte string pointed to by src.
///
/// https://en.cppreference.com/w/cpp/string/byte/strspn
///
/// \module Strings
[[nodiscard]] constexpr auto strspn(char const* dest, char const* src) noexcept
    -> etl::size_t
{
    return detail::str_span_impl<true>(dest, src);
}

/// \brief Returns the length of the maximum initial segment of the byte string
/// pointed to by dest, that consists of only the characters not found in byte
/// string pointed to by src.
///
/// \details The function name stands for "complementary span"
///
/// https://en.cppreference.com/w/cpp/string/byte/strcspn
///
/// \module Strings
[[nodiscard]] constexpr auto strcspn(char const* dest, char const* src) noexcept
    -> etl::size_t
{
    return detail::str_span_impl<false>(dest, src);
}

namespace detail {
    template <typename CharT>
    [[nodiscard]] constexpr auto strpbrk_impl(CharT* s, CharT* del) noexcept
        -> CharT*
    {
        auto const i = str_span_impl<false>(s, del);
        if (i != 0) { return s + i; }
        if (is_legal_char<true>(del, etl::strlen(del), s[0])) { return s; }
        return nullptr;
    }
}

/// \brief Scans the null-terminated byte string pointed to by dest for any
/// character from the null-terminated byte string pointed to by breakset, and
/// returns a pointer to that character.
///
/// https://en.cppreference.com/w/cpp/string/byte/strpbrk
///
/// \module Strings
[[nodiscard]] constexpr auto strpbrk(
    char const* dest, char const* breakset) noexcept -> char const*
{
    return detail::strpbrk_impl<char const>(dest, breakset);
}

/// \brief Scans the null-terminated byte string pointed to by dest for any
/// character from the null-terminated byte string pointed to by breakset, and
/// returns a pointer to that character.
///
/// https://en.cppreference.com/w/cpp/string/byte/strpbrk
///
/// \module Strings
[[nodiscard]] constexpr auto strpbrk(char* dest, char* breakset) noexcept
    -> char*
{
    return detail::strpbrk_impl<char>(dest, breakset);
}

namespace detail {
    template <typename CharT>
    [[nodiscard]] constexpr auto strstr_impl(
        CharT* haystack, CharT* needle) noexcept -> CharT*
    {
        while (*haystack != '\0') {
            if ((*haystack == *needle) && (strcmp(haystack, needle) == 0)) {
                return haystack;
            }
            haystack++;
        }
        return nullptr;
    }
}
/// \brief Finds the first occurrence of the byte string needle in the byte
/// string pointed to by haystack. The terminating null characters are not
/// compared.
[[nodiscard]] constexpr auto strstr(char* haystack, char* needle) noexcept
    -> char*
{
    return detail::strstr_impl<char>(haystack, needle);
}

/// \brief Finds the first occurrence of the byte string needle in the byte
/// string pointed to by haystack. The terminating null characters are not
/// compared.
[[nodiscard]] constexpr auto strstr(
    char const* haystack, char const* needle) noexcept -> char const*
{
    return detail::strstr_impl<char const>(haystack, needle);
}

/// \brief Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may not overlap. If source and destination
/// might overlap, memmove() must be used instead.
/// \module Strings
constexpr auto memcpy(void* dest, void const* src, etl::size_t n) -> void*
{
    auto* dp       = static_cast<unsigned char*>(dest);
    auto const* sp = static_cast<unsigned char const*>(src);
    while (n-- != 0) { *dp++ = *sp++; }
    return dest;
}

/// \brief Copies the value of c (converted to an unsigned char) into each of
/// the ﬁrst n characters of the object pointed to by s.
/// \module Strings
constexpr auto memset(void* s, int c, etl::size_t n) -> void*
{
    auto* p = static_cast<unsigned char*>(s);
    while (n-- != 0) { *p++ = static_cast<unsigned char>(c); }
    return s;
}

/// \brief Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may overlap.
///
/// \notes Check original implementation. They use `__np_anyptrlt` which is not
/// portable.
/// [clc-wiki.net](https://clc-wiki.net/wiki/C_standard_library:string.h:memmove)
/// \module Strings
constexpr auto memmove(void* dest, void const* src, etl::size_t n) -> void*
{
    auto const* ps = static_cast<unsigned char const*>(src);
    auto* pd       = static_cast<unsigned char*>(dest);

    if (ps < pd) {
        for (pd += n, ps += n; n-- != 0;) { *--pd = *--ps; }
    } else {
        while (n-- != 0) { *pd++ = *ps++; }
    }

    return dest;
}

} // namespace etl
#endif // TETL_CSTRING_HPP
