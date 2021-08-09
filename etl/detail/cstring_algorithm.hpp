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

#ifndef TETL_DETAIL_CSTRING_ALGORITHM_HPP
#define TETL_DETAIL_CSTRING_ALGORITHM_HPP

#include "etl/version.hpp"

namespace etl::detail {

template <typename CharT>
[[nodiscard]] constexpr auto strcpy_impl(CharT* dest, CharT const* src)
    -> CharT*
{
    auto* temp = dest;
    while ((*dest++ = *src++) != CharT(0)) { ; }
    return temp;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strncpy_impl(
    CharT* dest, CharT const* src, SizeT count) -> CharT*
{
    auto* temp = dest;
    for (SizeT counter = 0; *src != CharT(0) && counter != count;) {
        *dest = *src;
        ++src;
        ++dest;
        ++counter;
    }

    return temp;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strlen_impl(CharT const* str) -> SizeT
{
    CharT const* s = nullptr;
    for (s = str; *s != CharT(0); ++s) { ; }
    return static_cast<SizeT>(s - str);
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strcat_impl(CharT* dest, CharT const* src)
    -> CharT*
{
    auto* ptr = dest + strlen_impl<CharT, SizeT>(dest);
    while (*src != CharT(0)) { *ptr++ = *src++; }
    *ptr = CharT(0);
    return dest;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strncat_impl(
    CharT* dest, CharT const* src, SizeT const count) -> CharT*
{
    auto* ptr          = dest + strlen_impl<CharT, SizeT>(dest);
    SizeT localCounter = 0;
    while (*src != CharT(0) && localCounter != count) {
        *ptr++ = *src++;
        ++localCounter;
    }

    *ptr = CharT(0);
    return dest;
}

template <typename CharT>
[[nodiscard]] constexpr auto strcmp_impl(CharT const* lhs, CharT const* rhs)
    -> int
{
    for (; *lhs != CharT(0); ++lhs, ++rhs) {
        if (*lhs != *rhs) { break; }
    }
    return static_cast<int>(*lhs) - static_cast<int>(*rhs);
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strncmp_impl(
    CharT const* lhs, CharT const* rhs, SizeT const count) -> int
{
    CharT u1 {};
    CharT u2 {};

    auto localCount = count;
    while (localCount-- > 0) {
        u1 = static_cast<CharT>(*lhs++);
        u2 = static_cast<CharT>(*rhs++);
        if (u1 != u2) { return static_cast<int>(u1 - u2); }
        if (u1 == CharT(0)) { return 0; }
    }

    return 0;
}

template <typename CharT>
[[nodiscard]] constexpr auto strchr_impl(CharT* str, int ch) -> CharT*
{
    if (str == nullptr) { return nullptr; }

    while (*str != CharT(0)) {
        if (*str == static_cast<CharT>(ch)) { return str; }
        ++str;
    }

    if (static_cast<CharT>(ch) == CharT(0)) { return str; }
    return nullptr;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strrchr_impl(CharT* str, int ch) -> CharT*
{
    if (str == nullptr) { return nullptr; }
    auto len = strlen_impl<CharT, SizeT>(str);
    if (static_cast<CharT>(ch) == CharT(0)) { return str + len; }

    while (len-- != 0) {
        if (str[len] == static_cast<CharT>(ch)) { return str + len; }
    }

    return nullptr;
}

template <typename CharT, typename SizeT, bool InclusiveSearch>
[[nodiscard]] constexpr auto is_legal_char_impl(
    CharT const* options, SizeT len, CharT ch) noexcept -> bool
{
    for (SizeT i = 0; i < len; ++i) {
        if (options[i] == ch) { return InclusiveSearch; }
    }
    return !InclusiveSearch;
}

template <typename CharT, typename SizeT, bool InclusiveSearch>
[[nodiscard]] constexpr auto str_span_impl(
    CharT const* dest, CharT const* src) noexcept -> SizeT
{
    auto result       = SizeT { 0 };
    auto const length = strlen_impl<CharT, SizeT>(dest);
    auto const srcLen = strlen_impl<CharT, SizeT>(src);
    for (SizeT i = 0; i < length; ++i) {
        if (!is_legal_char_impl<CharT, SizeT, InclusiveSearch>(
                src, srcLen, dest[i])) {
            break;
        }
        ++result;
    }

    return result;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strpbrk_impl(CharT* s, CharT* del) noexcept
    -> CharT*
{
    auto const i = str_span_impl<CharT, SizeT, false>(s, del);
    if (i != 0) { return s + i; }
    if (is_legal_char_impl<CharT, SizeT, true>(
            del, strlen_impl<CharT, SizeT>(del), s[0])) {
        return s;
    }
    return nullptr;
}

template <typename CharT>
[[nodiscard]] constexpr auto strstr_impl(
    CharT* haystack, CharT* needle) noexcept -> CharT*
{
    while (*haystack != CharT(0)) {
        if ((*haystack == *needle) && (strcmp_impl(haystack, needle) == 0)) {
            return haystack;
        }
        haystack++;
    }
    return nullptr;
}

} // namespace etl::detail

#endif // TETL_DETAIL_CSTRING_ALGORITHM_HPP