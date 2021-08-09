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

#include "etl/_assert/macro.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

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
    return detail::strcpy_impl(dest, src);
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
    return detail::strncpy_impl(dest, src, count);
}

/// \brief Returns the length of the C string str.
/// \module Strings
constexpr auto strlen(char const* str) -> etl::size_t
{
    return detail::strlen_impl<char, etl::size_t>(str);
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
    return detail::strcat_impl<char, etl::size_t>(dest, src);
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
    return detail::strncat_impl<char, etl::size_t>(dest, src, count);
}

/// \brief Compares the C string lhs to the C string rhs.
///
/// \details This function starts comparing the first character of each string.
/// If they are equal to each other, it continues with the following pairs until
/// the characters differ or until a terminating null-character is reached.
/// \module Strings
constexpr auto strcmp(char const* lhs, char const* rhs) -> int
{
    return detail::strcmp_impl<char>(lhs, rhs);
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
    return detail::strncmp_impl<char, etl::size_t>(lhs, rhs, count);
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
    return detail::strrchr_impl<char const, etl::size_t>(str, ch);
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
    return detail::strrchr_impl<char, etl::size_t>(str, ch);
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
    return detail::str_span_impl<char, etl::size_t, true>(dest, src);
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
    return detail::str_span_impl<char, etl::size_t, false>(dest, src);
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
    return detail::strpbrk_impl<char const, etl::size_t>(dest, breakset);
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
    return detail::strpbrk_impl<char, etl::size_t>(dest, breakset);
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

/// \brief Converts ch to unsigned char and locates the first occurrence of that
/// value in the initial count characters (each interpreted as unsigned char) of
/// the object pointed to by ptr.
///
/// \details This function behaves as if it reads the characters sequentially
/// and stops as soon as a matching character is found: if the array pointed to
/// by ptr is smaller than count, but the match is found within the array, the
/// behavior is well-defined.
///
/// https://en.cppreference.com/w/cpp/string/byte/memchr
///
/// \returns Pointer to the location of the character, or a null pointer if no
/// such character is found.
///
/// \module Strings
[[nodiscard]] constexpr auto memchr(void* ptr, int ch, etl::size_t n) -> void*
{
    auto* p = static_cast<unsigned char*>(ptr);
    return detail::memchr_impl(p, static_cast<unsigned char>(ch), n);
}

/// \brief Converts ch to unsigned char and locates the first occurrence of that
/// value in the initial count characters (each interpreted as unsigned char) of
/// the object pointed to by ptr.
///
/// \details This function behaves as if it reads the characters sequentially
/// and stops as soon as a matching character is found: if the array pointed to
/// by ptr is smaller than count, but the match is found within the array, the
/// behavior is well-defined.
///
/// https://en.cppreference.com/w/cpp/string/byte/memchr
///
/// \returns Pointer to the location of the character, or a null pointer if no
/// such character is found.
///
/// \module Strings
[[nodiscard]] constexpr auto memchr(void const* ptr, int ch, etl::size_t n)
    -> void const*
{
    auto const* const p = static_cast<unsigned char const*>(ptr);
    auto const c        = static_cast<unsigned char>(ch);
    return detail::memchr_impl<unsigned char const, etl::size_t>(p, c, n);
}

/// \brief Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may not overlap. If source and destination
/// might overlap, memmove() must be used instead.
///
/// \module Strings
constexpr auto memcpy(void* dest, void const* src, etl::size_t n) -> void*
{
    return detail::memcpy_impl<unsigned char, etl::size_t>(dest, src, n);
}

/// \brief Copies the value of c (converted to an unsigned char) into each of
/// the ﬁrst n characters of the object pointed to by s.
/// \module Strings
constexpr auto memset(void* s, int c, etl::size_t n) -> void*
{
    return detail::memset_impl(static_cast<unsigned char*>(s), c, n);
}

/// \brief Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may overlap.
///
/// \module Strings
constexpr auto memmove(void* dest, void const* src, etl::size_t count) -> void*
{
    return detail::memmove_impl<unsigned char>(dest, src, count);
}

} // namespace etl
#endif // TETL_CSTRING_HPP
