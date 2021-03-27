/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CSTRING_HPP
#define TAETL_CSTRING_HPP

#include "etl/cassert.hpp"
#include "etl/cstddef.hpp"

namespace etl
{
/**
 * @brief The macro NULL is an implementation-defined null pointer constant.
 */
#define TAETL_NULL nullptr

/**
 * @brief Copies the character string pointed to by src, including the null
 * terminator, to the character array whose first element is pointed to by dest.
 *
 * @details The behavior is undefined if the dest array is not large enough. The
 * behavior is undefined if the strings overlap.
 *
 * @return dest
 */
constexpr auto strcpy(char* dest, char const* src) -> char*
{
  assert(dest != nullptr && src != nullptr);
  auto* temp = dest;
  while ((*dest++ = *src++) != '\0') { ; }
  return temp;
}

/**
 * @brief Copies at most count characters of the byte string pointed to by src
 * (including the terminating null character) to character array pointed to by
 * dest.
 *
 * @details If count is reached before the entire string src was copied, the
 * resulting character array is not null-terminated. If, after copying the
 * terminating null character from src, count is not reached, additional null
 * characters are written to dest until the total of count characters have been
 * written. If the strings overlap, the behavior is undefined.
 *
 * @return dest
 */
constexpr auto strncpy(char* dest, char const* src, etl::size_t const count)
  -> char*
{
  assert(dest != nullptr && src != nullptr);
  auto* temp = dest;
  for (etl::size_t counter = 0; *src != '\0' && counter != count;)
  {
    *dest = *src;
    ++src;
    ++dest;
    ++counter;
  }

  return temp;
}

/**
 * @brief Returns the length of the C string str.
 */
constexpr auto strlen(char const* str) -> etl::size_t
{
  char const* s = nullptr;
  for (s = str; *s != 0; ++s) { ; }
  return static_cast<etl::size_t>(s - str);
}

/**
 * @brief Appends a copy of the character string pointed to by src to the end of
 * the character string pointed to by dest. The character src[0] replaces the
 * null terminator at the end of dest. The resulting byte string is
 * null-terminated.
 *
 * @details The behavior is undefined if the destination array is not large
 * enough for the contents of both src and dest and the terminating null
 * character. The behavior is undefined if the strings overlap.
 */
constexpr auto strcat(char* dest, char const* src) -> char*
{
  auto* ptr = dest + etl::strlen(dest);
  while (*src != '\0') { *ptr++ = *src++; }
  *ptr = '\0';
  return dest;
}

/**
 * @brief Appends a byte string pointed to by src to a byte string pointed to by
 * dest. At most count characters are copied. The resulting byte string is
 * null-terminated.
 *
 * @details The destination byte string must have enough space for the contents
 * of both dest and src plus the terminating null character, except that the
 * size of src is limited to count. The behavior is undefined if the strings
 * overlap.
 */
constexpr auto strncat(char* dest, char const* src, etl::size_t const count)
  -> char*
{
  auto* ptr                = dest + etl::strlen(dest);
  etl::size_t localCounter = 0;
  while (*src != '\0' && localCounter != count)
  {
    *ptr++ = *src++;
    ++localCounter;
  }

  *ptr = '\0';
  return dest;
}

/**
 * @brief Compares the C string lhs to the C string rhs.
 *
 * @details This function starts comparing the first character of each string.
 * If they are equal to each other, it continues with the following pairs until
 * the characters differ or until a terminating null-character is reached.
 */
constexpr auto strcmp(char const* lhs, char const* rhs) -> int
{
  for (; *lhs != '\0'; ++lhs, ++rhs)
  {
    if (*lhs != *rhs) { break; }
  }

  return static_cast<unsigned char>(*lhs) - static_cast<unsigned char>(*rhs);
}

/**
 * @brief Compares at most count characters of two possibly null-terminated
 * arrays. The comparison is done lexicographically. Characters following the
 * null character are not compared.
 *
 * @details The behavior is undefined when access occurs past the end of either
 * array lhs or rhs. The behavior is undefined when either lhs or rhs is the
 * null pointer.
 */
constexpr auto strncmp(char const* lhs, char const* rhs,
                       etl::size_t const count) -> int
{
  unsigned char u1 {};
  unsigned char u2 {};

  auto localCount = count;
  while (localCount-- > 0)
  {
    u1 = static_cast<unsigned char>(*lhs++);
    u2 = static_cast<unsigned char>(*rhs++);
    if (u1 != u2) { return u1 - u2; }
    if (u1 == '\0') { return 0; }
  }

  return 0;
}

/**
 * @brief Copy the first n bytes pointed to by src to the buffer pointed to by
 * dest. Source and destination may not overlap. If source and destination might
 * overlap, memmove() must be used instead.
 */
constexpr auto memcpy(void* dest, void const* src, etl::size_t n) -> void*
{
  auto* dp       = static_cast<etl::byte*>(dest);
  auto const* sp = static_cast<etl::byte const*>(src);
  while (n-- != 0) { *dp++ = *sp++; }
  return dest;
}

/**
 * @brief Copies the value of c (converted to an unsigned char) into each of the
 * ﬁrst n characters of the object pointed to by s.
 */
constexpr auto memset(void* s, int c, etl::size_t n) -> void*
{
  auto* p = static_cast<etl::byte*>(s);
  while (n-- != 0) { *p++ = static_cast<etl::byte>(c); }
  return s;
}

/**
 * @brief Copy the first n bytes pointed to by src to the buffer pointed to by
 * dest. Source and destination may overlap.
 *
 * @todo Check original implementation. They use __np_anyptrlt which is not
 * portable. https://clc-wiki.net/wiki/C_standard_library:string.h:memmove
 */
constexpr auto memmove(void* dest, void const* src, etl::size_t n) -> void*
{
  auto const* ps = static_cast<etl::byte const*>(src);
  auto* pd       = static_cast<etl::byte*>(dest);

  if (ps < pd)
  {
    for (pd += n, ps += n; n-- != 0;) { *--pd = *--ps; }
  }
  else
  {
    while (n-- != 0) { *pd++ = *ps++; }
  }

  return dest;
}

}  // namespace etl
#endif  // TAETL_CSTRING_HPP
