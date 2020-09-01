
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

#include "byte.hpp"
#include "definitions.hpp"

namespace etl
{
/**
 * @brief Copy the first n bytes pointed to by src to the buffer pointed to by
 * dest. Source and destination may not overlap. If source and destination might
 * overlap, memmove() must be used instead.
 */
constexpr auto memcpy(void* dest, const void* src, etl::size_t n) -> void*
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
constexpr auto memmove(void* dest, const void* src, etl::size_t n) -> void*
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

/**
 * @brief Returns the length of the C string str.
 */
constexpr auto strlen(const char* str) -> etl::size_t
{
    const char* s = nullptr;
    for (s = str; *s != 0; ++s) { ; }
    return static_cast<etl::size_t>(s - str);
}

}  // namespace etl
#endif  // TAETL_CSTRING_HPP
