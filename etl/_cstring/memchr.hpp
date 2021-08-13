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

#ifndef TETL_CSTRING_MEMCHR_HPP
#define TETL_CSTRING_MEMCHR_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

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

} // namespace etl

#endif // TETL_CSTRING_MEMCHR_HPP