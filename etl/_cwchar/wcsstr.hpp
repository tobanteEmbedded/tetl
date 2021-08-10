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

#ifndef TETL_CWCHAR_WCSSTR_HPP
#define TETL_CWCHAR_WCSSTR_HPP

#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

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
} // namespace etl
#endif // TETL_CWCHAR_WCSSTR_HPP