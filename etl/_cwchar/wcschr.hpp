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

#ifndef TETL_CWCHAR_WCSCHR_HPP
#define TETL_CWCHAR_WCSCHR_HPP

#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {
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
} // namespace etl
#endif // TETL_CWCHAR_WCSCHR_HPP