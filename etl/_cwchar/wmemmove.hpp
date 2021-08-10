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

#ifndef TETL_CWCHAR_WMEMMOVE_HPP
#define TETL_CWCHAR_WMEMMOVE_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

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
} // namespace etl
#endif // TETL_CWCHAR_WMEMMOVE_HPP