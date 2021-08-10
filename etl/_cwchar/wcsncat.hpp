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

#ifndef TETL_CWCHAR_WCSNCAT_HPP
#define TETL_CWCHAR_WCSNCAT_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

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

} // namespace etl

#endif // TETL_CWCHAR_WCSNCAT_HPP