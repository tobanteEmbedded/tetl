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

#ifndef TETL_CCTYPE_ISCNTRL_HPP
#define TETL_CCTYPE_ISCNTRL_HPP

#include "etl/_assert/macro.hpp"

namespace etl {

/// \brief Checks if the given character is a control character as classified by
/// the currently installed C locale. In the default, "C" locale, the control
/// characters are the characters with the codes 0x00-0x1F and 0x7F.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a control character, zero
/// otherwise.
///
/// \notes
/// [cppreference.com/w/cpp/string/byte/iscntrl](https://en.cppreference.com/w/cpp/string/byte/iscntrl)
///
/// \module Strings
[[nodiscard]] constexpr auto iscntrl(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>((ch >= 0x00 && ch <= 0x1f) || ch == 0x7F);
}

} // namespace etl

#endif // TETL_CCTYPE_ISCNTRL_HPP