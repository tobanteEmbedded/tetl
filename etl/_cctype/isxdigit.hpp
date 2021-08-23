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

#ifndef TETL_CCTYPE_ISXDIGIT_HPP
#define TETL_CCTYPE_ISXDIGIT_HPP

#include "etl/_assert/macro.hpp"

namespace etl {
/// \brief Checks if the given character is a hexadecimal numeric character
/// (0123456789abcdefABCDEF).
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a hexadecimal numeric character,
/// zero otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isxdigit
///
/// \module Strings
[[nodiscard]] constexpr auto isxdigit(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    auto const isDigit    = ch >= '0' && ch <= '9';
    auto const isHexLower = ch >= 'a' && ch <= 'f';
    auto const isHexUpper = ch >= 'A' && ch <= 'F';

    return static_cast<int>(isDigit || isHexLower || isHexUpper);
}
} // namespace etl

#endif // TETL_CCTYPE_ISXDIGIT_HPP