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

#ifndef TETL_DETAIL_CCTYPE_ISGRAPH_HPP
#define TETL_DETAIL_CCTYPE_ISGRAPH_HPP

#include "etl/detail/assert/macro.hpp"

#include "etl/detail/cctype/isdigit.hpp"
#include "etl/detail/cctype/islower.hpp"
#include "etl/detail/cctype/ispunct.hpp"
#include "etl/detail/cctype/isupper.hpp"

namespace etl {

/// \brief Checks if the given character is graphic (has a graphical
/// representation) as classified by the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a punctuation character, zero
/// otherwise.
///
/// \notes
/// [cppreference.com/w/cpp/string/byte/isgraph](https://en.cppreference.com/w/cpp/string/byte/isgraph)
///
/// \module Strings
[[nodiscard]] constexpr auto isgraph(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    auto const isDigit = etl::isdigit(ch) != 0;
    auto const isUpper = etl::isupper(ch) != 0;
    auto const isLower = etl::islower(ch) != 0;
    auto const isPunct = etl::ispunct(ch) != 0;

    return static_cast<int>(isDigit || isLower || isUpper || isPunct);
}
} // namespace etl

#endif // TETL_DETAIL_CCTYPE_ISGRAPH_HPP