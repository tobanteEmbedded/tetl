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

#ifndef TETL_DETAIL_STRING_ALGORITHM_HPP
#define TETL_DETAIL_STRING_ALGORITHM_HPP

#include "etl/version.hpp"

#include "etl/detail/string_char_traits.hpp"

namespace etl::detail {

/// \brief Finds the first character not equal to any of the characters in the
/// given character sequence.
template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto find_first_not_of(CharT const* f, CharT const* l,
    CharT const* const sf, CharT const* const sl) -> SizeT
{
    auto const legalChar = [sf, sl](char ch) -> bool {
        auto const* ssf = sf;
        auto const* ssl = sl;
        for (; ssf != ssl; ++ssf) {
            if (::etl::char_traits<char>::eq(*ssf, ch)) { return true; }
        }
        return false;
    };

    SizeT counter { 0 };
    for (; f != l; ++f) {
        if (!legalChar(*f)) { return counter; }
        ++counter;
    }

    return static_cast<SizeT>(-1);
}

template <typename CharT>
auto replace_impl(CharT* f, CharT* l, CharT ch) -> void
{
    for (; f != l; ++f) { *f = ch; }
}

template <typename CharT>
auto replace_impl(CharT* f, CharT* l, CharT const* sf, CharT const* sl) -> void
{
    for (; (f != l) && (sf != sl); ++f, ++sf) { *f = *sf; }
}
} // namespace etl

#endif // TETL_DETAIL_STRING_ALGORITHM_HPP