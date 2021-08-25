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

#ifndef TETL_FORMAT_ARGUMENT_HPP
#define TETL_FORMAT_ARGUMENT_HPP

#include "etl/_format/formatter.hpp"

namespace etl::detail {
// Escape tokens
inline constexpr auto token_begin = '{';
inline constexpr auto token_end   = '}';

template <typename ValueT, typename FormatContext>
auto format_argument(ValueT const& val, FormatContext& fc) -> decltype(fc.out())
{
    auto f = formatter<ValueT, char> {};
    return f.format(val, fc);
}

inline auto split_at_next_argument(etl::string_view str)
    -> etl::pair<etl::string_view, etl::string_view>
{
    using size_type = etl::string_view::size_type;

    auto const* res = etl::find(begin(str), end(str), token_begin);
    if (res != end(str) && *etl::next(res) == token_end) {
        auto index  = static_cast<size_type>(etl::distance(begin(str), res));
        auto first  = str.substr(0, index);
        auto second = str.substr(index + 2);
        return etl::make_pair(first, second);
    }

    return etl::make_pair(str, etl::string_view {});
}

template <typename FormatContext>
auto format_escaped_sequences(etl::string_view str, FormatContext& ctx) -> void
{
    // Loop as long as escaped sequences are found.
    auto const* first = begin(str);
    while (true) {
        // Find open sequence {{
        const auto* const openFirst = etl::find(first, end(str), token_begin);
        const auto* const openSec   = etl::next(openFirst);
        auto const escapeStart      = openFirst != end(str) //
                                 && openSec != end(str)     //
                                 && *openSec == token_begin;

        if (escapeStart) {
            // Copy upto {{
            detail::format_argument(etl::string_view(first, openFirst), ctx);

            // Find sequence }}
            auto const* closeFirst
                = etl::find(etl::next(openSec), end(str), token_end);
            auto const* closeSec = etl::next(closeFirst);
            auto escapeClose     = closeFirst != end(str) //
                               && closeSec != end(str)    //
                               && *closeSec == token_end;

            // Copy everything between {{ ... }}, but only one curly each.
            if (escapeClose) {
                detail::format_argument(
                    etl::string_view(openSec, closeFirst + 1), ctx);
                first = closeFirst + 2;
            } else {
                // No closing "}}" found
                TETL_ASSERT(false);
                return;
            }
        } else {
            // No more escaped sequence found, copy rest.
            detail::format_argument(etl::string_view(first, end(str)), ctx);
            return;
        }
    }
}

} // namespace etl::detail

#endif // TETL_FORMAT_ARGUMENT_HPP
