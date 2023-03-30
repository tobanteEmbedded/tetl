// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_ARGUMENT_HPP
#define TETL_FORMAT_ARGUMENT_HPP

#include "etl/_algorithm/find.hpp"
#include "etl/_cassert/macro.hpp"
#include "etl/_format/formatter.hpp"
#include "etl/_utility/pair.hpp"

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

inline auto split_at_next_argument(etl::string_view str) -> etl::pair<etl::string_view, etl::string_view>
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
        auto const* const openFirst = etl::find(first, end(str), token_begin);
        auto const* const openSec   = etl::next(openFirst);
        auto const escapeStart      = openFirst != end(str) //
                                 && openSec != end(str)     //
                                 && *openSec == token_begin;

        if (escapeStart) {
            // Copy upto {{
            detail::format_argument(etl::string_view(first, openFirst), ctx);

            // Find sequence }}
            auto const* closeFirst = etl::find(etl::next(openSec), end(str), token_end);
            auto const* closeSec   = etl::next(closeFirst);
            auto escapeClose       = closeFirst != end(str) //
                               && closeSec != end(str)      //
                               && *closeSec == token_end;

            // Copy everything between {{ ... }}, but only one curly each.
            if (escapeClose) {
                detail::format_argument(etl::string_view(openSec, closeFirst + 1), ctx);
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
