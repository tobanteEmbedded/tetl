/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STRING_ALGORITHM_HPP
#define TETL_STRING_ALGORITHM_HPP

#include "etl/_strings/char_traits.hpp"

namespace etl::detail {

/// \brief Finds the first character not equal to any of the characters in the
/// given character sequence.
template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto find_first_not_of(CharT const* f, CharT const* l,
    CharT const* const sf, CharT const* const sl) -> SizeT
{
    auto const legalChar = [sf, sl](CharT ch) -> bool {
        auto const* ssf = sf;
        auto const* ssl = sl;
        for (; ssf != ssl; ++ssf) {
            if (etl::char_traits<CharT>::eq(*ssf, ch)) { return true; }
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
} // namespace etl::detail

#endif // TETL_STRING_ALGORITHM_HPP