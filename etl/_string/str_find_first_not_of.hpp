/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STRING_ALGORITHM_HPP
#define TETL_STRING_ALGORITHM_HPP

#include "etl/_string/char_traits.hpp"

namespace etl::detail {

template <typename CharT, typename SizeT, typename Traits, SizeT Npos>
[[nodiscard]] constexpr auto str_find_first_not_of(CharT const* str, SizeT size,
    CharT const* search, SizeT pos, SizeT n) noexcept -> SizeT
{
    if (pos < size) {
        auto const* last = str + size;
        for (auto const* s = str + pos; s != last; ++s) {
            if (Traits::find(search, n, *s) == nullptr) {
                return static_cast<SizeT>(s - str);
            }
        }
    }
    return Npos;
}

template <typename CharT, typename SizeT, typename Traits, SizeT Npos>
[[nodiscard]] constexpr auto str_find_first_not_of(
    CharT const* str, SizeT size, CharT c, SizeT pos) noexcept -> SizeT
{
    if (pos < size) {
        auto const* last = str + size;
        for (auto const* s = str + pos; s != last; ++s) {
            if (!Traits::eq(*s, c)) { return static_cast<SizeT>(s - str); }
        }
    }
    return Npos;
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