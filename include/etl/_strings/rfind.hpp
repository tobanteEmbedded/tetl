
// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRING_STRINGS_RFIND_HPP
#define TETL_STRING_STRINGS_RFIND_HPP

#include <etl/_algorithm/find_end.hpp>
#include <etl/_algorithm/min.hpp>
#include <etl/_string_view/basic_string_view.hpp>

namespace etl::strings {

template <typename CharT, typename Traits>
[[nodiscard]] constexpr auto rfind(
    basic_string_view<CharT, Traits> haystack,
    CharT character,
    typename basic_string_view<CharT, Traits>::size_type pos
) noexcept -> typename basic_string_view<CharT, Traits>::size_type
{
    auto const* str = haystack.data();
    auto const size = haystack.size();

    if (size < 1) {
        return basic_string_view<CharT, Traits>::npos;
    }

    if (pos < size) {
        ++pos;
    } else {
        pos = size;
    }
    for (auto const* s = str + pos; s != str;) {
        if (Traits::eq(*--s, character)) {
            return static_cast<typename basic_string_view<CharT, Traits>::size_type>(s - str);
        }
    }
    return basic_string_view<CharT, Traits>::npos;
}

template <typename CharT, typename Traits>
[[nodiscard]] constexpr auto rfind(
    basic_string_view<CharT, Traits> haystack,
    basic_string_view<CharT, Traits> needle,
    typename basic_string_view<CharT, Traits>::size_type pos
) noexcept -> typename basic_string_view<CharT, Traits>::size_type
{
    auto const* str = haystack.data();
    auto const size = haystack.size();

    auto const* s = needle.data();
    auto const n  = needle.size();

    pos = etl::min(pos, size);
    if (n < size - pos) {
        pos += n;
    } else {
        pos = size;
    }

    auto const* r = etl::find_end(str, str + pos, s, s + n, Traits::eq);
    if (n > 0 and r == str + pos) {
        return basic_string_view<CharT, Traits>::npos;
    }

    return static_cast<typename basic_string_view<CharT, Traits>::size_type>(r - str);
}

} // namespace etl::strings

#endif // TETL_STRING_STRINGS_RFIND_HPP
