
// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRING_STRINGS_RFIND_HPP
#define TETL_STRING_STRINGS_RFIND_HPP

#include <etl/_string_view/basic_string_view.hpp>

namespace etl::strings {

template <typename CharT, typename Traits>
[[nodiscard]] constexpr auto rfind(
    basic_string_view<CharT, Traits> haystack,
    CharT character,
    typename basic_string_view<CharT, Traits>::size_type pos
) noexcept -> typename basic_string_view<CharT, Traits>::size_type
{
    return haystack.rfind(character, pos);
}

template <typename CharT, typename Traits>
[[nodiscard]] constexpr auto rfind(
    basic_string_view<CharT, Traits> haystack,
    basic_string_view<CharT, Traits> needle,
    typename basic_string_view<CharT, Traits>::size_type pos
) noexcept -> typename basic_string_view<CharT, Traits>::size_type
{
    return haystack.rfind(needle, pos);
}

} // namespace etl::strings

#endif // TETL_STRING_STRINGS_RFIND_HPP
