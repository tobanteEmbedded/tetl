// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_FIND_HPP
#define TETL_STRINGS_FIND_HPP

#include <etl/_string_view/basic_string_view.hpp>

namespace etl::strings {

template <typename Char, typename Traits>
[[nodiscard]] constexpr auto find(
    basic_string_view<Char, Traits> haystack,
    basic_string_view<Char, Traits> needle,
    typename basic_string_view<Char, Traits>::size_type pos = 0
) noexcept -> typename basic_string_view<Char, Traits>::size_type
{
    if (needle.size() == 0 and pos <= haystack.size()) {
        return pos;
    }

    if (pos <= haystack.size() - needle.size()) {
        return haystack.find(needle, pos);
    }

    return basic_string_view<Char, Traits>::npos;
}

} // namespace etl::strings

#endif // TETL_STRINGS_FIND_HPP
