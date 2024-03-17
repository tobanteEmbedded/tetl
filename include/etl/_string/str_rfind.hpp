
// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRING_STR_RFIND_HPP
#define TETL_STRING_STR_RFIND_HPP

#include <etl/_algorithm/find_end.hpp>
#include <etl/_algorithm/min.hpp>

namespace etl::detail {

template <typename CharT, typename SizeT, typename Traits, SizeT NPos>
[[nodiscard]] constexpr auto str_rfind(CharT const* str, SizeT size, CharT c, SizeT pos) noexcept -> SizeT
{
    if (size < 1) {
        return NPos;
    }

    if (pos < size) {
        ++pos;
    } else {
        pos = size;
    }
    for (auto const* s = str + pos; s != str;) {
        if (Traits::eq(*--s, c)) {
            return static_cast<SizeT>(s - str);
        }
    }
    return NPos;
}

template <typename CharT, typename SizeT, typename Traits, SizeT NPos>
[[nodiscard]] constexpr auto
str_rfind(CharT const* str, SizeT size, CharT const* s, SizeT pos, SizeT n) noexcept -> SizeT
{
    pos = etl::min(pos, size);
    if (n < size - pos) {
        pos += n;
    } else {
        pos = size;
    }

    auto const* r = etl::find_end(str, str + pos, s, s + n, Traits::eq);
    if (n > 0 && r == str + pos) {
        return NPos;
    }
    return static_cast<SizeT>(r - str);
}

} // namespace etl::detail

#endif // TETL_STRING_STR_RFIND_HPP
