// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCTYPE_ISWPUNCT_HPP
#define TETL_CWCTYPE_ISWPUNCT_HPP

#include <etl/_cwchar/wint_t.hpp>

namespace etl {

/// \brief Checks if the given wide character is a punctuation character, i.e.
/// it is one of !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ or any punctuation character
/// specific to the current locale.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswpunct
///
/// \ingroup cwctype
[[nodiscard]] constexpr auto iswpunct(wint_t ch) noexcept -> int
{
    auto const sec1 = ch >= L'!' and ch <= L'/';
    auto const sec2 = ch >= L':' and ch <= L'@';
    auto const sec3 = ch >= L'[' and ch <= L'`';
    auto const sec4 = ch >= L'{' and ch <= L'~';
    return static_cast<int>(sec1 || sec2 || sec3 || sec4);
}
} // namespace etl

#endif // TETL_CWCTYPE_ISWPUNCT_HPP
