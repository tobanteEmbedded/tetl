// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCTYPE_ISWXDIGIT_HPP
#define TETL_CWCTYPE_ISWXDIGIT_HPP

#include <etl/_cwchar/wint_t.hpp>

namespace etl {
/// \brief Checks if the given wide character corresponds (if narrowed) to a
/// hexadecimal numeric character, i.e. one of 0123456789abcdefABCDEF.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswxdigit
[[nodiscard]] constexpr auto iswxdigit(wint_t ch) noexcept -> int
{
    auto const isDigit    = ch >= '0' && ch <= '9';
    auto const isHexLower = ch >= 'a' && ch <= 'f';
    auto const isHexUpper = ch >= 'A' && ch <= 'F';
    return static_cast<int>(isDigit || isHexLower || isHexUpper);
}
} // namespace etl

#endif // TETL_CWCTYPE_ISWXDIGIT_HPP
