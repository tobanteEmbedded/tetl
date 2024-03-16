// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCTYPE_ISWALNUM_HPP
#define TETL_CWCTYPE_ISWALNUM_HPP

#include <etl/_cwchar/wint_t.hpp>

namespace etl {

/// \brief Checks if the given wide character is an alphanumeric character, i.e.
/// either a number (0123456789), an uppercase letter
/// (ABCDEFGHIJKLMNOPQRSTUVWXYZ), a lowercase letter
/// (abcdefghijklmnopqrstuvwxyz) or any alphanumeric character specific to the
/// current locale.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswalnum
[[nodiscard]] constexpr auto iswalnum(wint_t ch) noexcept -> int
{
    auto isDigit = ch >= L'0' and ch <= L'9';
    auto isLower = ch >= L'a' and ch <= L'z';
    auto isUpper = ch >= L'A' and ch <= L'Z';
    return static_cast<int>(isDigit or isLower or isUpper);
}

} // namespace etl

#endif // TETL_CWCTYPE_ISWALNUM_HPP
