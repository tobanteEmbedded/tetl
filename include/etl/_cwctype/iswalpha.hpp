// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCTYPE_ISWALPHA_HPP
#define TETL_CWCTYPE_ISWALPHA_HPP

#include <etl/_cwchar/wint_t.hpp>

namespace etl {
/// \brief Checks if the given wide character is an alphabetic character, i.e.
/// either an uppercase letter (ABCDEFGHIJKLMNOPQRSTUVWXYZ), a lowercase letter
/// (abcdefghijklmnopqrstuvwxyz) or any alphabetic character specific to the
/// current locale.
///
/// If the value of ch is neither representable as a wchar_t nor equal to the
/// value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswalpha
[[nodiscard]] constexpr auto iswalpha(wint_t ch) noexcept -> int
{
    auto isLower = ch >= L'a' && ch <= L'z';
    auto isUpper = ch >= L'A' && ch <= L'Z';
    return static_cast<int>(isLower || isUpper);
}
} // namespace etl

#endif // TETL_CWCTYPE_ISWALPHA_HPP
