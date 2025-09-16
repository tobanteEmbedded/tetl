// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CWCTYPE_ISWSPACE_HPP
#define TETL_CWCTYPE_ISWSPACE_HPP

#include <etl/_cwchar/wint_t.hpp>

namespace etl {

/// Checks if the given wide character is a wide whitespace character as
/// classified by the currently installed C locale.
///
/// If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined. In the default
/// locale, the whitespace characters are the following:
///
///     - space (0x20)
///     - form feed (0x0c)
///     - line feed (0x0a)
///     - carriage return (0x0d)
///     - horizontal tab (0x09)
///     - vertical tab (0x0b)
///
/// https://en.cppreference.com/w/cpp/string/wide/iswspace
///
/// \ingroup cwctype
[[nodiscard]] constexpr auto iswspace(wint_t ch) noexcept -> int
{
    auto const sp       = ch == L' ';
    auto const form     = ch == L'\f';
    auto const line     = ch == L'\n';
    auto const carriage = ch == L'\r';
    auto const hTab     = ch == L'\t';
    auto const vTab     = ch == L'\v';
    return static_cast<int>(sp or form or line or carriage or hTab or vTab);
}
} // namespace etl

#endif // TETL_CWCTYPE_ISWSPACE_HPP
