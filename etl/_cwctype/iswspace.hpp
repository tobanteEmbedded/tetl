/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCTYPE_ISWSPACE_HPP
#define TETL_CWCTYPE_ISWSPACE_HPP

#include "etl/_cwchar/wint_t.hpp"

namespace etl {

/// \brief Checks if the given wide character is a wide whitespace character as
/// classified by the currently installed C locale. In the default locale, the
/// whitespace characters are the following:
///
///     - space (0x20, ' ')
///     - form feed (0x0c, '\f')
///     - line feed (0x0a, '\n')
///     - carriage return (0x0d, '\r')
///     - horizontal tab (0x09, '\t')
///     - vertical tab (0x0b, '\v')
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswspace
[[nodiscard]] constexpr auto iswspace(wint_t ch) noexcept -> int
{
    auto const sp       = ch == L' ';
    auto const form     = ch == L'\f';
    auto const line     = ch == L'\n';
    auto const carriage = ch == L'\r';
    auto const hTab     = ch == L'\t';
    auto const vTab     = ch == L'\v';
    return static_cast<int>(sp || form || line || carriage || hTab || vTab);
}
} // namespace etl

#endif // TETL_CWCTYPE_ISWSPACE_HPP