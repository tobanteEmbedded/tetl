// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CWCTYPE_TOWUPPER_HPP
#define TETL_CWCTYPE_TOWUPPER_HPP

#include <etl/_cwchar/wint_t.hpp>
#include <etl/_cwctype/iswlower.hpp>

namespace etl {

/// \brief Converts the given wide character to uppercase, if possible.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/towupper
///
/// \ingroup cwctype
[[nodiscard]] constexpr auto towupper(wint_t ch) noexcept -> wint_t
{
    if (iswlower(ch) != 0) {
        return ch - wint_t(32);
    }
    return ch;
}
} // namespace etl

#endif // TETL_CWCTYPE_TOWUPPER_HPP
