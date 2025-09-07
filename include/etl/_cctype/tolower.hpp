// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CCTYPE_TOLOWER_HPP
#define TETL_CCTYPE_TOLOWER_HPP

#include <etl/_cctype/isupper.hpp>

namespace etl {

/// \brief Converts the given character to lowercase according to the character
/// conversion rules defined by the default C locale.
///
/// In the default "C" locale, the following uppercase letters
/// **ABCDEFGHIJKLMNOPQRSTUVWXYZ** are replaced with respective lowercase
/// letters
/// **abcdefghijklmnopqrstuvwxyz**.
///
/// \param ch Character to classify.
///
/// \returns Lowercase version of ch or unmodified ch if no lowercase version is
/// listed in the current C locale.
///
/// https://en.cppreference.com/w/cpp/string/byte/tolower
///
/// \ingroup cctype
[[nodiscard]] constexpr auto tolower(int ch) noexcept -> int
{
    if (isupper(ch) != 0) {
        return static_cast<int>(ch + 32);
    }
    return static_cast<int>(ch);
}
} // namespace etl

#endif // TETL_CCTYPE_TOLOWER_HPP
