// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CCTYPE_ISDIGIT_HPP
#define TETL_CCTYPE_ISDIGIT_HPP

namespace etl {

/// Checks if the given character is one of the 10 decimal digits: 0123456789.
///
/// https://en.cppreference.com/w/cpp/string/byte/isdigit
///
/// \returns Non-zero value if the character is a numeric character, zero otherwise.
/// \param ch Character to classify.
/// \ingroup cctype
[[nodiscard]] constexpr auto isdigit(int ch) noexcept -> int
{
    return static_cast<int>(ch >= '0' and ch <= '9');
}

} // namespace etl

#endif // TETL_CCTYPE_ISDIGIT_HPP
