// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CCTYPE_ISUPPER_HPP
#define TETL_CCTYPE_ISUPPER_HPP

namespace etl {

/// \brief Checks if the given character is classified as a uppercase character
/// according to the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a uppercase letter, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isupper
///
/// \ingroup cctype
[[nodiscard]] constexpr auto isupper(int ch) noexcept -> int
{
    return static_cast<int>(ch >= 'A' and ch <= 'Z');
}

} // namespace etl

#endif // TETL_CCTYPE_ISUPPER_HPP
