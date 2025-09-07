// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CCTYPE_ISLOWER_HPP
#define TETL_CCTYPE_ISLOWER_HPP

namespace etl {

/// \brief Checks if the given character is classified as a lowercase character
/// according to the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a lowercase letter, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/islower
///
/// \ingroup cctype
[[nodiscard]] constexpr auto islower(int ch) noexcept -> int
{
    return static_cast<int>(ch >= 'a' and ch <= 'z');
}
} // namespace etl

#endif // TETL_CCTYPE_ISLOWER_HPP
