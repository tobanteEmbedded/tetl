// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CCTYPE_ISBLANK_HPP
#define TETL_CCTYPE_ISBLANK_HPP

namespace etl {
/// \brief Checks if the given character is a blank character as classified by
/// the currently installed C locale. Blank characters are whitespace characters
/// used to separate words within a sentence. In the default C locale, only
/// space (0x20) and horizontal tab (0x09) are classified as blank characters.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a blank character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isblank
///
/// \ingroup cctype
[[nodiscard]] constexpr auto isblank(int ch) noexcept -> int { return static_cast<int>(ch == ' ' || ch == '\t'); }
} // namespace etl

#endif // TETL_CCTYPE_ISBLANK_HPP
