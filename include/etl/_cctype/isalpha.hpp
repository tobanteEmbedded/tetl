// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CCTYPE_ISALPHA_HPP
#define TETL_CCTYPE_ISALPHA_HPP

namespace etl {
/// \brief Checks if the given character is an alphabetic character as
/// classified by the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is an alphabetic character, 0
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isalpha
[[nodiscard]] constexpr auto isalpha(int ch) noexcept -> int
{
    auto const isLower = ch >= 'a' and ch <= 'z';
    auto const isUpper = ch >= 'A' and ch <= 'Z';

    return static_cast<int>(isLower or isUpper);
}
} // namespace etl

#endif // TETL_CCTYPE_ISALPHA_HPP
