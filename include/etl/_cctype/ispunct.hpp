// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CCTYPE_ISPUNCT_HPP
#define TETL_CCTYPE_ISPUNCT_HPP

namespace etl {

/// \brief Checks if the given character is a punctuation character as
/// classified by the current C locale.
///
/// The default C locale classifies the characters
/// !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ as punctuation.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a punctuation character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/ispunct
///
/// \ingroup cctype
[[nodiscard]] constexpr auto ispunct(int ch) noexcept -> int
{
    auto const sec1 = ch >= '!' and ch <= '/';
    auto const sec2 = ch >= ':' and ch <= '@';
    auto const sec3 = ch >= '[' and ch <= '`';
    auto const sec4 = ch >= '{' and ch <= '~';

    return static_cast<int>(sec1 || sec2 || sec3 || sec4);
}
} // namespace etl

#endif // TETL_CCTYPE_ISPUNCT_HPP
