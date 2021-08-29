/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISPUNCT_HPP
#define TETL_CCTYPE_ISPUNCT_HPP

#include "etl/_cassert/macro.hpp"

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
/// \module Strings
[[nodiscard]] constexpr auto ispunct(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    auto const sec1 = ch >= '!' && ch <= '/';
    auto const sec2 = ch >= ':' && ch <= '@';
    auto const sec3 = ch >= '[' && ch <= '`';
    auto const sec4 = ch >= '{' && ch <= '~';

    return static_cast<int>(sec1 || sec2 || sec3 || sec4);
}
} // namespace etl

#endif // TETL_CCTYPE_ISPUNCT_HPP