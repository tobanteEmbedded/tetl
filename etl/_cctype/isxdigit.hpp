/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISXDIGIT_HPP
#define TETL_CCTYPE_ISXDIGIT_HPP

#include "etl/_assert/macro.hpp"

namespace etl {
/// \brief Checks if the given character is a hexadecimal numeric character
/// (0123456789abcdefABCDEF).
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a hexadecimal numeric character,
/// zero otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isxdigit
///
/// \module Strings
[[nodiscard]] constexpr auto isxdigit(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    auto const isDigit    = ch >= '0' && ch <= '9';
    auto const isHexLower = ch >= 'a' && ch <= 'f';
    auto const isHexUpper = ch >= 'A' && ch <= 'F';

    return static_cast<int>(isDigit || isHexLower || isHexUpper);
}
} // namespace etl

#endif // TETL_CCTYPE_ISXDIGIT_HPP