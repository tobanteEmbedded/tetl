/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISBLANK_HPP
#define TETL_CCTYPE_ISBLANK_HPP

#include "etl/_assert/macro.hpp"

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
/// \module Strings
[[nodiscard]] constexpr auto isblank(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>(ch == ' ' || ch == '\t');
}
} // namespace etl

#endif // TETL_CCTYPE_ISBLANK_HPP