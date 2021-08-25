/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_TOLOWER_HPP
#define TETL_CCTYPE_TOLOWER_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_cctype/isupper.hpp"

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
/// \module Strings
[[nodiscard]] constexpr auto tolower(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    if (isupper(ch) != 0) { return static_cast<int>(ch + 32); }
    return static_cast<int>(ch);
}
} // namespace etl

#endif // TETL_CCTYPE_TOLOWER_HPP