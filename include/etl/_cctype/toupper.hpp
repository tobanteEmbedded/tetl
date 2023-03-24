/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_TOUPPER_HPP
#define TETL_CCTYPE_TOUPPER_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_cctype/islower.hpp"

namespace etl {

/// \brief Converts the given character to uppercase according to the character
/// conversion rules defined by the default C locale.
///
/// In the default "C" locale, the following lowercase letters
/// **abcdefghijklmnopqrstuvwxyz** are replaced with respective uppercase
/// letters
/// **ABCDEFGHIJKLMNOPQRSTUVWXYZ**.
///
/// \param ch Character to classify.
///
/// \returns Converted character or ch if no uppercase version is defined by the
/// current C locale.
///
/// https://en.cppreference.com/w/cpp/string/byte/toupper
[[nodiscard]] constexpr auto toupper(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    if (islower(ch) != 0) { return static_cast<int>(ch - 32); }
    return static_cast<int>(ch);
}
} // namespace etl

#endif // TETL_CCTYPE_TOUPPER_HPP