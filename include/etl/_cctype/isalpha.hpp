/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISALPHA_HPP
#define TETL_CCTYPE_ISALPHA_HPP

#include "etl/_cassert/macro.hpp"

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
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    auto isLower = ch >= 'a' && ch <= 'z';
    auto isUpper = ch >= 'A' && ch <= 'Z';

    return static_cast<int>(isLower || isUpper);
}
} // namespace etl

#endif // TETL_CCTYPE_ISALPHA_HPP
