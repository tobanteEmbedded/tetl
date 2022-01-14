/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISUPPER_HPP
#define TETL_CCTYPE_ISUPPER_HPP

#include "etl/_cassert/macro.hpp"

namespace etl {

/// \brief Checks if the given character is classified as a uppercase character
/// according to the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a uppercase letter, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isupper
[[nodiscard]] constexpr auto isupper(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>(ch >= 'A' && ch <= 'Z');
}

} // namespace etl

#endif // TETL_CCTYPE_ISUPPER_HPP