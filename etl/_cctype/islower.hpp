/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISLOWER_HPP
#define TETL_CCTYPE_ISLOWER_HPP

#include "etl/_cassert/macro.hpp"

namespace etl {

/// \brief Checks if the given character is classified as a lowercase character
/// according to the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a lowercase letter, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/islower
[[nodiscard]] constexpr auto islower(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>(ch >= 'a' && ch <= 'z');
}
} // namespace etl

#endif // TETL_CCTYPE_ISLOWER_HPP
