/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISPRINT_HPP
#define TETL_CCTYPE_ISPRINT_HPP

#include "etl/_cassert/macro.hpp"

#include "etl/_cctype/isgraph.hpp"

namespace etl {
/// \brief Checks if ch is a printable character as classified by the default C
/// locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a punctuation character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isprint
[[nodiscard]] constexpr auto isprint(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    return static_cast<int>(etl::isgraph(ch) != 0 || ch == ' ');
}
} // namespace etl

#endif // TETL_CCTYPE_ISPRINT_HPP
