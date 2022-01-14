/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISCNTRL_HPP
#define TETL_CCTYPE_ISCNTRL_HPP

#include "etl/_cassert/macro.hpp"

namespace etl {

/// \brief Checks if the given character is a control character as classified by
/// the currently installed C locale. In the default, "C" locale, the control
/// characters are the characters with the codes 0x00-0x1F and 0x7F.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a control character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/iscntrl
[[nodiscard]] constexpr auto iscntrl(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);
    return static_cast<int>((ch >= 0x00 && ch <= 0x1f) || ch == 0x7F);
}

} // namespace etl

#endif // TETL_CCTYPE_ISCNTRL_HPP