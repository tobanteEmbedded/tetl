/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISSPACE_HPP
#define TETL_CCTYPE_ISSPACE_HPP

#include "etl/_cassert/macro.hpp"

namespace etl {

/// \brief Checks if the given character is whitespace character as classified
/// by the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a whitespace character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isspace
[[nodiscard]] constexpr auto isspace(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    auto const sp       = ch == ' ';
    auto const form     = ch == '\f';
    auto const line     = ch == '\n';
    auto const carriage = ch == '\r';
    auto const hTab     = ch == '\t';
    auto const vTab     = ch == '\v';
    return static_cast<int>(sp || form || line || carriage || hTab || vTab);
}
} // namespace etl

#endif // TETL_CCTYPE_ISSPACE_HPP
