/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISGRAPH_HPP
#define TETL_CCTYPE_ISGRAPH_HPP

#include "etl/_assert/macro.hpp"

#include "etl/_cctype/isdigit.hpp"
#include "etl/_cctype/islower.hpp"
#include "etl/_cctype/ispunct.hpp"
#include "etl/_cctype/isupper.hpp"

namespace etl {

/// \brief Checks if the given character is graphic (has a graphical
/// representation) as classified by the default C locale.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a punctuation character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isgraph
///
/// \module Strings
[[nodiscard]] constexpr auto isgraph(int ch) noexcept -> int
{
    // ch must de representable as a unsigned char
    TETL_ASSERT(static_cast<unsigned char>(ch) == ch);

    auto const isDigit = etl::isdigit(ch) != 0;
    auto const isUpper = etl::isupper(ch) != 0;
    auto const isLower = etl::islower(ch) != 0;
    auto const isPunct = etl::ispunct(ch) != 0;

    return static_cast<int>(isDigit || isLower || isUpper || isPunct);
}
} // namespace etl

#endif // TETL_CCTYPE_ISGRAPH_HPP