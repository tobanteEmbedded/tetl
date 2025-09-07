// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CCTYPE_ISPRINT_HPP
#define TETL_CCTYPE_ISPRINT_HPP

#include <etl/_cctype/isgraph.hpp>

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
///
/// \ingroup cctype
[[nodiscard]] constexpr auto isprint(int ch) noexcept -> int
{
    return static_cast<int>(etl::isgraph(ch) != 0 || ch == ' ');
}
} // namespace etl

#endif // TETL_CCTYPE_ISPRINT_HPP
