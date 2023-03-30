// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CCTYPE_TOUPPER_HPP
#define TETL_CCTYPE_TOUPPER_HPP

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
    if (islower(ch) != 0) { return static_cast<int>(ch - 32); }
    return static_cast<int>(ch);
}
} // namespace etl

#endif // TETL_CCTYPE_TOUPPER_HPP
