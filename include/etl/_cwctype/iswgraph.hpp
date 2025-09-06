// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CWCTYPE_ISWGRAPH_HPP
#define TETL_CWCTYPE_ISWGRAPH_HPP

#include <etl/_cwctype/iswdigit.hpp>
#include <etl/_cwctype/iswlower.hpp>
#include <etl/_cwctype/iswpunct.hpp>
#include <etl/_cwctype/iswupper.hpp>

namespace etl {

/// \brief Checks if the given wide character has a graphical representation,
/// i.e. it is either a number (0123456789), an uppercase letter
/// (ABCDEFGHIJKLMNOPQRSTUVWXYZ), a lowercase letter
/// (abcdefghijklmnopqrstuvwxyz), a punctuation
/// character(!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~) or any graphical character
/// specific to the current C locale.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswgraph
///
/// \ingroup cwctype
[[nodiscard]] constexpr auto iswgraph(wint_t ch) noexcept -> int
{
    auto const isDigit = iswdigit(ch) != 0;
    auto const isUpper = iswupper(ch) != 0;
    auto const isLower = iswlower(ch) != 0;
    auto const isPunct = iswpunct(ch) != 0;
    return static_cast<int>(isDigit || isLower || isUpper || isPunct);
}
} // namespace etl

#endif // TETL_CWCTYPE_ISWGRAPH_HPP
