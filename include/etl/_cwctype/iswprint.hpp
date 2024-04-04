// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCTYPE_ISWPRINT_HPP
#define TETL_CWCTYPE_ISWPRINT_HPP

#include <etl/_cwchar/wint_t.hpp>
#include <etl/_cwctype/iswgraph.hpp>

namespace etl {
/// \brief Checks if the given wide character can be printed, i.e. it is either
/// a number (0123456789), an uppercase letter (ABCDEFGHIJKLMNOPQRSTUVWXYZ), a
/// lowercase letter (abcdefghijklmnopqrstuvwxyz), a punctuation
/// character(!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~), space or any printable
/// character specific to the current C locale.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswprint
///
/// \ingroup cwctype
[[nodiscard]] constexpr auto iswprint(wint_t ch) noexcept -> int
{
    return static_cast<int>(etl::iswgraph(ch) != 0 || ch == ' ');
}

} // namespace etl

#endif // TETL_CWCTYPE_ISWPRINT_HPP
