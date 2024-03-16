// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCTYPE_ISWUPPER_HPP
#define TETL_CWCTYPE_ISWUPPER_HPP

#include <etl/_cwchar/wint_t.hpp>

namespace etl {

/// \brief Checks if the given wide character is an uppercase letter, i.e. one
/// of ABCDEFGHIJKLMNOPQRSTUVWXYZ or any uppercase letter specific to the
/// current locale.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswupper
[[nodiscard]] constexpr auto iswupper(wint_t ch) noexcept -> int { return static_cast<int>(ch >= L'A' && ch <= L'Z'); }

} // namespace etl

#endif // TETL_CWCTYPE_ISWUPPER_HPP
