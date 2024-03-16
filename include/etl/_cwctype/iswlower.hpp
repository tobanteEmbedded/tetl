// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCTYPE_ISWLOWER_HPP
#define TETL_CWCTYPE_ISWLOWER_HPP

#include <etl/_cwchar/wint_t.hpp>

namespace etl {

/// \brief Checks if the given wide character is a lowercase letter, i.e. one of
/// abcdefghijklmnopqrstuvwxyz or any lowercase letter specific to the current
/// locale.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswlower
[[nodiscard]] constexpr auto iswlower(wint_t ch) noexcept -> int { return static_cast<int>(ch >= L'a' && ch <= L'z'); }

} // namespace etl

#endif // TETL_CWCTYPE_ISWLOWER_HPP
