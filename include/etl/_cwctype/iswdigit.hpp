/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCTYPE_ISWDIGIT_HPP
#define TETL_CWCTYPE_ISWDIGIT_HPP

#include "etl/_cwchar/wint_t.hpp"

namespace etl {
/// \brief Checks if the given wide character corresponds (if narrowed) to one
/// of the ten decimal digit characters 0123456789.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/wide/iswdigit
[[nodiscard]] constexpr auto iswdigit(wint_t ch) noexcept -> int { return static_cast<int>(ch >= L'0' && ch <= L'9'); }
} // namespace etl

#endif // TETL_CWCTYPE_ISWDIGIT_HPP
