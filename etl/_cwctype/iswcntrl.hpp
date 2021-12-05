/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCTYPE_ISWCNTRL_HPP
#define TETL_CWCTYPE_ISWCNTRL_HPP

#include "etl/_cwchar/wint_t.hpp"

namespace etl {

/// \brief Checks if the given wide character is a control character, i.e. codes
/// 0x00-0x1F and 0x7F and any control characters specific to the current
/// locale.
///
/// \details If the value of ch is neither representable as a wchar_t nor equal
/// to the value of the macro WEOF, the behavior is undefined.
///
/// https://en.cppreference.com/w/cpp/string/byte/iscntrl
///
/// \module Strings
[[nodiscard]] constexpr auto iswcntrl(wint_t ch) noexcept -> int
{
    return static_cast<int>((ch <= wint_t(0x1F)) || ch == wint_t(0x7F));
}

} // namespace etl

#endif // TETL_CWCTYPE_ISWCNTRL_HPP