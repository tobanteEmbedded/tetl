/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CCTYPE_ISDIGIT_HPP
#define TETL_CCTYPE_ISDIGIT_HPP

namespace etl {
/// \brief Checks if the given character is one of the 10 decimal digits:
/// 0123456789.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a numeric character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/isdigit
[[nodiscard]] constexpr auto isdigit(int ch) noexcept -> int { return static_cast<int>(ch >= '0' && ch <= '9'); }
} // namespace etl

#endif // TETL_CCTYPE_ISDIGIT_HPP
