// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CCTYPE_ISCNTRL_HPP
#define TETL_CCTYPE_ISCNTRL_HPP

namespace etl {

/// \brief Checks if the given character is a control character as classified by
/// the currently installed C locale. In the default, "C" locale, the control
/// characters are the characters with the codes 0x00-0x1F and 0x7F.
///
/// \param ch Character to classify.
///
/// \returns Non-zero value if the character is a control character, zero
/// otherwise.
///
/// https://en.cppreference.com/w/cpp/string/byte/iscntrl
///
/// \ingroup cctype
[[nodiscard]] constexpr auto iscntrl(int ch) noexcept -> int
{
    return static_cast<int>((ch >= 0x00 and ch <= 0x1f) or ch == 0x7F);
}

} // namespace etl

#endif // TETL_CCTYPE_ISCNTRL_HPP
