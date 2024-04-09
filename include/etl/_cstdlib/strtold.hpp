// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_STRTOLD_HPP
#define TETL_CSTDLIB_STRTOLD_HPP

#include <etl/_strings/to_floating_point.hpp>

namespace etl {

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success. If the converted value falls out of range of corresponding return
/// type, range error occurs and HUGE_VAL, HUGE_VALF or HUGE_VALL is returned.
/// If no conversion can be performed, `0` is returned and *last is set to str.
[[nodiscard]] constexpr auto strtold(char const* str, char const** last = nullptr) noexcept -> long double
{
    return strings::to_floating_point<long double>(str, last);
}

} // namespace etl

#endif // TETL_CSTDLIB_STRTOLD_HPP
