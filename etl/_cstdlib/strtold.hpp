/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDLIB_STRTOLD_HPP
#define TETL_CSTDLIB_STRTOLD_HPP

#include "etl/_strings/conversion.hpp"

namespace etl {

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success. If the converted value falls out of range of corresponding return
/// type, range error occurs and HUGE_VAL, HUGE_VALF or HUGE_VALL is returned.
/// If no conversion can be performed, `0` is returned and *last is set to str.
[[nodiscard]] constexpr auto strtold(const char* str, char const** last = nullptr) noexcept -> long double
{
    return detail::ascii_to_floating_point<long double>(str, last);
}

} // namespace etl

#endif // TETL_CSTDLIB_STRTOLD_HPP