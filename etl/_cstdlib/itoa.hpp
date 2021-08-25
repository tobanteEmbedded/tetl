/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDLIB_IOTA_HPP
#define TETL_CSTDLIB_IOTA_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_strings/conversion.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Converts an integer value to a null-terminated string using the
/// specified base and stores the result in the array given by str parameter.
///
/// \details If base is 10 and value is negative, the resulting string is
/// preceded with a minus sign (-). With any other base, value is always
/// considered unsigned.
///
/// \todo Only base 10 is currently supported.
constexpr auto itoa(int val, char* const buffer, int base) -> char*
{
    auto res = detail::int_to_ascii<int>(val, buffer, base);
    TETL_ASSERT(res.error == detail::int_to_ascii_error::none);
    ignore_unused(res);
    return buffer;
}

} // namespace etl

#endif // TETL_CSTDLIB_IOTA_HPP