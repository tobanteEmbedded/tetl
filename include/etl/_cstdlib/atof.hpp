// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_ATOF_HPP
#define TETL_CSTDLIB_ATOF_HPP

#include <etl/_strings/to_floating_point.hpp>

namespace etl {

/// \brief Interprets a floating point value in a byte string pointed to by str.
[[nodiscard]] constexpr auto atof(char const* str) noexcept -> double
{
    return strings::to_floating_point<double>(str).value;
}

} // namespace etl

#endif // TETL_CSTDLIB_ATOF_HPP
