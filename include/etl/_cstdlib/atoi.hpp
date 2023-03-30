// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_ATOI_HPP
#define TETL_CSTDLIB_ATOI_HPP

#include <etl/_cstring/strlen.hpp>
#include <etl/_strings/conversion.hpp>

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
/// Discards any whitespace characters until the first non-whitespace character
/// is found, then takes as many characters as possible to form a valid integer
/// number representation and converts them to an integer value.
[[nodiscard]] constexpr auto atoi(char const* string) noexcept -> int
{
    auto const result = detail::ascii_to_integer<int, true>(string, strlen(string));
    return result.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_ATOI_HPP
