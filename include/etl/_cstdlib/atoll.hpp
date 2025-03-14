// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_ATOLL_HPP
#define TETL_CSTDLIB_ATOLL_HPP

#include <etl/_strings/to_integer.hpp>

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
/// Discards any whitespace characters until the first non-whitespace character
/// is found, then takes as many characters as possible to form a valid integer
/// number representation and converts them to an integer value.
[[nodiscard]] constexpr auto atoll(char const* str) noexcept -> long long
{
    auto const result = strings::to_integer<long long>(str);
    return result.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_ATOLL_HPP
