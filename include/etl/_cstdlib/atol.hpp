// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CSTDLIB_ATOL_HPP
#define TETL_CSTDLIB_ATOL_HPP

#include <etl/_strings/to_integer.hpp>

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
/// Discards any whitespace characters until the first non-whitespace character
/// is found, then takes as many characters as possible to form a valid integer
/// number representation and converts them to an integer value.
[[nodiscard]] constexpr auto atol(char const* str) noexcept -> long
{
    auto const result = strings::to_integer<long>(str);
    return result.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_ATOL_HPP
