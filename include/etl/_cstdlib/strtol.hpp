// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CSTDLIB_STRTOL_HPP
#define TETL_CSTDLIB_STRTOL_HPP

#include <etl/_cstring/strlen.hpp>
#include <etl/_strings/to_integer.hpp>

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtol
[[nodiscard]] constexpr auto strtol(char const* str, char const** last, int base) noexcept -> long
{
    auto const res = strings::to_integer<long>(str, base);
    if (last != nullptr) {
        *last = res.end;
    }
    return res.value;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtol
[[nodiscard]] constexpr auto strtoll(char const* str, char const** last, int base) noexcept -> long long
{
    auto const res = strings::to_integer<long long>(str, base);
    if (last != nullptr) {
        *last = res.end;
    }
    return res.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_STRTOL_HPP
