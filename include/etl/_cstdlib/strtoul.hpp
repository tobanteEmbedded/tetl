// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CSTDLIB_STRTOUL_HPP
#define TETL_CSTDLIB_STRTOUL_HPP

#include <etl/_cstring/strlen.hpp>
#include <etl/_strings/to_integer.hpp>

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtoul
[[nodiscard]] constexpr auto strtoul(char const* str, char const** last, int base) noexcept -> unsigned long
{
    auto const res = strings::to_integer<unsigned long>(str, static_cast<unsigned long>(base));
    if (last != nullptr) {
        *last = res.end;
    }
    return res.value;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtoul
[[nodiscard]] constexpr auto strtoull(char const* str, char const** last, int base) noexcept -> unsigned long long
{
    auto const res = strings::to_integer<unsigned long long>(str, static_cast<unsigned long long>(base));
    if (last != nullptr) {
        *last = res.end;
    }
    return res.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_STRTOUL_HPP
