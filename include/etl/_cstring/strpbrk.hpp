// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CSTRING_STRPBRK_HPP
#define TETL_CSTRING_STRPBRK_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// \ingroup cstring
/// @{

/// Scans the null-terminated byte string pointed to by dest for any
/// character from the null-terminated byte string pointed to by breakset, and
/// returns a pointer to that character.
///
/// https://en.cppreference.com/w/cpp/string/byte/strpbrk
///
/// \ingroup cstring
[[nodiscard]] constexpr auto strpbrk(char const* dest, char const* breakset) noexcept -> char const*
{
    return etl::detail::strpbrk_impl<char const, etl::size_t>(dest, breakset);
}

[[nodiscard]] constexpr auto strpbrk(char* dest, char* breakset) noexcept -> char*
{
    return etl::detail::strpbrk_impl<char, etl::size_t>(dest, breakset);
}

/// @}

} // namespace etl

#endif // TETL_CSTRING_STRPBRK_HPP
