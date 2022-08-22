/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRPBRK_HPP
#define TETL_CSTRING_STRPBRK_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Scans the null-terminated byte string pointed to by dest for any
/// character from the null-terminated byte string pointed to by breakset, and
/// returns a pointer to that character.
///
/// https://en.cppreference.com/w/cpp/string/byte/strpbrk
[[nodiscard]] constexpr auto strpbrk(char const* dest, char const* breakset) noexcept -> char const*
{
    return detail::strpbrk_impl<char const, etl::size_t>(dest, breakset);
}

/// \brief Scans the null-terminated byte string pointed to by dest for any
/// character from the null-terminated byte string pointed to by breakset, and
/// returns a pointer to that character.
///
/// https://en.cppreference.com/w/cpp/string/byte/strpbrk
[[nodiscard]] constexpr auto strpbrk(char* dest, char* breakset) noexcept -> char*
{
    return detail::strpbrk_impl<char, etl::size_t>(dest, breakset);
}

} // namespace etl

#endif // TETL_CSTRING_STRPBRK_HPP
